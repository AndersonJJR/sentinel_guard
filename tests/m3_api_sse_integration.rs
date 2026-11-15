#![cfg(unix)]
//! End-to-end HTTP and live TCP SSE integration tests for Milestone 3 (`feat/m3-axum-api-sse`).

use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, to_bytes};
use axum::http::{Request as HttpRequest, StatusCode, header};
use chrono::{Duration as ChronoDuration, SecondsFormat, Utc};
use secrecy::SecretString;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::{TempDir, tempdir};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{RwLock, watch};
use tokio::task::JoinHandle;
use tower::ServiceExt;

use sentinel_guard::application::inspect_file::InspectFileUseCase;
use sentinel_guard::application::update_config::UpdateConfigUseCase;
use sentinel_guard::domain::entities::{
    FileArtifact, InspectionReport, NetworkAlert, RuntimeConfig, SecurityVerdict,
};
use sentinel_guard::domain::ports::{ConfigStore, FileScanner, QuarantineRepo};
use sentinel_guard::infrastructure::fs_watcher::FsQuarantineMover;
use sentinel_guard::infrastructure::magic_bytes::{MagicBytesInspector, StreamingHasher};
use sentinel_guard::infrastructure::sqlite_repo::SqliteStore;
use sentinel_guard::infrastructure::suricata_tail::SuricataCorrelator;
use sentinel_guard::presentation::api_routes::{
    AlertsResponse, ApiState, HealthResponse, MAX_API_BODY_BYTES, ReportsResponse, build_api_router,
};
use sentinel_guard::presentation::sse_broadcaster::{SseBroadcaster, SseEvent};

const TEST_ADMIN_TOKEN: &str = "sentinel_m3_e2e_admin_token_64chars_0123456789abcdef0123456789";
const EXPECTED_CSP: &str = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'";
const IO_TIMEOUT: Duration = Duration::from_secs(5);

struct E2eTestServer {
    _temp_dir: TempDir,
    canonical_root: PathBuf,
    quarantine_dir: PathBuf,
    approved_dir: PathBuf,
    db_url: String,
    eve_path: PathBuf,
    addr: SocketAddr,
    store: Arc<SqliteStore>,
    runtime_config: Arc<RwLock<RuntimeConfig>>,
    inspect_use_case: Arc<InspectFileUseCase>,
    sse_broadcaster: Arc<SseBroadcaster>,
    watcher_rx: watch::Receiver<PathBuf>,
    state: Arc<ApiState>,
    shutdown_tx: watch::Sender<bool>,
    server_handle: Option<JoinHandle<std::io::Result<()>>>,
}

impl E2eTestServer {
    async fn start() -> Self {
        let dir = tempdir().expect("create tempdir");
        let canonical_root = std::fs::canonicalize(dir.path()).expect("canonicalize tempdir");
        let quarantine_dir = canonical_root.join("quarantine");
        let approved_dir = canonical_root.join("approved");
        std::fs::create_dir_all(&quarantine_dir).expect("create quarantine_dir");
        std::fs::create_dir_all(&approved_dir).expect("create approved_dir");

        let db_path = canonical_root.join("sentinel_guard_m3.db");
        let db_url = format!("sqlite://{}?mode=rwc", db_path.display());
        let clamd_socket_path = canonical_root.join("clamd.ctl");
        let eve_path = canonical_root.join("eve.json");

        let store = Arc::new(
            SqliteStore::connect_and_migrate(&db_url)
                .await
                .expect("connect and migrate SqliteStore"),
        );

        let default_config = RuntimeConfig {
            quarantine_dir: quarantine_dir.clone(),
            approved_dir: approved_dir.clone(),
            clamd_socket_path,
            suricata_eve_path: eve_path.clone(),
            updated_at: Utc::now(),
        };
        let initial_config = store
            .load_or_seed(&default_config)
            .await
            .expect("seed RuntimeConfig in SqliteStore");

        let runtime_config = Arc::new(RwLock::new(initial_config.clone()));
        let (watcher_tx, watcher_rx) = watch::channel(initial_config.quarantine_dir);

        let hasher = Arc::new(StreamingHasher::new());
        let magic_inspector = Arc::new(MagicBytesInspector::new());
        let suricata_correlator = Arc::new(SuricataCorrelator::new(runtime_config.clone()));
        let scanners: Vec<Arc<dyn FileScanner>> =
            vec![magic_inspector.clone(), suricata_correlator.clone()];
        let quarantine_mover = Arc::new(FsQuarantineMover::new());

        let inspect_use_case = Arc::new(InspectFileUseCase::new(
            hasher,
            magic_inspector,
            scanners,
            quarantine_mover,
            store.clone(),
            runtime_config.clone(),
        ));

        let update_config_use_case = Arc::new(UpdateConfigUseCase::new(
            store.clone(),
            runtime_config.clone(),
            watcher_tx,
        ));

        let sse_broadcaster = Arc::new(SseBroadcaster::new());

        let state = Arc::new(ApiState {
            config_store: store.clone(),
            quarantine_repo: store.clone(),
            runtime_config: runtime_config.clone(),
            update_config_use_case,
            suricata_correlator,
            sse_broadcaster: sse_broadcaster.clone(),
            admin_api_token: SecretString::from(TEST_ADMIN_TOKEN.to_string()),
        });

        let app = build_api_router(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral TcpListener");
        let addr = listener.local_addr().expect("listener local_addr");

        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let server_handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    while !*shutdown_rx.borrow_and_update() {
                        if shutdown_rx.changed().await.is_err() {
                            break;
                        }
                    }
                })
                .await
        });

        Self {
            _temp_dir: dir,
            canonical_root,
            quarantine_dir,
            approved_dir,
            db_url,
            eve_path,
            addr,
            store,
            runtime_config,
            inspect_use_case,
            sse_broadcaster,
            watcher_rx,
            state,
            shutdown_tx,
            server_handle: Some(server_handle),
        }
    }

    fn trigger_graceful_shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    async fn await_exit(&mut self) {
        if let Some(handle) = self.server_handle.take() {
            tokio::time::timeout(IO_TIMEOUT, handle)
                .await
                .expect("timed out waiting for HTTP server exit")
                .expect("HTTP server task panicked")
                .expect("HTTP server returned I/O error");
        }
    }

    async fn shutdown(mut self) {
        self.sse_broadcaster.shutdown();
        self.trigger_graceful_shutdown();
        self.await_exit().await;
    }
}

impl Drop for E2eTestServer {
    fn drop(&mut self) {
        self.sse_broadcaster.shutdown();
        let _ = self.shutdown_tx.send(true);
        if let Some(handle) = self.server_handle.take() {
            handle.abort();
        }
    }
}

#[derive(Debug)]
struct RawHttpResponse {
    status: u16,
    headers: HashMap<String, Vec<String>>,
    body: Vec<u8>,
}

impl RawHttpResponse {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .and_then(|vals| vals.first())
            .map(String::as_str)
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|err| {
            panic!(
                "expected valid JSON response body (status {}), err={err}, body={:?}",
                self.status,
                String::from_utf8_lossy(&self.body)
            )
        })
    }

    fn assert_security_headers(&self) {
        assert_eq!(self.header("x-content-type-options"), Some("nosniff"));
        assert_eq!(self.header("x-frame-options"), Some("DENY"));
        assert_eq!(self.header("referrer-policy"), Some("no-referrer"));
        assert_eq!(self.header("content-security-policy"), Some(EXPECTED_CSP));
        assert_eq!(self.header("cache-control"), Some("no-store"));
    }
}

async fn send_http_request(
    addr: SocketAddr,
    method: &str,
    path_and_query: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> RawHttpResponse {
    tokio::time::timeout(IO_TIMEOUT, async {
        let mut stream = TcpStream::connect(addr)
            .await
            .expect("connect TcpStream to HTTP server");

        let mut raw_req = Vec::with_capacity(256 + body.len());
        raw_req.extend_from_slice(
            format!("{method} {path_and_query} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n")
                .as_bytes(),
        );
        for (name, value) in headers {
            raw_req.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        if !body.is_empty() || matches!(method, "PATCH" | "POST" | "PUT") {
            raw_req.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        }
        raw_req.extend_from_slice(b"\r\n");
        raw_req.extend_from_slice(body);

        if let Err(err) = stream.write_all(&raw_req).await {
            assert!(
                matches!(
                    err.kind(),
                    ErrorKind::BrokenPipe | ErrorKind::ConnectionReset
                ),
                "unexpected TCP write error while sending {method} {path_and_query}: {err}"
            );
        }

        let mut raw_resp = Vec::new();
        stream
            .read_to_end(&mut raw_resp)
            .await
            .expect("read HTTP response to EOF");

        parse_raw_http_response(&raw_resp)
    })
    .await
    .unwrap_or_else(|_| panic!("HTTP request timed out: {method} {path_and_query}"))
}

fn parse_raw_http_response(raw: &[u8]) -> RawHttpResponse {
    let header_end = find_header_end(raw).unwrap_or_else(|| {
        panic!(
            "missing HTTP header terminator in response: {:?}",
            String::from_utf8_lossy(raw)
        )
    });
    let header_text = std::str::from_utf8(&raw[..header_end]).expect("HTTP headers must be UTF-8");
    let (status, headers) = parse_http_headers_block(header_text);

    let body_slice = &raw[header_end + 4..];
    let is_chunked = headers.get("transfer-encoding").is_some_and(|vals| {
        vals.iter()
            .any(|v| v.to_ascii_lowercase().contains("chunked"))
    });

    let body = if is_chunked {
        decode_chunked_body(body_slice)
    } else {
        body_slice.to_vec()
    };

    RawHttpResponse {
        status,
        headers,
        body,
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|window| window == b"\r\n")
}

fn parse_http_headers_block(header_text: &str) -> (u16, HashMap<String, Vec<String>>) {
    let mut lines = header_text.split("\r\n");
    let status_line = lines.next().expect("HTTP status line");
    let mut parts = status_line.split_whitespace();
    let version = parts.next().expect("HTTP version");
    assert!(
        version.starts_with("HTTP/1."),
        "unexpected HTTP version in status line: {status_line:?}"
    );
    let status: u16 = parts
        .next()
        .expect("HTTP status code")
        .parse()
        .expect("numeric HTTP status code");

    let mut headers: HashMap<String, Vec<String>> = HashMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers
                .entry(name.trim().to_ascii_lowercase())
                .or_default()
                .push(value.trim().to_string());
        }
    }

    (status, headers)
}

fn decode_chunked_body(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cursor = raw;
    loop {
        let crlf_pos = find_crlf(cursor).expect("chunk size CRLF");
        let size_line = std::str::from_utf8(&cursor[..crlf_pos]).expect("chunk size UTF-8");
        let hex_len = size_line.split(';').next().unwrap_or("").trim();
        let chunk_len = usize::from_str_radix(hex_len, 16)
            .unwrap_or_else(|err| panic!("invalid chunk hex size {hex_len:?}: {err}"));
        cursor = &cursor[crlf_pos + 2..];
        if chunk_len == 0 {
            break;
        }
        assert!(
            cursor.len() >= chunk_len + 2,
            "truncated chunked body: needed {}, remaining {}",
            chunk_len + 2,
            cursor.len()
        );
        out.extend_from_slice(&cursor[..chunk_len]);
        assert_eq!(
            &cursor[chunk_len..chunk_len + 2],
            b"\r\n",
            "expected CRLF after chunk payload"
        );
        cursor = &cursor[chunk_len + 2..];
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SseFrame {
    event: Option<String>,
    data: Vec<String>,
    comments: Vec<String>,
}

impl SseFrame {
    fn data_str(&self) -> String {
        self.data.join("\n")
    }

    fn parse_sse_event(&self) -> SseEvent {
        let payload = self.data_str();
        serde_json::from_str(&payload)
            .unwrap_or_else(|err| panic!("invalid SSE JSON payload {payload:?}: {err}"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChunkReadState {
    ReadingSize,
    ReadingData(usize),
    ReadingDataCrlf,
    ReadingTrailers,
    Done,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PumpOutcome {
    Progress,
    ChunkStreamEnded,
    TcpEof,
}

struct SseTcpClient {
    stream: TcpStream,
    raw_buf: Vec<u8>,
    decoded_buf: Vec<u8>,
    pending_lines: Vec<String>,
    chunked: bool,
    chunk_state: ChunkReadState,
    status: u16,
    headers: HashMap<String, Vec<String>>,
}

impl SseTcpClient {
    async fn connect(addr: SocketAddr, path: &str, token: &str) -> Self {
        tokio::time::timeout(IO_TIMEOUT, async {
            let mut stream = TcpStream::connect(addr)
                .await
                .expect("connect TcpStream for SSE");

            let req = format!(
                "GET {path} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {token}\r\nAccept: text/event-stream\r\n\r\n"
            );
            stream
                .write_all(req.as_bytes())
                .await
                .expect("write SSE handshake request");

            let mut raw_buf = Vec::with_capacity(4096);
            let header_end = loop {
                if let Some(pos) = find_header_end(&raw_buf) {
                    break pos;
                }
                let mut tmp = [0u8; 2048];
                let n = stream.read(&mut tmp).await.expect("read SSE HTTP headers");
                assert!(n > 0, "SSE socket closed before HTTP response headers completed");
                raw_buf.extend_from_slice(&tmp[..n]);
            };

            let header_text =
                std::str::from_utf8(&raw_buf[..header_end]).expect("SSE headers must be UTF-8");
            let (status, headers) = parse_http_headers_block(header_text);
            raw_buf.drain(..header_end + 4);

            let chunked = headers
                .get("transfer-encoding")
                .is_some_and(|vals| vals.iter().any(|v| v.to_ascii_lowercase().contains("chunked")));

            let mut decoded_buf = Vec::new();
            if !chunked {
                decoded_buf.append(&mut raw_buf);
            }

            Self {
                stream,
                raw_buf,
                decoded_buf,
                pending_lines: Vec::new(),
                chunked,
                chunk_state: ChunkReadState::ReadingSize,
                status,
                headers,
            }
        })
        .await
        .expect("timed out connecting live TCP SSE client")
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .and_then(|vals| vals.first())
            .map(String::as_str)
    }

    fn assert_security_headers(&self) {
        assert_eq!(self.header("x-content-type-options"), Some("nosniff"));
        assert_eq!(self.header("x-frame-options"), Some("DENY"));
        assert_eq!(self.header("referrer-policy"), Some("no-referrer"));
        assert_eq!(self.header("content-security-policy"), Some(EXPECTED_CSP));
        assert_eq!(self.header("cache-control"), Some("no-store"));
    }

    async fn pump_step(&mut self) -> std::io::Result<PumpOutcome> {
        if !self.chunked {
            let mut tmp = [0u8; 4096];
            let n = self.stream.read(&mut tmp).await?;
            if n == 0 {
                return Ok(PumpOutcome::TcpEof);
            }
            self.decoded_buf.extend_from_slice(&tmp[..n]);
            return Ok(PumpOutcome::Progress);
        }

        loop {
            match self.chunk_state {
                ChunkReadState::ReadingSize => {
                    if let Some(pos) = find_crlf(&self.raw_buf) {
                        let size_line =
                            std::str::from_utf8(&self.raw_buf[..pos]).expect("chunk size UTF-8");
                        let hex_len = size_line.split(';').next().unwrap_or("").trim();
                        let size = usize::from_str_radix(hex_len, 16)
                            .unwrap_or_else(|err| panic!("invalid chunk hex {hex_len:?}: {err}"));
                        self.raw_buf.drain(..pos + 2);
                        if size == 0 {
                            self.chunk_state = ChunkReadState::ReadingTrailers;
                        } else {
                            self.chunk_state = ChunkReadState::ReadingData(size);
                        }
                        continue;
                    }
                }
                ChunkReadState::ReadingData(remaining) => {
                    if !self.raw_buf.is_empty() {
                        let take = remaining.min(self.raw_buf.len());
                        self.decoded_buf.extend_from_slice(&self.raw_buf[..take]);
                        self.raw_buf.drain(..take);
                        if take == remaining {
                            self.chunk_state = ChunkReadState::ReadingDataCrlf;
                        } else {
                            self.chunk_state = ChunkReadState::ReadingData(remaining - take);
                        }
                        return Ok(PumpOutcome::Progress);
                    }
                }
                ChunkReadState::ReadingDataCrlf => {
                    if self.raw_buf.len() >= 2 {
                        assert_eq!(
                            &self.raw_buf[..2],
                            b"\r\n",
                            "expected CRLF after chunk payload"
                        );
                        self.raw_buf.drain(..2);
                        self.chunk_state = ChunkReadState::ReadingSize;
                        continue;
                    }
                }
                ChunkReadState::ReadingTrailers => {
                    if let Some(pos) = find_crlf(&self.raw_buf) {
                        let empty_trailer = pos == 0;
                        self.raw_buf.drain(..pos + 2);
                        if empty_trailer {
                            self.chunk_state = ChunkReadState::Done;
                            return Ok(PumpOutcome::ChunkStreamEnded);
                        }
                        continue;
                    }
                }
                ChunkReadState::Done => return Ok(PumpOutcome::ChunkStreamEnded),
            }

            let mut tmp = [0u8; 4096];
            let n = self.stream.read(&mut tmp).await?;
            if n == 0 {
                return Ok(PumpOutcome::TcpEof);
            }
            self.raw_buf.extend_from_slice(&tmp[..n]);
        }
    }

    fn try_pop_frame(&mut self) -> Option<SseFrame> {
        while let Some(newline_pos) = self.decoded_buf.iter().position(|&b| b == b'\n') {
            let line_bytes: Vec<u8> = self.decoded_buf.drain(..=newline_pos).collect();
            let line = std::str::from_utf8(&line_bytes)
                .expect("SSE payload must be valid UTF-8")
                .trim_end_matches(['\r', '\n'])
                .to_string();

            if line.is_empty() {
                if self.pending_lines.is_empty() {
                    continue;
                }
                let lines = std::mem::take(&mut self.pending_lines);
                return Some(parse_sse_frame(&lines));
            }

            self.pending_lines.push(line);
        }

        None
    }

    async fn next_event_frame(&mut self, timeout_dur: Duration) -> SseFrame {
        tokio::time::timeout(timeout_dur, async {
            loop {
                while let Some(frame) = self.try_pop_frame() {
                    if frame.event.is_none() && frame.data.is_empty() {
                        // Skip SSE comment keep-alive frames (`: keep-alive`).
                        continue;
                    }
                    return frame;
                }

                match self.pump_step().await.expect("pump SSE TCP stream") {
                    PumpOutcome::Progress => {}
                    PumpOutcome::ChunkStreamEnded => {
                        panic!("SSE chunked stream ended before expected event arrived");
                    }
                    PumpOutcome::TcpEof => {
                        panic!("SSE TCP socket closed before expected event arrived");
                    }
                }
            }
        })
        .await
        .expect("timed out waiting for live SSE frame over TcpStream")
    }

    async fn wait_for_chunked_stream_end(&mut self, timeout_dur: Duration) {
        if !self.chunked {
            return;
        }
        tokio::time::timeout(timeout_dur, async {
            loop {
                match self.pump_step().await.expect("pump SSE chunked terminator") {
                    PumpOutcome::Progress => {
                        while let Some(frame) = self.try_pop_frame() {
                            assert!(
                                frame.event.is_none() && frame.data.is_empty(),
                                "unexpected unread data frame during SSE shutdown: {frame:?}"
                            );
                        }
                    }
                    PumpOutcome::ChunkStreamEnded => break,
                    PumpOutcome::TcpEof => {
                        panic!("TCP EOF observed before HTTP/1.1 chunked 0\\r\\n\\r\\n terminator");
                    }
                }
            }
        })
        .await
        .expect("timed out waiting for SSE chunked stream end");
    }

    async fn wait_for_tcp_eof(&mut self, timeout_dur: Duration) {
        tokio::time::timeout(timeout_dur, async {
            assert!(
                self.raw_buf.is_empty(),
                "unexpected trailing raw bytes after SSE stream end: {:?}",
                String::from_utf8_lossy(&self.raw_buf)
            );
            let mut buf = [0u8; 64];
            let n = self
                .stream
                .read(&mut buf)
                .await
                .expect("expected clean TCP FIN/EOF without connection reset");
            assert_eq!(
                n,
                0,
                "expected clean TCP EOF (0 bytes), got extra bytes: {:?}",
                String::from_utf8_lossy(&buf[..n])
            );
        })
        .await
        .expect("timed out waiting for SSE TCP socket close");
    }
}

fn parse_sse_frame(lines: &[String]) -> SseFrame {
    let mut event = None;
    let mut data = Vec::new();
    let mut comments = Vec::new();

    for line in lines {
        if let Some(comment) = line.strip_prefix(':') {
            comments.push(comment.trim_start().to_string());
        } else if let Some(val) = line.strip_prefix("event:") {
            event = Some(val.trim_start().to_string());
        } else if let Some(val) = line.strip_prefix("data:") {
            data.push(val.trim_start().to_string());
        }
    }

    SseFrame {
        event,
        data,
        comments,
    }
}

fn auth_header_value(token: &str) -> String {
    format!("Bearer {token}")
}

fn build_valid_pdf(total_len: usize) -> Vec<u8> {
    let header = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<< /Type /Catalog >>\nendobj\n";
    let footer = b"\n%%EOF\n";
    assert!(total_len >= header.len() + footer.len());
    let body_len = total_len - header.len() - footer.len();

    let mut bytes = Vec::with_capacity(total_len);
    bytes.extend_from_slice(header);
    bytes.extend((0..body_len).map(|i| b'A' + (i % 26) as u8));
    bytes.extend_from_slice(footer);
    bytes
}

fn build_spoofed_elf_payload() -> Vec<u8> {
    let mut payload = vec![0u8; 128];
    payload[..8].copy_from_slice(&[0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00]);
    payload[16] = 0x02;
    payload
}

fn build_spoofed_pe_payload() -> Vec<u8> {
    let mut payload = vec![0u8; 128];
    payload[..4].copy_from_slice(&[0x4D, 0x5A, 0x90, 0x00]);
    payload
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn mode_bits(path: &Path) -> u32 {
    std::fs::metadata(path)
        .expect("read file metadata")
        .permissions()
        .mode()
        & 0o777
}

#[tokio::test]
async fn e2e_http_auth_security_headers_and_not_found_over_real_tcp() {
    let server = E2eTestServer::start().await;
    let valid_auth = auth_header_value(TEST_ADMIN_TOKEN);

    // 1. Unauthenticated, wrong Bearer, malformed schemes, and query-param tokens MUST return 401 + security headers.
    let unauthorized_cases: Vec<(&str, String, Option<String>, &[u8])> = vec![
        ("GET", "/api/v1/health".to_string(), None, b""),
        ("GET", "/api/v1/config".to_string(), None, b""),
        ("GET", "/api/v1/reports".to_string(), None, b""),
        ("GET", "/api/v1/alerts".to_string(), None, b""),
        ("GET", "/api/v1/events/stream".to_string(), None, b""),
        ("GET", "/api/".to_string(), None, b""),
        (
            "PATCH",
            "/api/v1/config".to_string(),
            None,
            br#"{"quarantine_dir":"/tmp/q","approved_dir":"/tmp/a"}"#,
        ),
        ("GET", "/api/v1/unknown".to_string(), None, b""),
        (
            "GET",
            "/api/v1/reports".to_string(),
            Some("Bearer wrong_token_value".to_string()),
            b"",
        ),
        (
            "GET",
            "/api/v1/reports".to_string(),
            Some(format!(
                "Bearer {}x",
                &TEST_ADMIN_TOKEN[..TEST_ADMIN_TOKEN.len() - 1]
            )),
            b"",
        ),
        (
            "PATCH",
            "/api/v1/config".to_string(),
            Some("Bearer wrong_patch_token".to_string()),
            br#"{"quarantine_dir":"/tmp/q","approved_dir":"/tmp/a"}"#,
        ),
        (
            "GET",
            "/api/v1/alerts".to_string(),
            Some("Basic dXNlcjpwYXNz".to_string()),
            b"",
        ),
        (
            "GET",
            "/api/v1/alerts".to_string(),
            Some("Bearer".to_string()),
            b"",
        ),
        (
            "GET",
            "/api/v1/alerts".to_string(),
            Some("Bearer    ".to_string()),
            b"",
        ),
        (
            "GET",
            "/api/v1/alerts".to_string(),
            Some(format!("Token {TEST_ADMIN_TOKEN}")),
            b"",
        ),
        (
            "GET",
            format!("/api/v1/health?token={TEST_ADMIN_TOKEN}"),
            None,
            b"",
        ),
        (
            "GET",
            format!("/api/v1/events/stream?token={TEST_ADMIN_TOKEN}"),
            None,
            b"",
        ),
        (
            "GET",
            format!("/api/v1/unknown?token={TEST_ADMIN_TOKEN}"),
            None,
            b"",
        ),
    ];

    for (method, path_and_query, auth_opt, body) in unauthorized_cases {
        let mut req_headers = Vec::new();
        if let Some(ref auth) = auth_opt {
            req_headers.push(("Authorization", auth.as_str()));
        }
        if !body.is_empty() {
            req_headers.push(("Content-Type", "application/json"));
        }

        let res = send_http_request(server.addr, method, &path_and_query, &req_headers, body).await;
        assert_eq!(
            res.status, 401,
            "expected 401 Unauthorized for {method} {path_and_query} (auth={auth_opt:?})"
        );
        assert_eq!(
            res.header("www-authenticate"),
            Some("Bearer"),
            "missing WWW-Authenticate: Bearer for {method} {path_and_query}"
        );
        res.assert_security_headers();
        assert_eq!(res.json()["error"], "unauthorized");
    }

    // 2. Authenticated unknown route returns 404 Not Found JSON with security headers.
    let not_found = send_http_request(
        server.addr,
        "GET",
        "/api/v1/unknown",
        &[("Authorization", valid_auth.as_str())],
        b"",
    )
    .await;
    assert_eq!(not_found.status, 404);
    not_found.assert_security_headers();
    let not_found_json = not_found.json();
    assert_eq!(not_found_json["error"], "not_found");
    assert_eq!(not_found_json["message"], "Endpoint not found");

    // 3. Authenticated unsupported HTTP method returns 405 Method Not Allowed JSON with security headers.
    let method_not_allowed = send_http_request(
        server.addr,
        "POST",
        "/api/v1/health",
        &[("Authorization", valid_auth.as_str())],
        b"",
    )
    .await;
    assert_eq!(method_not_allowed.status, 405);
    method_not_allowed.assert_security_headers();
    assert_eq!(method_not_allowed.json()["error"], "method_not_allowed");

    // 4. Fast negative-path checks using tower::ServiceExt on duplicate Authorization headers & case-insensitive scheme.
    let router = build_api_router(server.state.clone());
    let dup_res = router
        .clone()
        .oneshot(
            HttpRequest::builder()
                .uri("/api/v1/health")
                .header(header::AUTHORIZATION, valid_auth.as_str())
                .header(header::AUTHORIZATION, "Bearer second_header")
                .body(Body::empty())
                .expect("build duplicate auth request"),
        )
        .await
        .expect("execute duplicate auth oneshot");
    assert_eq!(dup_res.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        dup_res
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok()),
        Some("Bearer")
    );

    let lowercase_scheme_res = router
        .oneshot(
            HttpRequest::builder()
                .uri("/api/v1/health")
                .header(header::AUTHORIZATION, format!("bearer {TEST_ADMIN_TOKEN}"))
                .body(Body::empty())
                .expect("build lowercase bearer request"),
        )
        .await
        .expect("execute lowercase bearer oneshot");
    assert_eq!(lowercase_scheme_res.status(), StatusCode::OK);
    let body_bytes = to_bytes(lowercase_scheme_res.into_body(), 1024 * 1024)
        .await
        .expect("read oneshot body");
    let health: HealthResponse = serde_json::from_slice(&body_bytes).expect("parse HealthResponse");
    assert_eq!(health.status, "ok");

    // Empty/whitespace configured token must fail closed with 401.
    let fail_closed_state = Arc::new(ApiState {
        config_store: server.state.config_store.clone(),
        quarantine_repo: server.state.quarantine_repo.clone(),
        runtime_config: server.state.runtime_config.clone(),
        update_config_use_case: server.state.update_config_use_case.clone(),
        suricata_correlator: server.state.suricata_correlator.clone(),
        sse_broadcaster: server.state.sse_broadcaster.clone(),
        admin_api_token: SecretString::from("   ".to_string()),
    });
    let fail_closed_res = build_api_router(fail_closed_state)
        .oneshot(
            HttpRequest::builder()
                .uri("/api/v1/health")
                .header(header::AUTHORIZATION, "Bearer anything")
                .body(Body::empty())
                .expect("build fail-closed request"),
        )
        .await
        .expect("execute fail-closed oneshot");
    assert_eq!(fail_closed_res.status(), StatusCode::UNAUTHORIZED);

    server.shutdown().await;
}

#[tokio::test]
async fn e2e_rest_health_config_reports_and_suricata_alerts_with_real_sqlite() {
    let server = E2eTestServer::start().await;
    let valid_auth = auth_header_value(TEST_ADMIN_TOKEN);

    // 1. GET /api/v1/health and GET /api/v1/config reflect seeded SqliteStore RuntimeConfig.
    let health_res = send_http_request(
        server.addr,
        "GET",
        "/api/v1/health",
        &[("Authorization", valid_auth.as_str())],
        b"",
    )
    .await;
    assert_eq!(health_res.status, 200);
    health_res.assert_security_headers();
    let health: HealthResponse =
        serde_json::from_slice(&health_res.body).expect("deserialize HealthResponse");
    assert_eq!(health.status, "ok");
    assert_eq!(health.sse_subscribers, 0);
    assert_eq!(health.config.quarantine_dir, server.quarantine_dir);
    assert_eq!(health.config.approved_dir, server.approved_dir);
    assert_eq!(health.config.suricata_eve_path, server.eve_path);

    let config_res = send_http_request(
        server.addr,
        "GET",
        "/api/v1/config",
        &[("Authorization", valid_auth.as_str())],
        b"",
    )
    .await;
    assert_eq!(config_res.status, 200);
    config_res.assert_security_headers();
    let fetched_config: RuntimeConfig =
        serde_json::from_slice(&config_res.body).expect("deserialize RuntimeConfig");
    let expected_config = server.runtime_config.read().await.clone();
    assert_eq!(fetched_config, expected_config);

    // 2. Inspect real files (spoofed ELF .pdf, spoofed PE/MZ .jpg, empty .pdf, clean >64KB .pdf).
    let elf_path = server.quarantine_dir.join("malicious_elf.pdf");
    std::fs::write(&elf_path, build_spoofed_elf_payload()).expect("write spoofed ELF");
    std::fs::set_permissions(&elf_path, std::fs::Permissions::from_mode(0o755)).expect("chmod ELF");
    let elf_report = server
        .inspect_use_case
        .execute(&elf_path)
        .await
        .expect("inspect spoofed ELF");
    assert!(matches!(
        elf_report.verdict,
        SecurityVerdict::MaliciousSpoofing { .. }
    ));
    let expected_elf_dest = server.quarantine_dir.join(".isolated/malicious_elf.pdf");
    assert_eq!(
        elf_report.destination_path.as_ref(),
        Some(&expected_elf_dest)
    );
    assert_eq!(mode_bits(&expected_elf_dest), 0o600);

    let pe_path = server.quarantine_dir.join("trojan_pe.jpg");
    std::fs::write(&pe_path, build_spoofed_pe_payload()).expect("write spoofed PE");
    let pe_report = server
        .inspect_use_case
        .execute(&pe_path)
        .await
        .expect("inspect spoofed PE");
    assert!(matches!(
        pe_report.verdict,
        SecurityVerdict::MaliciousSpoofing { .. }
    ));

    let empty_path = server.quarantine_dir.join("empty_doc.pdf");
    std::fs::write(&empty_path, b"").expect("write empty file");
    let empty_report = server
        .inspect_use_case
        .execute(&empty_path)
        .await
        .expect("inspect empty file");
    assert!(matches!(
        empty_report.verdict,
        SecurityVerdict::CorruptedOrUnreadable { .. }
    ));

    let clean_pdf_bytes = build_valid_pdf(80 * 1024);
    let clean_pdf_sha = sha256_hex(&clean_pdf_bytes);
    let clean_path = server.quarantine_dir.join("clean_invoice.pdf");
    std::fs::write(&clean_path, &clean_pdf_bytes).expect("write clean >64KB PDF");
    let clean_report = server
        .inspect_use_case
        .execute(&clean_path)
        .await
        .expect("inspect clean >64KB PDF");
    assert_eq!(clean_report.verdict, SecurityVerdict::Clean);
    assert_eq!(clean_report.artifact.sha256_hash, clean_pdf_sha);
    assert_eq!(
        clean_report.destination_path.as_ref(),
        Some(&server.approved_dir.join("clean_invoice.pdf"))
    );
    assert_eq!(
        mode_bits(&server.approved_dir.join("clean_invoice.pdf")),
        0o640
    );

    // Verify all 4 real reports via GET /api/v1/reports ordered newest-first.
    let initial_reports_res = send_http_request(
        server.addr,
        "GET",
        "/api/v1/reports",
        &[("Authorization", valid_auth.as_str())],
        b"",
    )
    .await;
    assert_eq!(initial_reports_res.status, 200);
    initial_reports_res.assert_security_headers();
    let initial_reports: ReportsResponse =
        serde_json::from_slice(&initial_reports_res.body).expect("deserialize ReportsResponse");
    assert_eq!(initial_reports.count, 4);
    assert_eq!(initial_reports.reports.len(), 4);
    assert_eq!(
        initial_reports
            .reports
            .iter()
            .map(|r| r.artifact.sanitized_name.as_str())
            .collect::<Vec<_>>(),
        vec![
            "clean_invoice.pdf",
            "empty_doc.pdf",
            "trojan_pe.jpg",
            "malicious_elf.pdf",
        ]
    );
    assert_eq!(initial_reports.reports[0], clean_report);
    assert_eq!(initial_reports.reports[3], elf_report);

    // 3. Seed additional reports up to 505 total to verify default=50, clamping 0->1 and 9999->500, and newest-first order.
    let future_base = Utc::now() + ChronoDuration::seconds(10);
    for seq in 1..=501_i64 {
        let synthetic_report = InspectionReport {
            id: None,
            artifact: FileArtifact {
                path: server.quarantine_dir.join(format!("bulk_{seq:03}.pdf")),
                sanitized_name: format!("bulk_{seq:03}.pdf"),
                extension: Some("pdf".to_string()),
                size_bytes: 1_024,
                sha256_hash: format!("{seq:064x}"),
                detected_mime: Some("application/pdf".to_string()),
            },
            verdict: if seq % 2 == 0 {
                SecurityVerdict::Clean
            } else {
                SecurityVerdict::MaliciousSpoofing {
                    expected_ext: "pdf".to_string(),
                    actual_mime: "application/x-executable".to_string(),
                }
            },
            destination_path: Some(server.approved_dir.join(format!("bulk_{seq:03}.pdf"))),
            inspected_at: future_base + ChronoDuration::milliseconds(seq),
        };
        server
            .store
            .save_report(&synthetic_report)
            .await
            .expect("persist synthetic report");
    }

    // Default limit (no query param) -> 50 reports, newest-first.
    let default_res = send_http_request(
        server.addr,
        "GET",
        "/api/v1/reports",
        &[("Authorization", valid_auth.as_str())],
        b"",
    )
    .await;
    assert_eq!(default_res.status, 200);
    default_res.assert_security_headers();
    let default_reports: ReportsResponse =
        serde_json::from_slice(&default_res.body).expect("parse default reports");
    assert_eq!(default_reports.count, 50);
    assert_eq!(default_reports.reports.len(), 50);
    assert_eq!(
        default_reports.reports[0].artifact.sanitized_name,
        "bulk_501.pdf"
    );
    assert_eq!(
        default_reports.reports[49].artifact.sanitized_name,
        "bulk_452.pdf"
    );
    for pair in default_reports.reports.windows(2) {
        assert!(pair[0].inspected_at >= pair[1].inspected_at);
    }

    // Clamping limit=0 -> 1 report (newest).
    let min_res = send_http_request(
        server.addr,
        "GET",
        "/api/v1/reports?limit=0",
        &[("Authorization", valid_auth.as_str())],
        b"",
    )
    .await;
    assert_eq!(min_res.status, 200);
    min_res.assert_security_headers();
    let min_reports: ReportsResponse =
        serde_json::from_slice(&min_res.body).expect("parse limit=0 reports");
    assert_eq!(min_reports.count, 1);
    assert_eq!(min_reports.reports.len(), 1);
    assert_eq!(
        min_reports.reports[0].artifact.sanitized_name,
        "bulk_501.pdf"
    );

    // Clamping limit=9999 -> 500 reports (out of 505 total).
    let max_res = send_http_request(
        server.addr,
        "GET",
        "/api/v1/reports?limit=9999",
        &[("Authorization", valid_auth.as_str())],
        b"",
    )
    .await;
    assert_eq!(max_res.status, 200);
    max_res.assert_security_headers();
    let max_reports: ReportsResponse =
        serde_json::from_slice(&max_res.body).expect("parse limit=9999 reports");
    assert_eq!(max_reports.count, 500);
    assert_eq!(max_reports.reports.len(), 500);
    assert_eq!(
        max_reports.reports[0].artifact.sanitized_name,
        "bulk_501.pdf"
    );
    assert_eq!(
        max_reports.reports[499].artifact.sanitized_name,
        "bulk_002.pdf"
    );

    // Non-numeric and negative limit -> 400 Bad Request JSON.
    for bad_query in ["/api/v1/reports?limit=abc", "/api/v1/reports?limit=-5"] {
        let bad_res = send_http_request(
            server.addr,
            "GET",
            bad_query,
            &[("Authorization", valid_auth.as_str())],
            b"",
        )
        .await;
        assert_eq!(bad_res.status, 400, "expected 400 for {bad_query}");
        bad_res.assert_security_headers();
        assert_eq!(bad_res.json()["error"], "bad_request");
    }

    // 4. Suricata eve.json mixing active high-severity alerts, benign events, low-severity alert, and expired alert.
    let now = Utc::now();
    let ts_recent_1 =
        (now - ChronoDuration::seconds(15)).to_rfc3339_opts(SecondsFormat::Micros, false);
    let ts_recent_2 =
        (now - ChronoDuration::seconds(5)).to_rfc3339_opts(SecondsFormat::Micros, false);
    let ts_expired =
        (now - ChronoDuration::minutes(20)).to_rfc3339_opts(SecondsFormat::Micros, false);

    let eve_contents = [
        format!(
            "{{\"timestamp\":\"{ts_expired}\",\"event_type\":\"alert\",\"src_ip\":\"203.0.113.9\",\"dest_ip\":\"10.0.0.5\",\"alert\":{{\"signature\":\"ET EXPIRED Old Alert\",\"severity\":1}}}}"
        ),
        format!(
            "{{\"timestamp\":\"{ts_recent_1}\",\"event_type\":\"dns\",\"src_ip\":\"10.0.0.15\",\"dest_ip\":\"8.8.8.8\",\"dns\":{{\"rrname\":\"example.com\"}}}}"
        ),
        format!(
            "{{\"timestamp\":\"{ts_recent_1}\",\"event_type\":\"alert\",\"src_ip\":\"198.51.100.42\",\"dest_ip\":\"10.0.0.10\",\"alert\":{{\"signature\":\"ET MALWARE CobaltStrike Beacon\",\"severity\":1}}}}"
        ),
        format!(
            "{{\"timestamp\":\"{ts_recent_2}\",\"event_type\":\"alert\",\"src_ip\":\"192.0.2.77\",\"dest_ip\":\"10.0.0.12\",\"alert\":{{\"signature\":\"ET INFO Low Severity Noise\",\"severity\":3}}}}"
        ),
        format!(
            "{{\"timestamp\":\"{ts_recent_2}\",\"event_type\":\"http\",\"src_ip\":\"10.0.0.20\",\"dest_ip\":\"93.184.216.34\"}}"
        ),
        format!(
            "{{\"timestamp\":\"{ts_recent_2}\",\"event_type\":\"alert\",\"src_ip\":\"203.0.113.55\",\"dest_ip\":\"10.0.0.10\",\"alert\":{{\"signature\":\"ET POLICY Suspicious Executable Download\",\"severity\":2}}}}"
        ),
    ]
    .join("\n")
        + "\n";
    std::fs::write(&server.eve_path, eve_contents).expect("write eve.json");

    let alerts_res = send_http_request(
        server.addr,
        "GET",
        "/api/v1/alerts",
        &[("Authorization", valid_auth.as_str())],
        b"",
    )
    .await;
    assert_eq!(alerts_res.status, 200);
    alerts_res.assert_security_headers();
    let alerts_payload: AlertsResponse =
        serde_json::from_slice(&alerts_res.body).expect("deserialize AlertsResponse");
    assert_eq!(alerts_payload.count, 2);
    assert_eq!(alerts_payload.alerts.len(), 2);

    assert_eq!(
        alerts_payload.alerts[0],
        NetworkAlert {
            timestamp: chrono::DateTime::parse_from_rfc3339(&ts_recent_1)
                .expect("ts_recent_1")
                .with_timezone(&Utc),
            src_ip: "198.51.100.42".to_string(),
            dest_ip: "10.0.0.10".to_string(),
            signature: "ET MALWARE CobaltStrike Beacon".to_string(),
            severity: 1,
        }
    );
    assert_eq!(
        alerts_payload.alerts[1],
        NetworkAlert {
            timestamp: chrono::DateTime::parse_from_rfc3339(&ts_recent_2)
                .expect("ts_recent_2")
                .with_timezone(&Utc),
            src_ip: "203.0.113.55".to_string(),
            dest_ip: "10.0.0.10".to_string(),
            signature: "ET POLICY Suspicious Executable Download".to_string(),
            severity: 2,
        }
    );

    // Append a new active alert to eve.json and confirm live incremental tailing via GET /api/v1/alerts.
    let ts_recent_3 = Utc::now().to_rfc3339_opts(SecondsFormat::Micros, false);
    {
        use std::io::Write;
        let mut eve_file = std::fs::OpenOptions::new()
            .append(true)
            .open(&server.eve_path)
            .expect("open eve.json for append");
        writeln!(
            eve_file,
            "{{\"timestamp\":\"{ts_recent_3}\",\"event_type\":\"alert\",\"src_ip\":\"198.51.100.88\",\"dest_ip\":\"10.0.0.10\",\"alert\":{{\"signature\":\"ET TROJAN Incremental Append Alert\",\"severity\":1}}}}"
        )
        .expect("append alert line to eve.json");
    }

    let updated_alerts_res = send_http_request(
        server.addr,
        "GET",
        "/api/v1/alerts",
        &[("Authorization", valid_auth.as_str())],
        b"",
    )
    .await;
    assert_eq!(updated_alerts_res.status, 200);
    let updated_alerts: AlertsResponse =
        serde_json::from_slice(&updated_alerts_res.body).expect("deserialize updated alerts");
    assert_eq!(updated_alerts.count, 3);
    assert_eq!(
        updated_alerts.alerts[2].signature,
        "ET TROJAN Incremental Append Alert"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn e2e_patch_config_hot_reload_and_security_error_mapping() {
    let mut server = E2eTestServer::start().await;
    let valid_auth = auth_header_value(TEST_ADMIN_TOKEN);
    let mut sse_rx = server.sse_broadcaster.subscribe();

    let new_q = server.canonical_root.join("hot_quarantine");
    let new_a = server.canonical_root.join("hot_approved");
    let new_eve = server.canonical_root.join("logs/suricata/eve.json");
    std::fs::create_dir_all(&new_q).expect("create new_q");
    std::fs::create_dir_all(&new_a).expect("create new_a");
    std::fs::create_dir_all(new_eve.parent().expect("new_eve parent"))
        .expect("create new_eve parent");

    // 1. Valid PATCH /api/v1/config updates SQLite, RuntimeConfig, watch channel, and broadcasts SseEvent::ConfigUpdated.
    let valid_payload = json!({
        "quarantine_dir": new_q,
        "approved_dir": new_a,
        "clamd_socket_path": null,
        "suricata_eve_path": new_eve,
    })
    .to_string();

    let patch_res = send_http_request(
        server.addr,
        "PATCH",
        "/api/v1/config",
        &[
            ("Authorization", valid_auth.as_str()),
            ("Content-Type", "application/json"),
        ],
        valid_payload.as_bytes(),
    )
    .await;
    assert_eq!(patch_res.status, 200);
    patch_res.assert_security_headers();
    let updated_cfg: RuntimeConfig =
        serde_json::from_slice(&patch_res.body).expect("deserialize updated RuntimeConfig");
    assert_eq!(updated_cfg.quarantine_dir, new_q);
    assert_eq!(updated_cfg.approved_dir, new_a);
    assert_eq!(updated_cfg.suricata_eve_path, new_eve);

    // Verify in-memory RuntimeConfig and GET /api/v1/config.
    assert_eq!(*server.runtime_config.read().await, updated_cfg);
    let get_cfg_res = send_http_request(
        server.addr,
        "GET",
        "/api/v1/config",
        &[("Authorization", valid_auth.as_str())],
        b"",
    )
    .await;
    assert_eq!(get_cfg_res.status, 200);
    let fetched_cfg: RuntimeConfig =
        serde_json::from_slice(&get_cfg_res.body).expect("deserialize GET /config");
    assert_eq!(fetched_cfg, updated_cfg);

    // Verify SQLite persistence across an independent connection.
    let verify_store = SqliteStore::connect_and_migrate(&server.db_url)
        .await
        .expect("open independent SqliteStore");
    let persisted_cfg = verify_store
        .load_or_seed(&RuntimeConfig {
            quarantine_dir: server.quarantine_dir.clone(),
            approved_dir: server.approved_dir.clone(),
            clamd_socket_path: PathBuf::from("/tmp/unused.ctl"),
            suricata_eve_path: PathBuf::from("/tmp/unused_eve.json"),
            updated_at: Utc::now(),
        })
        .await
        .expect("load persisted config from SQLite");
    assert_eq!(persisted_cfg, updated_cfg);
    verify_store.close().await.expect("close verify_store");

    // Verify watch::Receiver<PathBuf> notification and SseEvent::ConfigUpdated broadcast.
    assert!(server.watcher_rx.has_changed().expect("watch channel open"));
    assert_eq!(*server.watcher_rx.borrow_and_update(), new_q);
    let emitted_event = tokio::time::timeout(IO_TIMEOUT, sse_rx.recv())
        .await
        .expect("timed out waiting for ConfigUpdated broadcast")
        .expect("receive ConfigUpdated");
    assert_eq!(
        emitted_event,
        SseEvent::ConfigUpdated {
            config: updated_cfg.clone()
        }
    );

    // Prepare fixtures for 403 / 400 / 413 negative tests.
    let missing_dir = server.canonical_root.join("does_not_exist");
    let regular_file = server.canonical_root.join("not_a_directory.txt");
    std::fs::write(&regular_file, b"regular file").expect("write regular file");
    let readonly_dir = server.canonical_root.join("readonly_dir");
    std::fs::create_dir_all(&readonly_dir).expect("create readonly_dir");
    std::fs::set_permissions(&readonly_dir, std::fs::Permissions::from_mode(0o555))
        .expect("chmod 0555 readonly_dir");

    // 2. Path traversal and forbidden system directories return 403 Forbidden without mutating state.
    let traversal_q = new_q.join("../escape");
    let traversal_a = new_a.join("sub/../escape");
    let forbidden_cases = [
        (
            traversal_q.to_string_lossy().into_owned(),
            new_a.to_string_lossy().into_owned(),
        ),
        (
            "/tmp/../escape".to_string(),
            new_a.to_string_lossy().into_owned(),
        ),
        (
            new_q.to_string_lossy().into_owned(),
            traversal_a.to_string_lossy().into_owned(),
        ),
        (
            "/etc/sentinel".to_string(),
            new_a.to_string_lossy().into_owned(),
        ),
        (
            new_q.to_string_lossy().into_owned(),
            "/etc/sentinel".to_string(),
        ),
        ("/bin".to_string(), new_a.to_string_lossy().into_owned()),
        ("/usr".to_string(), new_a.to_string_lossy().into_owned()),
        ("/root".to_string(), new_a.to_string_lossy().into_owned()),
    ];

    for (bad_q, bad_a) in forbidden_cases {
        let payload = json!({
            "quarantine_dir": bad_q,
            "approved_dir": bad_a,
            "clamd_socket_path": null,
            "suricata_eve_path": null,
        })
        .to_string();

        let res = send_http_request(
            server.addr,
            "PATCH",
            "/api/v1/config",
            &[
                ("Authorization", valid_auth.as_str()),
                ("Content-Type", "application/json"),
            ],
            payload.as_bytes(),
        )
        .await;
        assert_eq!(
            res.status,
            403,
            "expected 403 Forbidden for q={bad_q:?}, a={bad_a:?}, body={}",
            String::from_utf8_lossy(&res.body)
        );
        res.assert_security_headers();
        assert_eq!(res.json()["error"], "forbidden");
    }

    let nested_inside_q = new_q.join("nested_approved");
    std::fs::create_dir_all(&nested_inside_q).expect("create nested_inside_q");

    // 3. Missing directory, read-only directory, regular file, equal/nested dirs, and relative paths return 400 Bad Request.
    let bad_request_cases = [
        ("missing_q", missing_dir.clone(), new_a.clone()),
        ("missing_a", new_q.clone(), missing_dir),
        ("readonly_q", readonly_dir.clone(), new_a.clone()),
        ("readonly_a", new_q.clone(), readonly_dir.clone()),
        ("regular_file_q", regular_file.clone(), new_a.clone()),
        ("regular_file_a", new_q.clone(), regular_file),
        ("equal_dirs", new_q.clone(), new_q.clone()),
        ("nested_dirs", new_q.clone(), nested_inside_q),
        (
            "relative_dir",
            PathBuf::from("relative/quarantine"),
            new_a.clone(),
        ),
    ];

    for (label, bad_q, bad_a) in bad_request_cases {
        let payload = json!({
            "quarantine_dir": bad_q,
            "approved_dir": bad_a,
            "clamd_socket_path": null,
            "suricata_eve_path": null,
        })
        .to_string();

        let res = send_http_request(
            server.addr,
            "PATCH",
            "/api/v1/config",
            &[
                ("Authorization", valid_auth.as_str()),
                ("Content-Type", "application/json"),
            ],
            payload.as_bytes(),
        )
        .await;
        assert_eq!(
            res.status,
            400,
            "expected 400 Bad Request for {label}, body={}",
            String::from_utf8_lossy(&res.body)
        );
        res.assert_security_headers();
        assert_eq!(res.json()["error"], "bad_request");
    }

    // Restore permissions so TempDir cleanup succeeds cleanly.
    let _ = std::fs::set_permissions(&readonly_dir, std::fs::Permissions::from_mode(0o755));

    // 4. Oversized payload (> 64 KB) returns 413 Payload Too Large without mutating state.
    let oversized_value = "x".repeat(MAX_API_BODY_BYTES + 2048);
    let oversized_payload = json!({
        "quarantine_dir": oversized_value,
        "approved_dir": new_a,
        "clamd_socket_path": null,
        "suricata_eve_path": null,
    })
    .to_string();
    assert!(oversized_payload.len() > MAX_API_BODY_BYTES);

    let limit_res = send_http_request(
        server.addr,
        "PATCH",
        "/api/v1/config",
        &[
            ("Authorization", valid_auth.as_str()),
            ("Content-Type", "application/json"),
        ],
        oversized_payload.as_bytes(),
    )
    .await;
    assert_eq!(limit_res.status, 413);
    limit_res.assert_security_headers();
    assert_eq!(limit_res.json()["error"], "payload_too_large");

    // Verify zero state mutation across memory, SQLite, watch channel, and SSE broadcaster after all rejected PATCH calls.
    assert_eq!(*server.runtime_config.read().await, updated_cfg);
    let check_store = SqliteStore::connect_and_migrate(&server.db_url)
        .await
        .expect("reconnect SqliteStore");
    let still_persisted = check_store
        .load_or_seed(&updated_cfg)
        .await
        .expect("read persisted config");
    assert_eq!(still_persisted, updated_cfg);
    check_store.close().await.expect("close check_store");

    assert!(
        !server
            .watcher_rx
            .has_changed()
            .expect("watch channel still open"),
        "rejected PATCH calls must not notify watcher channel"
    );
    assert!(
        sse_rx.try_recv().is_err(),
        "rejected PATCH calls must not broadcast SseEvent::ConfigUpdated"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn e2e_live_tcp_sse_stream_config_inspection_and_graceful_shutdown() {
    let mut server = E2eTestServer::start().await;
    let valid_auth = auth_header_value(TEST_ADMIN_TOKEN);

    // 1. Connect authenticated client over raw TcpStream to GET /api/v1/events/stream.
    let mut sse_client =
        SseTcpClient::connect(server.addr, "/api/v1/events/stream", TEST_ADMIN_TOKEN).await;
    assert_eq!(sse_client.status, 200);
    assert_eq!(sse_client.header("content-type"), Some("text/event-stream"));
    sse_client.assert_security_headers();

    // Verify GET /api/v1/health reports sse_subscribers == 1.
    let health_res = send_http_request(
        server.addr,
        "GET",
        "/api/v1/health",
        &[("Authorization", valid_auth.as_str())],
        b"",
    )
    .await;
    assert_eq!(health_res.status, 200);
    let health: HealthResponse =
        serde_json::from_slice(&health_res.body).expect("parse HealthResponse");
    assert_eq!(health.sse_subscribers, 1);

    // 2. Trigger PATCH /api/v1/config and verify live TCP SSE receives `event: config_updated`.
    let hot_q = server.canonical_root.join("sse_quarantine");
    let hot_a = server.canonical_root.join("sse_approved");
    std::fs::create_dir_all(&hot_q).expect("create hot_q");
    std::fs::create_dir_all(&hot_a).expect("create hot_a");

    let patch_body = json!({
        "quarantine_dir": hot_q,
        "approved_dir": hot_a,
        "clamd_socket_path": null,
        "suricata_eve_path": null,
    })
    .to_string();
    let patch_res = send_http_request(
        server.addr,
        "PATCH",
        "/api/v1/config",
        &[
            ("Authorization", valid_auth.as_str()),
            ("Content-Type", "application/json"),
        ],
        patch_body.as_bytes(),
    )
    .await;
    assert_eq!(patch_res.status, 200);
    let patched_cfg: RuntimeConfig =
        serde_json::from_slice(&patch_res.body).expect("parse patched RuntimeConfig");

    let config_frame = sse_client.next_event_frame(IO_TIMEOUT).await;
    assert_eq!(config_frame.event.as_deref(), Some("config_updated"));
    assert_eq!(
        config_frame.parse_sse_event(),
        SseEvent::ConfigUpdated {
            config: patched_cfg
        }
    );

    // 3. Trigger real file inspection (spoofed ELF .pdf isolated to .isolated/ + clean .pdf approved) & publish via SseBroadcaster.
    let spoofed_src = hot_q.join("spoofed_elf.pdf");
    let spoofed_bytes = build_spoofed_elf_payload();
    std::fs::write(&spoofed_src, &spoofed_bytes).expect("write spoofed_elf.pdf");
    std::fs::set_permissions(&spoofed_src, std::fs::Permissions::from_mode(0o755))
        .expect("chmod spoofed_elf.pdf");

    let spoofed_report = server
        .inspect_use_case
        .execute(&spoofed_src)
        .await
        .expect("execute InspectFileUseCase for spoofed ELF");
    let expected_isolated_dest = hot_q.join(".isolated/spoofed_elf.pdf");
    assert_eq!(
        spoofed_report.destination_path.as_ref(),
        Some(&expected_isolated_dest)
    );
    assert!(expected_isolated_dest.exists());
    assert_eq!(mode_bits(&expected_isolated_dest), 0o600);
    assert!(matches!(
        spoofed_report.verdict,
        SecurityVerdict::MaliciousSpoofing {
            ref expected_ext,
            ref actual_mime,
        } if expected_ext == "pdf" && actual_mime == "application/x-executable"
    ));

    let delivered_spoofed = server
        .sse_broadcaster
        .publish(SseEvent::InspectionCompleted {
            report: spoofed_report.clone(),
        });
    assert_eq!(delivered_spoofed, 1);

    let spoofed_frame = sse_client.next_event_frame(IO_TIMEOUT).await;
    assert_eq!(spoofed_frame.event.as_deref(), Some("inspection_completed"));
    assert_eq!(
        spoofed_frame.parse_sse_event(),
        SseEvent::InspectionCompleted {
            report: spoofed_report.clone(),
        }
    );

    // Clean PDF (> 64 KB) approved to hot_a.
    let clean_src = hot_q.join("quarterly_report.pdf");
    let clean_bytes = build_valid_pdf(72 * 1024);
    std::fs::write(&clean_src, &clean_bytes).expect("write quarterly_report.pdf");
    std::fs::set_permissions(&clean_src, std::fs::Permissions::from_mode(0o755))
        .expect("chmod quarterly_report.pdf");

    let clean_report = server
        .inspect_use_case
        .execute(&clean_src)
        .await
        .expect("execute InspectFileUseCase for clean PDF");
    let expected_approved_dest = hot_a.join("quarterly_report.pdf");
    assert_eq!(clean_report.verdict, SecurityVerdict::Clean);
    assert_eq!(
        clean_report.destination_path.as_ref(),
        Some(&expected_approved_dest)
    );
    assert!(expected_approved_dest.exists());
    assert_eq!(mode_bits(&expected_approved_dest), 0o640);

    let delivered_clean = server
        .sse_broadcaster
        .publish(SseEvent::InspectionCompleted {
            report: clean_report.clone(),
        });
    assert_eq!(delivered_clean, 1);

    let clean_frame = sse_client.next_event_frame(IO_TIMEOUT).await;
    assert_eq!(clean_frame.event.as_deref(), Some("inspection_completed"));
    assert_eq!(
        clean_frame.parse_sse_event(),
        SseEvent::InspectionCompleted {
            report: clean_report.clone(),
        }
    );

    // Also verify NetworkAlertDetected streaming and that REST /api/v1/reports matches the persisted verdicts.
    let alert_event = SseEvent::NetworkAlertDetected {
        alert: NetworkAlert {
            timestamp: Utc::now(),
            src_ip: "198.51.100.99".to_string(),
            dest_ip: "10.0.0.8".to_string(),
            signature: "ET MALWARE Live SSE Alert".to_string(),
            severity: 1,
        },
    };
    assert_eq!(server.sse_broadcaster.publish(alert_event.clone()), 1);
    let alert_frame = sse_client.next_event_frame(IO_TIMEOUT).await;
    assert_eq!(alert_frame.event.as_deref(), Some("network_alert_detected"));
    assert_eq!(alert_frame.parse_sse_event(), alert_event);

    let reports_res = send_http_request(
        server.addr,
        "GET",
        "/api/v1/reports",
        &[("Authorization", valid_auth.as_str())],
        b"",
    )
    .await;
    assert_eq!(reports_res.status, 200);
    let persisted_reports: ReportsResponse =
        serde_json::from_slice(&reports_res.body).expect("parse ReportsResponse");
    assert_eq!(persisted_reports.count, 2);
    assert_eq!(
        persisted_reports.reports,
        vec![clean_report, spoofed_report]
    );

    // 4. Signal sse_broadcaster.shutdown() + graceful server termination and verify socket closes cleanly.
    server.sse_broadcaster.shutdown();
    sse_client.wait_for_chunked_stream_end(IO_TIMEOUT).await;

    server.trigger_graceful_shutdown();
    sse_client.wait_for_tcp_eof(IO_TIMEOUT).await;
    server.await_exit().await;

    assert_eq!(server.sse_broadcaster.subscriber_count(), 0);
}
