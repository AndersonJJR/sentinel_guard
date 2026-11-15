//! End-to-end integration tests for embedded Vue 3 SPA static asset serving,
//! security headers, API/static 401 vs 404 boundaries, and path-traversal hardening.

use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Request as HttpRequest, StatusCode, header};
use chrono::Utc;
use secrecy::SecretString;
use serde_json::Value;
use tempfile::{TempDir, tempdir};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{RwLock, watch};
use tokio::task::JoinHandle;
use tower::ServiceExt;

use sentinel_guard::application::update_config::UpdateConfigUseCase;
use sentinel_guard::domain::entities::RuntimeConfig;
use sentinel_guard::domain::ports::ConfigStore;
use sentinel_guard::infrastructure::sqlite_repo::SqliteStore;
use sentinel_guard::infrastructure::suricata_tail::SuricataCorrelator;
use sentinel_guard::presentation::api_routes::{ApiState, build_api_router};
use sentinel_guard::presentation::sse_broadcaster::SseBroadcaster;
use sentinel_guard::presentation::static_assets::EmbeddedFrontendAssets;

const TEST_ADMIN_TOKEN: &str = "sentinel_m3_static_assets_test_token_0123456789abcdef01234567";
const EXPECTED_CSP: &str = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'";
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const FORBIDDEN_CDN_MARKERS: [&str; 5] =
    ["fonts.googleapis", "cdn.", "unpkg.com", "jsdelivr", "cdnjs"];

struct StaticAssetsTestServer {
    _temp_dir: TempDir,
    _watcher_rx: watch::Receiver<PathBuf>,
    addr: SocketAddr,
    state: Arc<ApiState>,
    sse_broadcaster: Arc<SseBroadcaster>,
    shutdown_tx: watch::Sender<bool>,
    server_handle: Option<JoinHandle<std::io::Result<()>>>,
}

impl StaticAssetsTestServer {
    async fn start() -> Self {
        let dir = tempdir().expect("create tempdir");
        let canonical_root = std::fs::canonicalize(dir.path()).expect("canonicalize tempdir");
        let quarantine_dir = canonical_root.join("quarantine");
        let approved_dir = canonical_root.join("approved");
        std::fs::create_dir_all(&quarantine_dir).expect("create quarantine_dir");
        std::fs::create_dir_all(&approved_dir).expect("create approved_dir");

        let clamd_socket_path = canonical_root.join("clamd.ctl");
        let eve_path = canonical_root.join("eve.json");

        let store = Arc::new(
            SqliteStore::connect_and_migrate("sqlite::memory:")
                .await
                .expect("connect and migrate in-memory SqliteStore"),
        );

        let default_config = RuntimeConfig {
            quarantine_dir,
            approved_dir,
            clamd_socket_path,
            suricata_eve_path: eve_path,
            updated_at: Utc::now(),
        };
        let initial_config = store
            .load_or_seed(&default_config)
            .await
            .expect("seed RuntimeConfig in SqliteStore");

        let runtime_config = Arc::new(RwLock::new(initial_config.clone()));
        let (watcher_tx, watcher_rx) = watch::channel(initial_config.quarantine_dir);
        let update_config_use_case = Arc::new(UpdateConfigUseCase::new(
            store.clone(),
            runtime_config.clone(),
            watcher_tx,
        ));
        let suricata_correlator = Arc::new(SuricataCorrelator::new(runtime_config.clone()));
        let sse_broadcaster = Arc::new(SseBroadcaster::new());

        let state = Arc::new(ApiState {
            config_store: store.clone(),
            quarantine_repo: store,
            runtime_config,
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
            _watcher_rx: watcher_rx,
            addr,
            state,
            sse_broadcaster,
            shutdown_tx,
            server_handle: Some(server_handle),
        }
    }

    async fn shutdown(mut self) {
        self.sse_broadcaster.shutdown();
        let _ = self.shutdown_tx.send(true);
        if let Some(handle) = self.server_handle.take() {
            tokio::time::timeout(IO_TIMEOUT, handle)
                .await
                .expect("timed out waiting for HTTP server exit")
                .expect("HTTP server task panicked")
                .expect("HTTP server returned I/O error");
        }
    }
}

impl Drop for StaticAssetsTestServer {
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

    fn body_utf8(&self) -> &str {
        std::str::from_utf8(&self.body).expect("response body should be valid UTF-8")
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|err| {
            panic!(
                "expected valid JSON body (status {}), err={err}, body={:?}",
                self.status,
                String::from_utf8_lossy(&self.body)
            )
        })
    }

    fn assert_security_headers(&self) {
        assert_eq!(self.header("x-content-type-options"), Some("nosniff"));
        assert_eq!(self.header("x-frame-options"), Some("DENY"));
        assert_eq!(self.header("referrer-policy"), Some("no-referrer"));
        let csp = self
            .header("content-security-policy")
            .expect("missing Content-Security-Policy header");
        assert!(
            csp.contains("default-src 'self'"),
            "CSP must contain default-src 'self', got: {csp}"
        );
        assert_eq!(csp, EXPECTED_CSP);
    }
}

async fn send_raw_http_request(
    addr: SocketAddr,
    method: &str,
    raw_target: &str,
    headers: &[(&str, &str)],
) -> RawHttpResponse {
    tokio::time::timeout(IO_TIMEOUT, async {
        let mut stream = TcpStream::connect(addr)
            .await
            .expect("connect TcpStream to HTTP server");

        let mut raw_req = Vec::with_capacity(256);
        raw_req.extend_from_slice(
            format!("{method} {raw_target} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n")
                .as_bytes(),
        );
        for (name, value) in headers {
            raw_req.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        raw_req.extend_from_slice(b"\r\n");

        if let Err(err) = stream.write_all(&raw_req).await {
            assert!(
                matches!(
                    err.kind(),
                    ErrorKind::BrokenPipe | ErrorKind::ConnectionReset
                ),
                "unexpected TCP write error for {method} {raw_target}: {err}"
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
    .unwrap_or_else(|_| panic!("HTTP request timed out: {method} {raw_target}"))
}

fn parse_raw_http_response(raw: &[u8]) -> RawHttpResponse {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or_else(|| {
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
        if let Some(len_str) = headers.get("content-length").and_then(|vals| vals.first()) {
            let expected_len: usize = len_str.parse().expect("valid Content-Length header");
            assert_eq!(
                body_slice.len(),
                expected_len,
                "body length mismatch against Content-Length"
            );
        }
        body_slice.to_vec()
    };

    RawHttpResponse {
        status,
        headers,
        body,
    }
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
        let crlf_pos = cursor
            .windows(2)
            .position(|w| w == b"\r\n")
            .expect("chunk size CRLF");
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

fn assert_axum_security_headers(headers: &HeaderMap) {
    assert_eq!(
        headers
            .get(header::X_CONTENT_TYPE_OPTIONS)
            .and_then(|v| v.to_str().ok()),
        Some("nosniff")
    );
    assert_eq!(
        headers
            .get(header::X_FRAME_OPTIONS)
            .and_then(|v| v.to_str().ok()),
        Some("DENY")
    );
    assert_eq!(
        headers
            .get(header::REFERRER_POLICY)
            .and_then(|v| v.to_str().ok()),
        Some("no-referrer")
    );
    let csp = headers
        .get(header::CONTENT_SECURITY_POLICY)
        .and_then(|v| v.to_str().ok())
        .expect("Content-Security-Policy header");
    assert!(csp.contains("default-src 'self'"));
    assert_eq!(csp, EXPECTED_CSP);
}

fn assert_no_external_cdns(content: &str, context: &str) {
    let lower = content.to_ascii_lowercase();
    for marker in FORBIDDEN_CDN_MARKERS {
        assert!(
            !lower.contains(marker),
            "unexpected external CDN reference {marker:?} in {context}"
        );
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ExtractedViteAssets {
    script_srcs: Vec<String>,
    stylesheet_hrefs: Vec<String>,
}

fn extract_tag_attribute(tag: &str, attr_name: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let needle = format!("{attr_name}=");
    let mut search_from = 0;

    while let Some(rel_idx) = lower[search_from..].find(&needle) {
        let idx = search_from + rel_idx;
        let preceded_by_whitespace = idx > 0 && tag.as_bytes()[idx - 1].is_ascii_whitespace();
        if !preceded_by_whitespace {
            search_from = idx + needle.len();
            continue;
        }

        let after_eq = tag[idx + needle.len()..].trim_start();
        if let Some(quote) = after_eq.chars().next().filter(|c| *c == '"' || *c == '\'') {
            let rest = &after_eq[quote.len_utf8()..];
            if let Some(end) = rest.find(quote) {
                return Some(rest[..end].to_string());
            }
            return None;
        }

        let end = after_eq
            .find(|c: char| c.is_ascii_whitespace() || c == '>')
            .unwrap_or(after_eq.len());
        return Some(after_eq[..end].to_string());
    }

    None
}

fn extract_vite_assets_from_html(html: &str) -> ExtractedViteAssets {
    let mut script_srcs = Vec::new();
    let mut stylesheet_hrefs = Vec::new();
    let mut cursor = html;

    while let Some(open_idx) = cursor.find('<') {
        let after_open = &cursor[open_idx..];
        let Some(close_idx) = after_open.find('>') else {
            break;
        };
        let tag = &after_open[..=close_idx];
        let lower_tag = tag.to_ascii_lowercase();

        if lower_tag.starts_with("<script")
            && lower_tag
                .as_bytes()
                .get(7)
                .is_some_and(|b| b.is_ascii_whitespace() || *b == b'>')
            && let Some(src) = extract_tag_attribute(tag, "src")
            && src.starts_with("/assets/")
        {
            script_srcs.push(src);
        } else if lower_tag.starts_with("<link")
            && lower_tag
                .as_bytes()
                .get(5)
                .is_some_and(|b| b.is_ascii_whitespace() || *b == b'>')
            && let Some(href) = extract_tag_attribute(tag, "href")
            && href.starts_with("/assets/")
        {
            stylesheet_hrefs.push(href);
        }

        cursor = &after_open[close_idx + 1..];
    }

    ExtractedViteAssets {
        script_srcs,
        stylesheet_hrefs,
    }
}

#[tokio::test]
async fn spa_routes_serve_real_built_html_and_security_headers_without_bearer_auth() {
    let server = StaticAssetsTestServer::start().await;
    let embedded_index = EmbeddedFrontendAssets::get("index.html")
        .expect("compiled vue_sentinel_guard/dist/index.html must be embedded");

    for route in ["/", "/dashboard", "/quarantine", "/config"] {
        let res = send_raw_http_request(server.addr, "GET", route, &[]).await;

        assert_eq!(res.status, 200, "expected 200 OK for GET {route}");
        assert_eq!(
            res.header("content-type"),
            Some("text/html; charset=utf-8"),
            "unexpected Content-Type for {route}"
        );
        assert_eq!(
            res.header("cache-control"),
            Some("no-cache"),
            "unexpected Cache-Control for {route}"
        );
        res.assert_security_headers();

        assert_eq!(
            res.body.as_slice(),
            embedded_index.data.as_ref(),
            "response body for {route} should match embedded index.html"
        );

        let html = res.body_utf8();
        assert!(
            html.contains("Sentinel Guard"),
            "expected 'Sentinel Guard' in HTML for {route}"
        );
        assert!(
            html.contains("<div id=\"app\"></div>"),
            "expected Vue mount root in HTML for {route}"
        );
        assert_no_external_cdns(html, route);
    }

    server.shutdown().await;
}

#[tokio::test]
async fn real_vite_assets_parsed_from_index_html_are_served_with_immutable_cache_and_no_cdns() {
    let server = StaticAssetsTestServer::start().await;

    let index_res = send_raw_http_request(server.addr, "GET", "/", &[]).await;
    assert_eq!(index_res.status, 200);
    let html = index_res.body_utf8();
    assert_no_external_cdns(html, "index.html");

    let extracted = extract_vite_assets_from_html(html);
    assert!(
        !extracted.script_srcs.is_empty(),
        "expected at least one compiled <script src=\"/assets/...\"> in index.html: {html}"
    );
    assert!(
        !extracted.stylesheet_hrefs.is_empty(),
        "expected at least one compiled <link href=\"/assets/...\"> in index.html: {html}"
    );

    for script_path in &extracted.script_srcs {
        let res = send_raw_http_request(server.addr, "GET", script_path, &[]).await;
        assert_eq!(res.status, 200, "expected 200 OK for {script_path}");
        res.assert_security_headers();
        assert_eq!(
            res.header("cache-control"),
            Some("public, max-age=31536000, immutable"),
            "expected immutable Cache-Control for {script_path}"
        );

        let content_type = res
            .header("content-type")
            .expect("missing Content-Type header for JS asset");
        assert!(
            content_type.contains("javascript"),
            "expected javascript MIME type for {script_path}, got {content_type}"
        );

        assert!(
            !res.body.is_empty(),
            "JS asset {script_path} must not be empty"
        );
        let embedded = EmbeddedFrontendAssets::get(script_path.trim_start_matches('/'))
            .unwrap_or_else(|| panic!("expected {script_path} in EmbeddedFrontendAssets"));
        assert_eq!(
            res.body.as_slice(),
            embedded.data.as_ref(),
            "served bytes for {script_path} must match EmbeddedFrontendAssets"
        );
        assert_no_external_cdns(res.body_utf8(), script_path);
    }

    for css_path in &extracted.stylesheet_hrefs {
        let res = send_raw_http_request(server.addr, "GET", css_path, &[]).await;
        assert_eq!(res.status, 200, "expected 200 OK for {css_path}");
        res.assert_security_headers();
        assert_eq!(
            res.header("cache-control"),
            Some("public, max-age=31536000, immutable"),
            "expected immutable Cache-Control for {css_path}"
        );

        let content_type = res
            .header("content-type")
            .expect("missing Content-Type header for CSS asset");
        assert!(
            content_type.contains("text/css"),
            "expected text/css MIME type for {css_path}, got {content_type}"
        );

        assert!(
            !res.body.is_empty(),
            "CSS asset {css_path} must not be empty"
        );
        let embedded = EmbeddedFrontendAssets::get(css_path.trim_start_matches('/'))
            .unwrap_or_else(|| panic!("expected {css_path} in EmbeddedFrontendAssets"));
        assert_eq!(
            res.body.as_slice(),
            embedded.data.as_ref(),
            "served bytes for {css_path} must match EmbeddedFrontendAssets"
        );
        assert_no_external_cdns(res.body_utf8(), css_path);
    }

    if let Some(embedded_favicon) = EmbeddedFrontendAssets::get("favicon.ico") {
        let favicon_res = send_raw_http_request(server.addr, "GET", "/favicon.ico", &[]).await;
        assert_eq!(favicon_res.status, 200);
        favicon_res.assert_security_headers();
        assert_eq!(
            favicon_res.header("cache-control"),
            Some("public, max-age=3600")
        );
        assert_eq!(favicon_res.body.as_slice(), embedded_favicon.data.as_ref());
    }

    server.shutdown().await;
}

#[tokio::test]
async fn distinguishes_missing_static_assets_404_from_api_401_and_authenticated_api_404() {
    let server = StaticAssetsTestServer::start().await;

    // 1. Missing static assets under /assets/ or with file extensions return 404 without auth.
    for missing_asset in [
        "/assets/missing.js",
        "/missing.css",
        "/assets/missing.css",
        "/assets/no-extension",
        "/nonexistent.txt",
    ] {
        let res = send_raw_http_request(server.addr, "GET", missing_asset, &[]).await;
        assert_eq!(
            res.status, 404,
            "expected 404 Not Found for missing static asset {missing_asset}"
        );
        res.assert_security_headers();
        assert_ne!(
            res.header("cache-control"),
            Some("no-cache"),
            "missing asset {missing_asset} must not return index.html"
        );
        let json = res.json();
        assert_eq!(json["error"], "not_found");
        assert_eq!(json["message"], "Asset not found");
    }

    // 2. Unknown / unauthenticated API routes return 401 Unauthorized with Cache-Control: no-store.
    for api_path in ["/api", "/api/", "/api/v1/unknown", "/api/v2/health"] {
        let unauth_res = send_raw_http_request(server.addr, "GET", api_path, &[]).await;
        assert_eq!(
            unauth_res.status, 401,
            "expected 401 Unauthorized without Bearer token for {api_path}"
        );
        unauth_res.assert_security_headers();
        assert_eq!(
            unauth_res.header("cache-control"),
            Some("no-store"),
            "expected Cache-Control: no-store on unauthenticated {api_path}"
        );
        assert_eq!(
            unauth_res.header("www-authenticate"),
            Some("Bearer"),
            "expected WWW-Authenticate: Bearer for {api_path}"
        );
        let unauth_json = unauth_res.json();
        assert_eq!(unauth_json["error"], "unauthorized");
    }

    // 3. Same unknown API routes with a valid Bearer token return 404 Not Found with Cache-Control: no-store.
    let auth_header = format!("Bearer {TEST_ADMIN_TOKEN}");
    for api_path in ["/api", "/api/", "/api/v1/unknown", "/api/v2/health"] {
        let auth_res = send_raw_http_request(
            server.addr,
            "GET",
            api_path,
            &[("Authorization", auth_header.as_str())],
        )
        .await;
        assert_eq!(
            auth_res.status, 404,
            "expected 404 Not Found with valid Bearer token for {api_path}"
        );
        auth_res.assert_security_headers();
        assert_eq!(
            auth_res.header("cache-control"),
            Some("no-store"),
            "expected Cache-Control: no-store on authenticated {api_path}"
        );
        let auth_json = auth_res.json();
        assert_eq!(auth_json["error"], "not_found");
        assert_eq!(auth_json["message"], "Endpoint not found");
    }

    server.shutdown().await;
}

#[tokio::test]
async fn static_route_traversal_null_bytes_and_backslashes_are_rejected_cleanly() {
    let server = StaticAssetsTestServer::start().await;
    let router = build_api_router(server.state.clone());

    let malicious_targets = [
        "/%2e%2e/etc/passwd",
        "/%2E%2E/%2e%2e/etc/shadow",
        "/..",
        "/assets/../index.html",
        "/assets/%2e%2e/index.html",
        "/%00",
        "/assets%5cindex.html",
        "/assets/.%2e/index.html",
        "/assets/%2e%2e%2findex.html",
        "/assets/app%00.js",
        "/assets%5Cindex.html",
    ];

    // 1. Exercise literal un-normalized request targets over real TCP socket.
    for target in malicious_targets {
        let tcp_res = send_raw_http_request(server.addr, "GET", target, &[]).await;
        assert!(
            matches!(tcp_res.status, 400 | 404),
            "expected 400 or 404 over TCP for {target}, got {}",
            tcp_res.status
        );
        tcp_res.assert_security_headers();
        let body_text = String::from_utf8_lossy(&tcp_res.body);
        assert!(
            !body_text.contains("Sentinel Guard") && !body_text.contains("<div id=\"app\">"),
            "malicious TCP path {target} must NEVER return index.html"
        );
    }

    // 2. Also verify raw un-normalized URIs directly through tower::ServiceExt::oneshot.
    for target in malicious_targets {
        let req = HttpRequest::builder()
            .uri(target)
            .body(Body::empty())
            .expect("build raw test HttpRequest");
        let oneshot_res = router
            .clone()
            .oneshot(req)
            .await
            .expect("router oneshot response");
        let status = oneshot_res.status();
        assert!(
            status == StatusCode::BAD_REQUEST || status == StatusCode::NOT_FOUND,
            "expected 400 or 404 via ServiceExt::oneshot for {target}, got {status}"
        );
        assert_axum_security_headers(oneshot_res.headers());

        let bytes = to_bytes(oneshot_res.into_body(), 1024 * 1024)
            .await
            .expect("read oneshot response bytes");
        let body_text = String::from_utf8_lossy(&bytes);
        assert!(
            !body_text.contains("Sentinel Guard") && !body_text.contains("<div id=\"app\">"),
            "malicious oneshot path {target} must NEVER return index.html"
        );
    }

    // 3. Literal unencoded backslash and NUL byte over raw TCP are rejected at HTTP/router boundary.
    for raw_invalid_target in ["/assets\\index.html", "/index\0.html"] {
        let raw_res = send_raw_http_request(server.addr, "GET", raw_invalid_target, &[]).await;
        assert!(
            matches!(raw_res.status, 400 | 404),
            "expected 400 or 404 for raw invalid target {raw_invalid_target:?}, got {}",
            raw_res.status
        );
        let body_text = String::from_utf8_lossy(&raw_res.body);
        assert!(
            !body_text.contains("Sentinel Guard") && !body_text.contains("<div id=\"app\">"),
            "raw invalid target {raw_invalid_target:?} must NEVER return index.html"
        );
    }

    server.shutdown().await;
}
