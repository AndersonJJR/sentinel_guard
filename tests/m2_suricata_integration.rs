#![cfg(unix)]
//! End-to-end integration tests for Milestone 2 (`feat/m2-suricata-correlator`).

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, Duration as ChronoDuration, SecondsFormat, Utc};
use sha2::{Digest, Sha256};
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{RwLock, watch};
use tokio::task::JoinHandle;

use sentinel_guard::application::inspect_file::InspectFileUseCase;
use sentinel_guard::application::update_config::{UpdateConfigRequest, UpdateConfigUseCase};
use sentinel_guard::domain::entities::{RuntimeConfig, SecurityVerdict};
use sentinel_guard::domain::errors::DomainError;
use sentinel_guard::domain::ports::{ConfigStore, FileScanner, QuarantineRepo};
use sentinel_guard::infrastructure::clamav_client::ClamAvScanner;
use sentinel_guard::infrastructure::fs_watcher::FsQuarantineMover;
use sentinel_guard::infrastructure::magic_bytes::{
    MagicBytesInspector, STREAM_CHUNK_SIZE, StreamingHasher,
};
use sentinel_guard::infrastructure::sqlite_repo::SqliteStore;
use sentinel_guard::infrastructure::suricata_tail::{
    DEFAULT_CORRELATION_WINDOW, DEFAULT_MAX_SEVERITY_THRESHOLD, MAX_EVE_LINE_BYTES,
    MAX_RECENT_ALERTS, SuricataCorrelator,
};

const CLAMD_TEST_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
struct CapturedInstream {
    command: Vec<u8>,
    chunk_sizes: Vec<usize>,
    saw_eof_marker: bool,
    payload: Vec<u8>,
}

#[derive(Debug, Default)]
struct MockClamdState {
    instreams: Vec<CapturedInstream>,
}

struct MockClamdServer {
    state: Arc<Mutex<MockClamdState>>,
    shutdown_tx: watch::Sender<bool>,
    handle: JoinHandle<()>,
}

impl MockClamdServer {
    fn start(socket_path: PathBuf) -> Self {
        let listener = UnixListener::bind(&socket_path).expect("bind mock clamd UnixListener");
        let state = Arc::new(Mutex::new(MockClamdState::default()));
        let state_clone = Arc::clone(&state);
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    changed = shutdown_rx.changed() => {
                        if changed.is_err() || *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    accepted = listener.accept() => {
                        let (mut stream, _) = match accepted {
                            Ok(conn) => conn,
                            Err(err) => panic!("mock clamd accept failed: {err}"),
                        };
                        let conn_state = Arc::clone(&state_clone);
                        tokio::spawn(async move {
                            handle_clamd_connection(&mut stream, &conn_state).await;
                        });
                    }
                }
            }
        });

        Self {
            state,
            shutdown_tx,
            handle,
        }
    }

    fn instreams(&self) -> Vec<CapturedInstream> {
        self.state
            .lock()
            .expect("mock clamd state mutex")
            .instreams
            .clone()
    }

    async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        tokio::time::timeout(CLAMD_TEST_TIMEOUT, self.handle)
            .await
            .expect("timed out waiting for mock clamd server shutdown")
            .expect("mock clamd server task panicked");
    }
}

async fn handle_clamd_connection(stream: &mut UnixStream, state: &Arc<Mutex<MockClamdState>>) {
    let command = read_null_terminated_command(stream)
        .await
        .expect("read clamd NUL-terminated command");

    match command.as_slice() {
        b"zPING\0" => {
            let _ = stream.write_all(b"PONG\0").await;
            let _ = stream.shutdown().await;
        }
        b"zINSTREAM\0" => {
            let (chunk_sizes, payload, saw_eof_marker) = read_instream_chunks(stream)
                .await
                .expect("read zINSTREAM chunks");
            {
                let mut guard = state.lock().expect("mock clamd state mutex");
                guard.instreams.push(CapturedInstream {
                    command,
                    chunk_sizes,
                    saw_eof_marker,
                    payload,
                });
            }
            let _ = stream.write_all(b"stream: OK\0").await;
            let _ = stream.shutdown().await;
        }
        other => panic!(
            "unexpected clamd command received: {:?}",
            String::from_utf8_lossy(other)
        ),
    }
}

async fn read_null_terminated_command(stream: &mut UnixStream) -> std::io::Result<Vec<u8>> {
    let mut cmd = Vec::with_capacity(16);
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "EOF before clamd command NUL terminator",
            ));
        }
        cmd.push(byte[0]);
        if byte[0] == 0 {
            return Ok(cmd);
        }
        assert!(cmd.len() <= 64, "clamd command exceeded 64 bytes");
    }
}

async fn read_instream_chunks(
    stream: &mut UnixStream,
) -> std::io::Result<(Vec<usize>, Vec<u8>, bool)> {
    let mut chunk_sizes = Vec::new();
    let mut payload = Vec::new();
    loop {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let chunk_len = u32::from_be_bytes(len_buf) as usize;
        if chunk_len == 0 {
            return Ok((chunk_sizes, payload, true));
        }
        assert!(
            chunk_len <= STREAM_CHUNK_SIZE,
            "chunk length {chunk_len} exceeded STREAM_CHUNK_SIZE ({STREAM_CHUNK_SIZE})"
        );
        chunk_sizes.push(chunk_len);
        let mut chunk = vec![0u8; chunk_len];
        stream.read_exact(&mut chunk).await?;
        payload.extend_from_slice(&chunk);
    }
}

fn utc_now_micros() -> DateTime<Utc> {
    DateTime::from_timestamp_micros(Utc::now().timestamp_micros()).expect("microsecond timestamp")
}

fn ts_rfc3339_offset(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(SecondsFormat::Micros, false)
}

fn ts_suricata_numeric(dt: DateTime<Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%S%.6f+0000").to_string()
}

fn format_eve_alert_line(
    ts: &str,
    src_ip: &str,
    dest_ip: &str,
    signature: &str,
    severity: u8,
) -> String {
    format!(
        "{{\"timestamp\":\"{ts}\",\"event_type\":\"alert\",\"src_ip\":\"{src_ip}\",\"dest_ip\":\"{dest_ip}\",\"alert\":{{\"signature\":\"{signature}\",\"severity\":{severity}}}}}"
    )
}

fn build_valid_pdf_1_7(total_len: usize, salt: u8) -> Vec<u8> {
    let header = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n";
    let footer = b"\n%%EOF\n";
    assert!(total_len >= header.len() + footer.len());
    let body_len = total_len - header.len() - footer.len();

    let mut payload = Vec::with_capacity(total_len);
    payload.extend_from_slice(header);
    payload.extend(
        (0..body_len).map(|i| (((i.wrapping_mul(41) ^ (i >> 7)) + usize::from(salt)) % 251) as u8),
    );
    payload.extend_from_slice(footer);
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

fn dir_entry_count(dir: &Path) -> usize {
    std::fs::read_dir(dir).expect("read_dir").count()
}

fn write_file_with_mode(path: &Path, bytes: &[u8], mode: u32) {
    std::fs::write(path, bytes).expect("write test file");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .expect("set file permissions");
}

fn dummy_runtime_config(eve_path: PathBuf) -> Arc<RwLock<RuntimeConfig>> {
    Arc::new(RwLock::new(RuntimeConfig {
        quarantine_dir: PathBuf::from("/var/sentinel/quarantine"),
        approved_dir: PathBuf::from("/var/sentinel/approved"),
        clamd_socket_path: PathBuf::from("/var/run/clamav/clamd.ctl"),
        suricata_eve_path: eve_path,
        updated_at: Utc::now(),
    }))
}

struct FullPipelineEnv {
    _root_guard: tempfile::TempDir,
    canonical_root: PathBuf,
    quarantine_dir: PathBuf,
    approved_dir: PathBuf,
    eve_path: PathBuf,
    store: Arc<SqliteStore>,
    runtime_config: Arc<RwLock<RuntimeConfig>>,
    suricata_correlator: Arc<SuricataCorrelator>,
    inspect_use_case: InspectFileUseCase,
    update_config_use_case: UpdateConfigUseCase,
    _watcher_rx: watch::Receiver<PathBuf>,
}

async fn setup_full_pipeline_env(
    socket_path: PathBuf,
    eve_file_name: &str,
    correlation_window: Duration,
    max_severity_threshold: u8,
) -> FullPipelineEnv {
    let root_guard = tempdir().expect("create tempdir");
    let canonical_root = std::fs::canonicalize(root_guard.path()).expect("canonical tempdir");
    let quarantine_dir = canonical_root.join("quarantine");
    let approved_dir = canonical_root.join("approved");
    std::fs::create_dir_all(&quarantine_dir).expect("create quarantine_dir");
    std::fs::create_dir_all(&approved_dir).expect("create approved_dir");

    let eve_path = canonical_root.join(eve_file_name);

    let store = Arc::new(
        SqliteStore::connect_and_migrate("sqlite::memory:")
            .await
            .expect("in-memory sqlite migration"),
    );

    let defaults = RuntimeConfig {
        quarantine_dir: quarantine_dir.clone(),
        approved_dir: approved_dir.clone(),
        clamd_socket_path: socket_path,
        suricata_eve_path: eve_path.clone(),
        updated_at: Utc::now(),
    };
    let seeded = store
        .load_or_seed(&defaults)
        .await
        .expect("seed initial runtime config");

    let runtime_config = Arc::new(RwLock::new(seeded.clone()));
    let (watcher_tx, watcher_rx) = watch::channel(seeded.quarantine_dir);

    let hasher = Arc::new(StreamingHasher::new());
    let magic_inspector = Arc::new(MagicBytesInspector::new());
    let clamav_scanner = Arc::new(ClamAvScanner::with_timeout(
        Arc::clone(&runtime_config),
        CLAMD_TEST_TIMEOUT,
    ));
    let suricata_correlator = Arc::new(SuricataCorrelator::with_policy(
        Arc::clone(&runtime_config),
        correlation_window,
        max_severity_threshold,
        Vec::new(),
    ));

    let scanners: Vec<Arc<dyn FileScanner>> = vec![
        Arc::clone(&magic_inspector) as Arc<dyn FileScanner>,
        Arc::clone(&clamav_scanner) as Arc<dyn FileScanner>,
        Arc::clone(&suricata_correlator) as Arc<dyn FileScanner>,
    ];
    let quarantine_mover = Arc::new(FsQuarantineMover::new());

    let inspect_use_case = InspectFileUseCase::new(
        hasher,
        magic_inspector,
        scanners,
        quarantine_mover,
        store.clone(),
        Arc::clone(&runtime_config),
    );
    let update_config_use_case =
        UpdateConfigUseCase::new(store.clone(), Arc::clone(&runtime_config), watcher_tx);

    FullPipelineEnv {
        _root_guard: root_guard,
        canonical_root,
        quarantine_dir,
        approved_dir,
        eve_path,
        store,
        runtime_config,
        suricata_correlator,
        inspect_use_case,
        update_config_use_case,
        _watcher_rx: watcher_rx,
    }
}

#[tokio::test]
async fn eve_mixed_stream_parses_rfc3339_and_numeric_tz_skips_low_severity_and_survives_oversized_90kb_line()
 {
    let dir = tempdir().expect("create tempdir");
    let canonical_dir = std::fs::canonicalize(dir.path()).expect("canonical tempdir");
    let eve_path = canonical_dir.join("eve.json");
    let now = utc_now_micros();

    let ts_sev3_rfc3339 = now - ChronoDuration::seconds(30);
    let ts_sev2_rfc3339 = now - ChronoDuration::seconds(20);
    let ts_sev1_numeric = now - ChronoDuration::seconds(10);

    let ts_sev3_str = ts_rfc3339_offset(ts_sev3_rfc3339);
    let ts_sev2_str = ts_rfc3339_offset(ts_sev2_rfc3339);
    let ts_sev1_str = ts_suricata_numeric(ts_sev1_numeric);
    assert!(
        ts_sev2_str.ends_with("+00:00"),
        "expected RFC3339 +00:00 timestamp, got {ts_sev2_str}"
    );
    assert!(
        ts_sev1_str.ends_with("+0000"),
        "expected Suricata +0000 timestamp, got {ts_sev1_str}"
    );

    // Build a > 90 KB oversized eve.json line (> 65,536 bytes MAX_EVE_LINE_BYTES) to test DoS resilience.
    let oversized_padding = "X".repeat(90 * 1024);
    let oversized_alert_line = format_eve_alert_line(
        &ts_sev1_str,
        "198.51.100.250",
        "10.0.0.99",
        &oversized_padding,
        1,
    );
    assert!(oversized_alert_line.len() > MAX_EVE_LINE_BYTES + 24 * 1024);

    let mut raw_stream = Vec::new();
    raw_stream.extend_from_slice(
        format!(
            "{{\"timestamp\":\"{ts_sev2_str}\",\"event_type\":\"dns\",\"src_ip\":\"10.0.0.5\",\"dest_ip\":\"8.8.8.8\",\"dns\":{{\"rrname\":\"updates.example.com\"}}}}\n"
        )
        .as_bytes(),
    );
    raw_stream.extend_from_slice(b"{not-valid-json\n");
    raw_stream.extend_from_slice(b"\xff\xfe\xfd malformed non-utf8 bytes\n");
    raw_stream.extend_from_slice(
        format!(
            "{{\"timestamp\":\"{ts_sev1_str}\",\"event_type\":\"flow\",\"src_ip\":\"10.0.0.5\",\"dest_ip\":\"1.1.1.1\"}}\n"
        )
        .as_bytes(),
    );
    raw_stream.extend_from_slice(
        format!(
            "{{\"timestamp\":\"{ts_sev2_str}\",\"event_type\":\"stats\",\"stats\":{{\"uptime\":4200}}}}\n"
        )
        .as_bytes(),
    );
    raw_stream.extend_from_slice(oversized_alert_line.as_bytes());
    raw_stream.push(b'\n');

    // Severity 3 alert (RFC3339 +00:00)
    raw_stream.extend_from_slice(
        format_eve_alert_line(
            &ts_sev3_str,
            "192.0.2.30",
            "10.0.0.10",
            "ET POLICY Low Severity Informational",
            3,
        )
        .as_bytes(),
    );
    raw_stream.push(b'\n');

    // Severity 2 alert (RFC3339 +00:00)
    raw_stream.extend_from_slice(
        format_eve_alert_line(
            &ts_sev2_str,
            "203.0.113.20",
            "10.0.0.10",
            "ET MALWARE Medium Suspicious Payload",
            2,
        )
        .as_bytes(),
    );
    raw_stream.push(b'\n');

    // Severity 1 alert (Suricata numeric +0000)
    raw_stream.extend_from_slice(
        format_eve_alert_line(
            &ts_sev1_str,
            "198.51.100.10",
            "10.0.0.10",
            "ET TROJAN High Severity Beacon",
            1,
        )
        .as_bytes(),
    );
    raw_stream.push(b'\n');

    std::fs::write(&eve_path, &raw_stream).expect("write mixed eve.json");

    // 1. With max_severity_threshold = 3, verify all 3 severities and both timestamp formats parse accurately.
    let permissive_correlator = SuricataCorrelator::with_policy(
        dummy_runtime_config(eve_path.clone()),
        DEFAULT_CORRELATION_WINDOW,
        3,
        Vec::new(),
    );
    let all_parsed = permissive_correlator
        .active_alerts()
        .await
        .expect("parse all 1..=3 alerts");
    assert_eq!(
        all_parsed.len(),
        3,
        "only valid 1..=3 alerts may survive (dns/flow/stats/malformed/90KB oversized skipped)"
    );
    assert_eq!(all_parsed[0].severity, 3);
    assert_eq!(all_parsed[0].timestamp, ts_sev3_rfc3339);
    assert_eq!(all_parsed[0].src_ip, "192.0.2.30");
    assert_eq!(
        all_parsed[0].signature,
        "ET POLICY Low Severity Informational"
    );

    assert_eq!(all_parsed[1].severity, 2);
    assert_eq!(all_parsed[1].timestamp, ts_sev2_rfc3339);
    assert_eq!(all_parsed[1].src_ip, "203.0.113.20");
    assert_eq!(
        all_parsed[1].signature,
        "ET MALWARE Medium Suspicious Payload"
    );

    assert_eq!(all_parsed[2].severity, 1);
    assert_eq!(all_parsed[2].timestamp, ts_sev1_numeric);
    assert_eq!(all_parsed[2].src_ip, "198.51.100.10");
    assert_eq!(all_parsed[2].signature, "ET TROJAN High Severity Beacon");

    // 2. With max_severity_threshold = 2, severity 3 must be filtered out while 1..=2 remain.
    let strict_correlator = SuricataCorrelator::with_policy(
        dummy_runtime_config(eve_path.clone()),
        DEFAULT_CORRELATION_WINDOW,
        2,
        Vec::new(),
    );
    let filtered = strict_correlator
        .active_alerts()
        .await
        .expect("filter alerts by max_severity_threshold = 2");
    assert_eq!(filtered.len(), 2);
    assert!(filtered.iter().all(|alert| alert.severity <= 2));
    assert_eq!(filtered[0].severity, 2);
    assert_eq!(filtered[1].severity, 1);

    // Re-syncing must stay idempotent (no duplicate parsing or re-reading the discarded 90 KB line).
    let resynced = strict_correlator
        .active_alerts()
        .await
        .expect("idempotent resync");
    assert_eq!(resynced, filtered);

    let dummy_pdf = sentinel_guard::domain::entities::FileArtifact {
        path: canonical_dir.join("probe.pdf"),
        sanitized_name: "probe.pdf".to_string(),
        extension: Some("pdf".to_string()),
        size_bytes: 512,
        sha256_hash: "b".repeat(64),
        detected_mime: Some("application/pdf".to_string()),
    };
    assert_eq!(
        strict_correlator
            .scan(&dummy_pdf)
            .await
            .expect("scan selects highest-severity alert"),
        SecurityVerdict::SuspiciousNetworkCorrelation {
            alert_signature: "ET TROJAN High Severity Beacon".to_string(),
            src_ip: "198.51.100.10".to_string(),
        }
    );

    // 3. Verify bounded ring-buffer memory under > MAX_RECENT_ALERTS flood + another 90 KB line.
    let flood_eve_path = canonical_dir.join("flood_eve.json");
    {
        let mut f = std::fs::File::create(&flood_eve_path).expect("create flood_eve.json");
        writeln!(f, "{oversized_alert_line}").expect("write leading 90 KB line");
        for idx in 0..(MAX_RECENT_ALERTS + 120) {
            let ts = ts_suricata_numeric(now + ChronoDuration::milliseconds(idx as i64));
            writeln!(
                f,
                "{}",
                format_eve_alert_line(
                    &ts,
                    "10.40.0.5",
                    "10.40.0.10",
                    &format!("Flood Alert #{idx}"),
                    1,
                )
            )
            .expect("write flood alert");
        }
    }

    let flood_correlator = SuricataCorrelator::with_policy(
        dummy_runtime_config(flood_eve_path),
        DEFAULT_CORRELATION_WINDOW,
        2,
        Vec::new(),
    );
    let bounded = flood_correlator
        .active_alerts()
        .await
        .expect("load flood alerts");
    assert_eq!(
        bounded.len(),
        MAX_RECENT_ALERTS,
        "in-memory alert queue must remain strictly bounded at MAX_RECENT_ALERTS"
    );
    assert_eq!(
        bounded.first().map(|a| a.signature.as_str()),
        Some("Flood Alert #120")
    );
    assert_eq!(
        bounded.last().map(|a| a.signature.as_str()),
        Some("Flood Alert #1143")
    );
}

#[tokio::test]
async fn alerts_expire_after_correlation_window_and_offset_resets_on_truncation_and_rotation() {
    let dir = tempdir().expect("create tempdir");
    let canonical_dir = std::fs::canonicalize(dir.path()).expect("canonical tempdir");
    let eve_path = canonical_dir.join("eve.json");
    let rotated_path = canonical_dir.join("eve.json.1");

    let artifact = sentinel_guard::domain::entities::FileArtifact {
        path: canonical_dir.join("sample.pdf"),
        sanitized_name: "sample.pdf".to_string(),
        extension: Some("pdf".to_string()),
        size_bytes: 256,
        sha256_hash: "a".repeat(64),
        detected_mime: Some("application/pdf".to_string()),
    };

    // 1. Pre-aged alert beyond correlation_window is ignored -> Clean.
    let expiry_eve_path = canonical_dir.join("expiry_eve.json");
    let short_window = Duration::from_millis(250);
    let old_ts = ts_suricata_numeric(Utc::now() - ChronoDuration::seconds(30));
    std::fs::write(
        &expiry_eve_path,
        format!(
            "{}\n",
            format_eve_alert_line(
                &old_ts,
                "198.51.100.1",
                "10.0.0.1",
                "Already Expired Alert",
                1
            )
        ),
    )
    .expect("write pre-aged alert");

    let expiry_correlator = SuricataCorrelator::with_policy(
        dummy_runtime_config(expiry_eve_path.clone()),
        short_window,
        DEFAULT_MAX_SEVERITY_THRESHOLD,
        Vec::new(),
    );
    assert!(
        expiry_correlator
            .active_alerts()
            .await
            .expect("sync expired")
            .is_empty()
    );
    assert_eq!(
        expiry_correlator
            .scan(&artifact)
            .await
            .expect("scan expired"),
        SecurityVerdict::Clean
    );

    // 2. Fresh alert inside short_window is active, then expires naturally over time -> Clean.
    let fresh_ts = ts_suricata_numeric(Utc::now());
    {
        let mut f = OpenOptions::new()
            .append(true)
            .open(&expiry_eve_path)
            .expect("open expiry_eve for append");
        writeln!(
            f,
            "{}",
            format_eve_alert_line(
                &fresh_ts,
                "198.51.100.2",
                "10.0.0.1",
                "Short Lived Alert",
                1
            )
        )
        .expect("append fresh alert");
    }
    assert_eq!(
        expiry_correlator
            .scan(&artifact)
            .await
            .expect("scan active before window expiry"),
        SecurityVerdict::SuspiciousNetworkCorrelation {
            alert_signature: "Short Lived Alert".to_string(),
            src_ip: "198.51.100.2".to_string(),
        }
    );

    tokio::time::sleep(Duration::from_millis(320)).await;
    assert!(
        expiry_correlator
            .active_alerts()
            .await
            .expect("sync after window expiry")
            .is_empty(),
        "cached alert must expire once correlation_window elapses"
    );
    assert_eq!(
        expiry_correlator
            .scan(&artifact)
            .await
            .expect("scan after window expiry"),
        SecurityVerdict::Clean
    );

    // 3. Log truncation (shrinking file size) and log rotation (new inode) reset offset cleanly.
    let now = utc_now_micros();
    {
        let mut f = std::fs::File::create(&eve_path).expect("create eve.json");
        for idx in 0..4 {
            writeln!(
                f,
                "{{\"timestamp\":\"{}\",\"event_type\":\"flow\",\"src_ip\":\"10.0.0.{idx}\",\"dest_ip\":\"10.0.0.99\",\"pad\":\"{}\"}}",
                ts_suricata_numeric(now),
                "p".repeat(64)
            )
            .expect("write initial flow padding");
        }
        writeln!(
            f,
            "{}",
            format_eve_alert_line(
                &ts_suricata_numeric(now),
                "203.0.113.10",
                "10.0.0.1",
                "Initial Pre-Truncation Alert",
                2,
            )
        )
        .expect("write initial alert");
    }

    let tail_correlator = SuricataCorrelator::with_policy(
        dummy_runtime_config(eve_path.clone()),
        DEFAULT_CORRELATION_WINDOW,
        DEFAULT_MAX_SEVERITY_THRESHOLD,
        Vec::new(),
    );
    let initial_alerts = tail_correlator
        .active_alerts()
        .await
        .expect("initial tail sync");
    assert_eq!(initial_alerts.len(), 1);
    assert_eq!(initial_alerts[0].signature, "Initial Pre-Truncation Alert");

    // Truncate eve.json to a smaller size (< previous offset) and write a fresh alert.
    let truncated_ts = ts_suricata_numeric(Utc::now());
    {
        let mut f = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&eve_path)
            .expect("truncate eve.json");
        writeln!(
            f,
            "{}",
            format_eve_alert_line(
                &truncated_ts,
                "203.0.113.11",
                "10.0.0.1",
                "Post-Truncation Alert",
                1,
            )
        )
        .expect("write post-truncation alert");
    }
    let after_truncate = tail_correlator
        .active_alerts()
        .await
        .expect("sync after truncation");
    assert!(
        after_truncate
            .iter()
            .any(|a| a.signature == "Post-Truncation Alert"),
        "truncation must reset offset to 0 and read new alert"
    );

    // Append another alert after truncation to confirm offset tracked the new file length accurately.
    {
        let mut f = OpenOptions::new()
            .append(true)
            .open(&eve_path)
            .expect("append after truncation");
        writeln!(
            f,
            "{}",
            format_eve_alert_line(
                &ts_suricata_numeric(Utc::now()),
                "203.0.113.12",
                "10.0.0.1",
                "Post-Truncation Followup Alert",
                1,
            )
        )
        .expect("write followup after truncation");
    }
    let after_trunc_append = tail_correlator
        .active_alerts()
        .await
        .expect("sync followup after truncation");
    assert!(
        after_trunc_append
            .iter()
            .any(|a| a.signature == "Post-Truncation Followup Alert")
    );

    // Rotate eve.json -> rename old file and create a NEW inode that is LARGER than previous offset.
    std::fs::rename(&eve_path, &rotated_path).expect("rename eve.json to rotated");
    {
        let mut f = std::fs::File::create(&eve_path).expect("create rotated eve.json");
        for idx in 0..10 {
            writeln!(
                f,
                "{{\"timestamp\":\"{}\",\"event_type\":\"dns\",\"src_ip\":\"10.1.0.{idx}\",\"dest_ip\":\"8.8.8.8\",\"rrname\":\"rot{idx}.example.net\"}}",
                ts_suricata_numeric(Utc::now())
            )
            .expect("write dns padding to rotated file");
        }
        writeln!(
            f,
            "{}",
            format_eve_alert_line(
                &ts_suricata_numeric(Utc::now()),
                "203.0.113.99",
                "10.0.0.1",
                "Post-Rotation New Inode Alert",
                1,
            )
        )
        .expect("write post-rotation alert");
    }

    let after_rotation = tail_correlator
        .active_alerts()
        .await
        .expect("sync after rotation");
    assert!(
        after_rotation
            .iter()
            .any(|a| a.signature == "Post-Rotation New Inode Alert"),
        "log rotation to a new inode (even larger than prior offset) must reset offset and detect new alerts"
    );

    // Append another line on the new inode to verify continuous tailing post-rotation.
    {
        let mut f = OpenOptions::new()
            .append(true)
            .open(&eve_path)
            .expect("append on rotated eve.json");
        writeln!(
            f,
            "{}",
            format_eve_alert_line(
                &ts_suricata_numeric(Utc::now()),
                "203.0.113.100",
                "10.0.0.1",
                "Post-Rotation Appended Alert",
                1,
            )
        )
        .expect("write post-rotation appended alert");
    }
    let after_rot_append = tail_correlator
        .active_alerts()
        .await
        .expect("sync append after rotation");
    assert!(
        after_rot_append
            .iter()
            .any(|a| a.signature == "Post-Rotation Appended Alert")
    );
}

#[tokio::test]
async fn full_three_scanner_pipeline_isolates_correlated_pdf_and_approves_expired_or_low_severity_pdf()
 {
    let socket_dir = tempdir().expect("create socket tempdir");
    let canonical_socket_dir =
        std::fs::canonicalize(socket_dir.path()).expect("canonical socket dir");
    let socket_path = canonical_socket_dir.join("clamd.ctl");
    let mock_clamd = MockClamdServer::start(socket_path.clone());

    // Part A: Active Suricata alert (severity <= 2) triggers SuspiciousNetworkCorrelation after MagicBytes + ClamAV pass.
    let env_alert = setup_full_pipeline_env(
        socket_path.clone(),
        "eve_active.json",
        DEFAULT_CORRELATION_WINDOW,
        DEFAULT_MAX_SEVERITY_THRESHOLD,
    )
    .await;

    let active_ts = ts_suricata_numeric(Utc::now());
    std::fs::write(
        &env_alert.eve_path,
        format!(
            "{}\n",
            format_eve_alert_line(
                &active_ts,
                "198.51.100.77",
                "10.0.0.25",
                "ET TROJAN Active C2 Callback",
                2,
            )
        ),
    )
    .expect("write active alert to eve_active.json");

    let infected_ctx_pdf_len = STREAM_CHUNK_SIZE + 2_048;
    let pdf_one_bytes = build_valid_pdf_1_7(infected_ctx_pdf_len, 11);
    let pdf_one_sha = sha256_hex(&pdf_one_bytes);
    let pdf_one_src = env_alert.quarantine_dir.join("relatorio_suspeito.pdf");
    write_file_with_mode(&pdf_one_src, &pdf_one_bytes, 0o755);

    let report_isolated = env_alert
        .inspect_use_case
        .execute(&pdf_one_src)
        .await
        .expect("3-scanner pipeline should isolate correlated PDF");

    let expected_corr_verdict = SecurityVerdict::SuspiciousNetworkCorrelation {
        alert_signature: "ET TROJAN Active C2 Callback".to_string(),
        src_ip: "198.51.100.77".to_string(),
    };
    let isolated_dir = env_alert.quarantine_dir.join(".isolated");
    let isolated_pdf_path = isolated_dir.join("relatorio_suspeito.pdf");

    assert!(
        !pdf_one_src.exists(),
        "source file must leave quarantine root"
    );
    assert_eq!(
        dir_entry_count(&env_alert.approved_dir),
        0,
        "correlated file must NEVER move to approved_dir"
    );
    assert!(isolated_dir.is_dir());
    assert_eq!(mode_bits(&isolated_dir), 0o700);
    assert!(isolated_pdf_path.exists());
    assert_eq!(
        mode_bits(&isolated_pdf_path),
        0o600,
        "isolated PDF must have 0o600 permissions"
    );
    assert_eq!(
        mode_bits(&isolated_pdf_path) & 0o111,
        0,
        "isolated PDF must have no execute bits"
    );
    assert_eq!(
        std::fs::read(&isolated_pdf_path).expect("read isolated PDF"),
        pdf_one_bytes
    );

    assert!(report_isolated.id.is_some());
    assert_eq!(report_isolated.verdict, expected_corr_verdict);
    assert_eq!(
        report_isolated.artifact.detected_mime.as_deref(),
        Some("application/pdf")
    );
    assert_eq!(report_isolated.artifact.sha256_hash, pdf_one_sha);
    assert_eq!(
        report_isolated.destination_path.as_ref(),
        Some(&isolated_pdf_path)
    );

    let persisted_alert = env_alert
        .store
        .list_recent_reports(10)
        .await
        .expect("list persisted reports for alert run");
    assert_eq!(persisted_alert.len(), 1);
    assert_eq!(persisted_alert[0].verdict, expected_corr_verdict);
    assert_eq!(
        persisted_alert[0].destination_path.as_ref(),
        Some(&isolated_pdf_path)
    );

    // Confirm ClamAvScanner actually streamed the entire PDF over zINSTREAM before Suricata flagged it.
    let instreams_after_a = mock_clamd.instreams();
    assert_eq!(instreams_after_a.len(), 1);
    assert_eq!(instreams_after_a[0].command, b"zINSTREAM\0");
    assert!(instreams_after_a[0].saw_eof_marker);
    assert!(instreams_after_a[0].chunk_sizes.len() > 1);
    assert_eq!(
        instreams_after_a[0].chunk_sizes.iter().sum::<usize>(),
        pdf_one_bytes.len()
    );
    assert_eq!(instreams_after_a[0].payload, pdf_one_bytes);

    // Part B: Converse — eve.json with only expired + severity 3 alerts allows valid PDF to reach approved/.
    let env_clean = setup_full_pipeline_env(
        socket_path,
        "eve_benign.json",
        Duration::from_secs(60),
        DEFAULT_MAX_SEVERITY_THRESHOLD,
    )
    .await;

    let now = utc_now_micros();
    let expired_ts = ts_rfc3339_offset(now - ChronoDuration::seconds(300));
    let low_sev_ts = ts_suricata_numeric(now - ChronoDuration::seconds(5));
    let mut benign_eve = String::new();
    benign_eve.push_str(&format_eve_alert_line(
        &expired_ts,
        "198.51.100.88",
        "10.0.0.25",
        "ET EXPLOIT Expired Historic Alert",
        1,
    ));
    benign_eve.push('\n');
    benign_eve.push_str(&format_eve_alert_line(
        &low_sev_ts,
        "198.51.100.89",
        "10.0.0.25",
        "ET INFO Low Severity Three",
        3,
    ));
    benign_eve.push('\n');
    std::fs::write(&env_clean.eve_path, benign_eve).expect("write eve_benign.json");

    let pdf_two_bytes = build_valid_pdf_1_7(STREAM_CHUNK_SIZE + 4_096, 29);
    let pdf_two_sha = sha256_hex(&pdf_two_bytes);
    let pdf_two_src = env_clean.quarantine_dir.join("contrato_aprovado.pdf");
    write_file_with_mode(&pdf_two_src, &pdf_two_bytes, 0o755);

    let report_approved = env_clean
        .inspect_use_case
        .execute(&pdf_two_src)
        .await
        .expect(
            "3-scanner pipeline should approve valid PDF when no active severity <= 2 alerts exist",
        );

    let approved_pdf_path = env_clean.approved_dir.join("contrato_aprovado.pdf");
    assert!(!pdf_two_src.exists());
    assert!(approved_pdf_path.exists());
    assert!(!env_clean.quarantine_dir.join(".isolated").exists());
    assert_eq!(mode_bits(&approved_pdf_path), 0o640);
    assert_eq!(
        mode_bits(&approved_pdf_path) & 0o111,
        0,
        "approved PDF must strip execute bits"
    );
    assert_eq!(
        std::fs::read(&approved_pdf_path).expect("read approved PDF"),
        pdf_two_bytes
    );

    assert_eq!(report_approved.verdict, SecurityVerdict::Clean);
    assert_eq!(
        report_approved.artifact.detected_mime.as_deref(),
        Some("application/pdf")
    );
    assert_eq!(report_approved.artifact.sha256_hash, pdf_two_sha);
    assert_eq!(
        report_approved.destination_path.as_ref(),
        Some(&approved_pdf_path)
    );

    let persisted_clean = env_clean
        .store
        .list_recent_reports(10)
        .await
        .expect("list persisted reports for clean run");
    assert_eq!(persisted_clean.len(), 1);
    assert_eq!(persisted_clean[0].verdict, SecurityVerdict::Clean);
    assert_eq!(persisted_clean[0].artifact.sha256_hash, pdf_two_sha);
    assert_eq!(
        persisted_clean[0].destination_path.as_ref(),
        Some(&approved_pdf_path)
    );

    let instreams_after_b = mock_clamd.instreams();
    assert_eq!(instreams_after_b.len(), 2);
    assert!(instreams_after_b[1].chunk_sizes.len() > 1);
    assert_eq!(
        instreams_after_b[1].chunk_sizes.iter().sum::<usize>(),
        pdf_two_bytes.len()
    );
    assert_eq!(instreams_after_b[1].payload, pdf_two_bytes);

    mock_clamd.shutdown().await;
}

#[tokio::test]
async fn eve_path_security_rejections_and_dynamic_reload_via_update_config() {
    let socket_dir = tempdir().expect("create socket tempdir");
    let canonical_socket_dir =
        std::fs::canonicalize(socket_dir.path()).expect("canonical socket dir");
    let socket_path = canonical_socket_dir.join("clamd.ctl");
    let mock_clamd = MockClamdServer::start(socket_path.clone());

    let env = setup_full_pipeline_env(
        socket_path,
        "eve_one.json",
        DEFAULT_CORRELATION_WINDOW,
        DEFAULT_MAX_SEVERITY_THRESHOLD,
    )
    .await;

    let eve_one = env.eve_path.clone();
    std::fs::write(
        &eve_one,
        format!(
            "{}\n",
            format_eve_alert_line(
                &ts_suricata_numeric(Utc::now()),
                "203.0.113.50",
                "10.0.0.8",
                "ET TROJAN Initial Eve One Alert",
                1,
            )
        ),
    )
    .expect("write eve_one.json");

    let pending_bytes = build_valid_pdf_1_7(4_096, 3);
    let pending_pdf = env.quarantine_dir.join("pendente_validacao.pdf");
    write_file_with_mode(&pending_pdf, &pending_bytes, 0o640);

    // 1. Security & validation parity rejections across UpdateConfigUseCase, SuricataCorrelator, and InspectFileUseCase.
    let initial_snapshot = env.runtime_config.read().await.clone();
    let existing_eve_dir = env.canonical_root.join("eve_dir");
    std::fs::create_dir_all(&existing_eve_dir).expect("create existing_eve_dir");
    let wrong_type_sock = canonical_socket_dir.join("wrong_type_eve.sock");
    let _wrong_type_listener =
        UnixListener::bind(&wrong_type_sock).expect("bind unix socket for wrong-type eve check");

    // Existing regular file for clamd_socket_path must fail with InvalidPath without mutating config.
    let regular_file_clamd_err = env
        .update_config_use_case
        .execute(UpdateConfigRequest {
            quarantine_dir: env.quarantine_dir.clone(),
            approved_dir: env.approved_dir.clone(),
            clamd_socket_path: Some(eve_one.clone()),
            suricata_eve_path: None,
        })
        .await
        .expect_err("existing regular file for clamd_socket_path must fail in UpdateConfigUseCase");
    assert!(
        matches!(regular_file_clamd_err, DomainError::InvalidPath(_)),
        "expected InvalidPath for regular file clamd_socket_path, got {regular_file_clamd_err:?}"
    );
    assert_eq!(
        *env.runtime_config.read().await,
        initial_snapshot,
        "rejected clamd_socket_path (regular file) must not mutate RuntimeConfig"
    );
    assert_eq!(
        env.store
            .load_or_seed(&initial_snapshot)
            .await
            .expect("read persisted config after clamd regular file rejection"),
        initial_snapshot,
        "rejected clamd_socket_path (regular file) must not mutate SQLite system_config"
    );

    for (label, invalid_eve) in [
        ("existing_directory", existing_eve_dir),
        ("existing_unix_socket", wrong_type_sock),
        (
            "trailing_slash",
            PathBuf::from(format!("{}/", eve_one.display())),
        ),
        ("trailing_dot", eve_one.join(".")),
        ("control_newline", env.canonical_root.join("bad\neve.json")),
        ("control_escape", env.canonical_root.join("bad\x1beve.json")),
    ] {
        let cfg_err = env
            .update_config_use_case
            .execute(UpdateConfigRequest {
                quarantine_dir: env.quarantine_dir.clone(),
                approved_dir: env.approved_dir.clone(),
                clamd_socket_path: None,
                suricata_eve_path: Some(invalid_eve.clone()),
            })
            .await
            .expect_err("invalid suricata_eve_path must fail in UpdateConfigUseCase");
        assert!(
            matches!(cfg_err, DomainError::InvalidPath(_)),
            "expected InvalidPath in UpdateConfigUseCase for {label}, got {cfg_err:?}"
        );
        assert_eq!(
            *env.runtime_config.read().await,
            initial_snapshot,
            "rejected UpdateConfigUseCase ({label}) must not mutate RuntimeConfig"
        );
        assert_eq!(
            env.store
                .load_or_seed(&initial_snapshot)
                .await
                .expect("read persisted config after rejection"),
            initial_snapshot,
            "rejected UpdateConfigUseCase ({label}) must not mutate SQLite system_config"
        );

        env.runtime_config.write().await.suricata_eve_path = invalid_eve;
        let corr_err = env
            .suricata_correlator
            .sync_alerts()
            .await
            .expect_err("invalid eve path must also fail in SuricataCorrelator");
        assert!(
            matches!(corr_err, DomainError::InvalidPath(_)),
            "expected InvalidPath in SuricataCorrelator for {label}, got {corr_err:?}"
        );
        let pipe_err = env
            .inspect_use_case
            .execute(&pending_pdf)
            .await
            .expect_err("invalid eve path must abort pipeline");
        assert!(
            matches!(pipe_err, DomainError::InvalidPath(_)),
            "expected InvalidPath in pipeline for {label}, got {pipe_err:?}"
        );
        *env.runtime_config.write().await = initial_snapshot.clone();
    }

    let symlink_eve = env.canonical_root.join("sym_eve.json");
    std::os::unix::fs::symlink(&eve_one, &symlink_eve).expect("symlink eve.json");

    let dangling_symlink_eve = env.canonical_root.join("dangling_eve.json");
    std::os::unix::fs::symlink(
        env.canonical_root.join("absent_eve.json"),
        &dangling_symlink_eve,
    )
    .expect("dangling symlink eve.json");

    let sym_to_etc_passwd = env.canonical_root.join("sym_passwd.json");
    std::os::unix::fs::symlink("/etc/passwd", &sym_to_etc_passwd).expect("symlink /etc/passwd");

    for sym_path in [&symlink_eve, &dangling_symlink_eve, &sym_to_etc_passwd] {
        env.runtime_config.write().await.suricata_eve_path = sym_path.clone();

        let corr_err = env
            .suricata_correlator
            .sync_alerts()
            .await
            .expect_err("symlinked eve.json must fail in SuricataCorrelator");
        assert!(
            matches!(corr_err, DomainError::PathTraversalAttempt(_)),
            "expected PathTraversalAttempt for symlink {}, got {corr_err:?}",
            sym_path.display()
        );

        let pipe_err = env
            .inspect_use_case
            .execute(&pending_pdf)
            .await
            .expect_err("symlinked eve.json must abort pipeline without disposition");
        assert!(
            matches!(pipe_err, DomainError::PathTraversalAttempt(_)),
            "expected PathTraversalAttempt in pipeline for {}, got {pipe_err:?}",
            sym_path.display()
        );
    }

    // UpdateConfigUseCase must also reject symlink pointing into /etc/passwd as ForbiddenSystemDirectory.
    let cfg_sym_etc_err = env
        .update_config_use_case
        .execute(UpdateConfigRequest {
            quarantine_dir: env.quarantine_dir.clone(),
            approved_dir: env.approved_dir.clone(),
            clamd_socket_path: None,
            suricata_eve_path: Some(sym_to_etc_passwd),
        })
        .await
        .expect_err("symlink into /etc/passwd must fail in UpdateConfigUseCase");
    assert!(matches!(
        cfg_sym_etc_err,
        DomainError::ForbiddenSystemDirectory(_)
    ));

    // Relative path -> InvalidPath in both UpdateConfigUseCase and SuricataCorrelator/pipeline.
    let relative_eve = PathBuf::from("relative/eve.json");
    let cfg_rel_err = env
        .update_config_use_case
        .execute(UpdateConfigRequest {
            quarantine_dir: env.quarantine_dir.clone(),
            approved_dir: env.approved_dir.clone(),
            clamd_socket_path: None,
            suricata_eve_path: Some(relative_eve.clone()),
        })
        .await
        .expect_err("relative eve.json must fail in UpdateConfigUseCase");
    assert!(matches!(cfg_rel_err, DomainError::InvalidPath(_)));

    env.runtime_config.write().await.suricata_eve_path = relative_eve;
    assert!(matches!(
        env.suricata_correlator.sync_alerts().await,
        Err(DomainError::InvalidPath(_))
    ));
    assert!(matches!(
        env.inspect_use_case.execute(&pending_pdf).await,
        Err(DomainError::InvalidPath(_))
    ));

    // Parent '..' traversal -> PathTraversalAttempt in both UpdateConfigUseCase and SuricataCorrelator/pipeline.
    for traversal_eve in [
        env.canonical_root.join("../eve.json"),
        env.canonical_root.join("sub/../eve.json"),
    ] {
        let cfg_trav_err = env
            .update_config_use_case
            .execute(UpdateConfigRequest {
                quarantine_dir: env.quarantine_dir.clone(),
                approved_dir: env.approved_dir.clone(),
                clamd_socket_path: None,
                suricata_eve_path: Some(traversal_eve.clone()),
            })
            .await
            .expect_err(".. traversal in suricata_eve_path must fail");
        assert!(matches!(cfg_trav_err, DomainError::PathTraversalAttempt(_)));

        env.runtime_config.write().await.suricata_eve_path = traversal_eve;
        assert!(matches!(
            env.suricata_correlator.sync_alerts().await,
            Err(DomainError::PathTraversalAttempt(_))
        ));
        assert!(matches!(
            env.inspect_use_case.execute(&pending_pdf).await,
            Err(DomainError::PathTraversalAttempt(_))
        ));
    }

    // Forbidden system paths (/etc/passwd, /bin, /usr, /root, symlink ancestor to /etc) -> ForbiddenSystemDirectory.
    let etc_link = env.canonical_root.join("etc_link");
    std::os::unix::fs::symlink("/etc", &etc_link).expect("symlink /etc");

    for forbidden_eve in [
        PathBuf::from("/etc/passwd"),
        PathBuf::from("/bin/eve.json"),
        PathBuf::from("/usr/eve.json"),
        PathBuf::from("/root/eve.json"),
        etc_link.join("passwd"),
    ] {
        let cfg_forb_err = env
            .update_config_use_case
            .execute(UpdateConfigRequest {
                quarantine_dir: env.quarantine_dir.clone(),
                approved_dir: env.approved_dir.clone(),
                clamd_socket_path: None,
                suricata_eve_path: Some(forbidden_eve.clone()),
            })
            .await
            .expect_err("forbidden system path in suricata_eve_path must fail");
        assert!(
            matches!(cfg_forb_err, DomainError::ForbiddenSystemDirectory(_)),
            "expected ForbiddenSystemDirectory in UpdateConfigUseCase for {}, got {cfg_forb_err:?}",
            forbidden_eve.display()
        );

        env.runtime_config.write().await.suricata_eve_path = forbidden_eve.clone();
        assert!(matches!(
            env.suricata_correlator.sync_alerts().await,
            Err(DomainError::ForbiddenSystemDirectory(_))
        ));
        assert!(matches!(
            env.inspect_use_case.execute(&pending_pdf).await,
            Err(DomainError::ForbiddenSystemDirectory(_))
        ));
    }

    // Verify rejected paths caused zero filesystem or database side effects.
    assert!(pending_pdf.exists());
    assert_eq!(dir_entry_count(&env.approved_dir), 0);
    assert!(!env.quarantine_dir.join(".isolated").exists());
    assert!(
        env.store
            .list_recent_reports(10)
            .await
            .expect("list reports after rejections")
            .is_empty()
    );
    assert_eq!(
        env.store
            .load_or_seed(&initial_snapshot)
            .await
            .expect("load persisted config after all rejections"),
        initial_snapshot
    );

    // 2. Restore valid eve_one.json and verify full dynamic reload via UpdateConfigUseCase.
    env.runtime_config.write().await.suricata_eve_path = eve_one.clone();

    let first_report = env
        .inspect_use_case
        .execute(&pending_pdf)
        .await
        .expect("pending PDF should now inspect against eve_one.json");
    assert_eq!(
        first_report.verdict,
        SecurityVerdict::SuspiciousNetworkCorrelation {
            alert_signature: "ET TROJAN Initial Eve One Alert".to_string(),
            src_ip: "203.0.113.50".to_string(),
        }
    );
    assert!(
        env.quarantine_dir
            .join(".isolated/pendente_validacao.pdf")
            .exists()
    );

    // Reload via UpdateConfigUseCase to an alert-free eve_two.json -> clears old alert and approves next PDF.
    let eve_two = env.canonical_root.join("eve_two.json");
    std::fs::write(
        &eve_two,
        format!(
            "{{\"timestamp\":\"{}\",\"event_type\":\"dns\",\"src_ip\":\"10.0.0.1\",\"dest_ip\":\"8.8.8.8\"}}\n",
            ts_suricata_numeric(Utc::now())
        ),
    )
    .expect("write eve_two.json");

    let updated_to_two = env
        .update_config_use_case
        .execute(UpdateConfigRequest {
            quarantine_dir: env.quarantine_dir.clone(),
            approved_dir: env.approved_dir.clone(),
            clamd_socket_path: None,
            suricata_eve_path: Some(eve_two.clone()),
        })
        .await
        .expect("UpdateConfigUseCase should hot-reload suricata_eve_path to eve_two.json");
    assert_eq!(updated_to_two.suricata_eve_path, eve_two);
    assert_eq!(env.runtime_config.read().await.suricata_eve_path, eve_two);

    let reloaded_db_two = env
        .store
        .load_or_seed(&updated_to_two)
        .await
        .expect("load persisted config after eve_two reload");
    assert_eq!(reloaded_db_two.suricata_eve_path, eve_two);

    let pdf_two = env.quarantine_dir.join("lote_pos_reload_limpo.pdf");
    write_file_with_mode(&pdf_two, &build_valid_pdf_1_7(8_192, 5), 0o755);

    let second_report = env
        .inspect_use_case
        .execute(&pdf_two)
        .await
        .expect("PDF after reloading to clean eve_two.json must be approved");
    assert_eq!(second_report.verdict, SecurityVerdict::Clean);
    let approved_two = env.approved_dir.join("lote_pos_reload_limpo.pdf");
    assert!(approved_two.exists());
    assert_eq!(mode_bits(&approved_two), 0o640);

    // Reload via UpdateConfigUseCase to eve_three.json containing a fresh severity 1 alert.
    let eve_three = env.canonical_root.join("eve_three.json");
    std::fs::write(
        &eve_three,
        format!(
            "{}\n",
            format_eve_alert_line(
                &ts_rfc3339_offset(Utc::now()),
                "192.0.2.222",
                "10.0.0.8",
                "ET MALWARE Dynamic Reload Eve Three",
                1,
            )
        ),
    )
    .expect("write eve_three.json");

    let updated_to_three = env
        .update_config_use_case
        .execute(UpdateConfigRequest {
            quarantine_dir: env.quarantine_dir.clone(),
            approved_dir: env.approved_dir.clone(),
            clamd_socket_path: None,
            suricata_eve_path: Some(eve_three.clone()),
        })
        .await
        .expect("UpdateConfigUseCase should hot-reload suricata_eve_path to eve_three.json");
    assert_eq!(updated_to_three.suricata_eve_path, eve_three);

    let pdf_three = env.quarantine_dir.join("lote_pos_reload_alerta.pdf");
    write_file_with_mode(&pdf_three, &build_valid_pdf_1_7(8_192, 9), 0o755);

    let third_report = env
        .inspect_use_case
        .execute(&pdf_three)
        .await
        .expect("PDF after reloading to eve_three.json must isolate on new alert");
    assert_eq!(
        third_report.verdict,
        SecurityVerdict::SuspiciousNetworkCorrelation {
            alert_signature: "ET MALWARE Dynamic Reload Eve Three".to_string(),
            src_ip: "192.0.2.222".to_string(),
        }
    );
    let isolated_three = env
        .quarantine_dir
        .join(".isolated/lote_pos_reload_alerta.pdf");
    assert!(isolated_three.exists());
    assert_eq!(mode_bits(&isolated_three), 0o600);

    let persisted_reports = env
        .store
        .list_recent_reports(10)
        .await
        .expect("list all persisted reports");
    assert_eq!(persisted_reports.len(), 3);

    mock_clamd.shutdown().await;
}
