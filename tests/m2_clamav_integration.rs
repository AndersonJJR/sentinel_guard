#![cfg(unix)]
//! End-to-end integration tests for Milestone 2 (`feat/m2-clamav-adapter`).

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::Utc;
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

const EICAR_SIGNATURE: &[u8] =
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
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
    pings: usize,
    instreams: Vec<CapturedInstream>,
}

#[derive(Debug, Clone, Copy)]
enum MockClamdBehavior {
    DetectEicarOrClean,
    SlowResponse(Duration),
}

struct MockClamdServer {
    state: Arc<Mutex<MockClamdState>>,
    shutdown_tx: watch::Sender<bool>,
    handle: JoinHandle<()>,
}

impl MockClamdServer {
    fn start(socket_path: PathBuf, behavior: MockClamdBehavior) -> Self {
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
                        let mut conn_shutdown = shutdown_rx.clone();
                        tokio::spawn(async move {
                            handle_clamd_connection(
                                &mut stream,
                                &conn_state,
                                behavior,
                                &mut conn_shutdown,
                            )
                            .await;
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

    fn snapshot(&self) -> (usize, Vec<CapturedInstream>) {
        let guard = self.state.lock().expect("mock clamd state mutex");
        (guard.pings, guard.instreams.clone())
    }

    async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        tokio::time::timeout(CLAMD_TEST_TIMEOUT, self.handle)
            .await
            .expect("timed out waiting for mock clamd server shutdown")
            .expect("mock clamd server task panicked");
    }
}

async fn handle_clamd_connection(
    stream: &mut UnixStream,
    state: &Arc<Mutex<MockClamdState>>,
    behavior: MockClamdBehavior,
    shutdown_rx: &mut watch::Receiver<bool>,
) {
    let command = read_null_terminated_command(stream)
        .await
        .expect("read clamd NUL-terminated command");

    match command.as_slice() {
        b"zPING\0" => {
            {
                let mut guard = state.lock().expect("mock clamd state mutex");
                guard.pings += 1;
            }
            if let MockClamdBehavior::SlowResponse(delay) = behavior {
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    _ = shutdown_rx.changed() => return,
                }
            }
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
                    payload: payload.clone(),
                });
            }

            if let MockClamdBehavior::SlowResponse(delay) = behavior {
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    _ = shutdown_rx.changed() => return,
                }
            }

            let reply: &[u8] = if contains_subslice(&payload, EICAR_SIGNATURE) {
                b"stream: Win.Test.EICAR_HDB-1 FOUND\0"
            } else {
                b"stream: OK\0"
            };
            let _ = stream.write_all(reply).await;
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

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

fn build_valid_pdf_bytes(total_len: usize, salt: u8) -> Vec<u8> {
    let header = b"%PDF-1.5\n%\xe2\xe3\xcf\xd3\n";
    let footer = b"\n%%EOF\n";
    assert!(total_len >= header.len() + footer.len());
    let body_len = total_len - header.len() - footer.len();

    let mut payload = Vec::with_capacity(total_len);
    payload.extend_from_slice(header);
    payload.extend(
        (0..body_len).map(|i| (((i.wrapping_mul(37) ^ (i >> 8)) + usize::from(salt)) % 251) as u8),
    );
    payload.extend_from_slice(footer);
    payload
}

fn build_pdf_with_eicar_payload(body_padding_len: usize) -> Vec<u8> {
    let mut payload = b"%PDF-1.5\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<< /Note (".to_vec();
    payload.extend_from_slice(EICAR_SIGNATURE);
    payload.extend_from_slice(b") >>\nendobj\n");
    payload.extend(std::iter::repeat_n(b'A', body_padding_len));
    payload.extend_from_slice(b"\n%%EOF\n");
    payload
}

fn build_elf_payload(total_len: usize) -> Vec<u8> {
    let mut payload = vec![0u8; total_len.max(64)];
    payload[..8].copy_from_slice(&[0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00]);
    payload[16] = 0x02; // ET_EXEC
    payload[18] = 0x3E; // EM_X86_64
    payload[20] = 0x01; // EV_CURRENT
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

struct PipelineEnv {
    _root_guard: tempfile::TempDir,
    canonical_root: PathBuf,
    quarantine_dir: PathBuf,
    approved_dir: PathBuf,
    store: Arc<SqliteStore>,
    runtime_config: Arc<RwLock<RuntimeConfig>>,
    clamav_scanner: Arc<ClamAvScanner>,
    inspect_use_case: InspectFileUseCase,
    update_config_use_case: UpdateConfigUseCase,
    _watcher_rx: watch::Receiver<PathBuf>,
}

async fn setup_pipeline_env(socket_path: PathBuf, clamd_timeout: Duration) -> PipelineEnv {
    let root_guard = tempdir().expect("create tempdir");
    let canonical_root = std::fs::canonicalize(root_guard.path()).expect("canonical tempdir");
    let quarantine_dir = canonical_root.join("quarantine");
    let approved_dir = canonical_root.join("approved");
    std::fs::create_dir_all(&quarantine_dir).expect("create quarantine_dir");
    std::fs::create_dir_all(&approved_dir).expect("create approved_dir");

    let store = Arc::new(
        SqliteStore::connect_and_migrate("sqlite::memory:")
            .await
            .expect("in-memory sqlite migration"),
    );

    let defaults = RuntimeConfig {
        quarantine_dir: quarantine_dir.clone(),
        approved_dir: approved_dir.clone(),
        clamd_socket_path: socket_path,
        suricata_eve_path: canonical_root.join("eve.json"),
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
        clamd_timeout,
    ));
    let scanners: Vec<Arc<dyn FileScanner>> = vec![
        Arc::clone(&magic_inspector) as Arc<dyn FileScanner>,
        Arc::clone(&clamav_scanner) as Arc<dyn FileScanner>,
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

    PipelineEnv {
        _root_guard: root_guard,
        canonical_root,
        quarantine_dir,
        approved_dir,
        store,
        runtime_config,
        clamav_scanner,
        inspect_use_case,
        update_config_use_case,
        _watcher_rx: watcher_rx,
    }
}

#[tokio::test]
async fn instream_over_64kb_validates_framing_approves_pdf_and_persists_clean() {
    let socket_dir = tempdir().expect("create socket tempdir");
    let canonical_socket_dir =
        std::fs::canonicalize(socket_dir.path()).expect("canonical socket dir");
    let socket_path = canonical_socket_dir.join("clamd.ctl");
    let server = MockClamdServer::start(socket_path.clone(), MockClamdBehavior::DetectEicarOrClean);

    let env = setup_pipeline_env(socket_path, CLAMD_TEST_TIMEOUT).await;

    // ~200 KB PDF (non-multiple of 64 KB -> 3 x 65,536 B chunks + 1 trailing chunk).
    let total_len = 200 * 1024 + 333;
    let pdf_bytes = build_valid_pdf_bytes(total_len, 7);
    let expected_sha256 = sha256_hex(&pdf_bytes);

    let src_path = env.quarantine_dir.join("contrato_grande.pdf");
    write_file_with_mode(&src_path, &pdf_bytes, 0o755);

    let report = env
        .inspect_use_case
        .execute(&src_path)
        .await
        .expect("valid >64KB PDF must pass MagicBytesInspector and ClamAvScanner");

    let approved_path = env.approved_dir.join("contrato_grande.pdf");
    assert!(!src_path.exists(), "source must be moved out of quarantine");
    assert!(approved_path.exists(), "clean PDF must be in approved_dir");
    assert_eq!(mode_bits(&approved_path), 0o640);
    assert_eq!(
        mode_bits(&approved_path) & 0o111,
        0,
        "approved PDF must not retain execute bits"
    );
    assert_eq!(
        std::fs::read(&approved_path).expect("read approved PDF"),
        pdf_bytes
    );
    assert!(!env.quarantine_dir.join(".isolated").exists());

    assert!(report.id.is_some());
    assert_eq!(report.verdict, SecurityVerdict::Clean);
    assert_eq!(report.artifact.sanitized_name, "contrato_grande.pdf");
    assert_eq!(report.artifact.extension.as_deref(), Some("pdf"));
    assert_eq!(report.artifact.size_bytes, total_len as u64);
    assert_eq!(report.artifact.sha256_hash, expected_sha256);
    assert_eq!(
        report.artifact.detected_mime.as_deref(),
        Some("application/pdf")
    );
    assert_eq!(report.destination_path.as_ref(), Some(&approved_path));

    let persisted = env
        .store
        .list_recent_reports(10)
        .await
        .expect("list persisted reports");
    assert_eq!(persisted.len(), 1);
    assert_eq!(persisted[0].verdict, SecurityVerdict::Clean);
    assert_eq!(persisted[0].artifact.sha256_hash, expected_sha256);
    assert_eq!(persisted[0].destination_path.as_ref(), Some(&approved_path));

    let (pings, instreams) = server.snapshot();
    assert_eq!(pings, 0);
    assert_eq!(instreams.len(), 1);
    let captured = &instreams[0];
    assert_eq!(captured.command, b"zINSTREAM\0");
    assert!(
        captured.saw_eof_marker,
        "zINSTREAM must terminate with [0,0,0,0]"
    );
    assert!(
        captured.chunk_sizes.len() > 1,
        "expected multiple chunks for >64KB file, got {:?}",
        captured.chunk_sizes
    );
    assert_eq!(
        captured.chunk_sizes.iter().sum::<usize>(),
        total_len,
        "sum of chunk lengths must equal original file size"
    );
    assert_eq!(
        captured.payload, pdf_bytes,
        "reconstructed zINSTREAM payload must match file byte-for-byte"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn ocp_pipeline_passes_magic_bytes_and_blocks_clamav_eicar_signature_to_isolated() {
    let socket_dir = tempdir().expect("create socket tempdir");
    let canonical_socket_dir =
        std::fs::canonicalize(socket_dir.path()).expect("canonical socket dir");
    let socket_path = canonical_socket_dir.join("clamd.ctl");
    let server = MockClamdServer::start(socket_path.clone(), MockClamdBehavior::DetectEicarOrClean);

    let env = setup_pipeline_env(socket_path, CLAMD_TEST_TIMEOUT).await;

    // 1. Valid %PDF-1.5 header (passes MagicBytesInspector) + EICAR signature (>64 KB total).
    let eicar_pdf_bytes = build_pdf_with_eicar_payload(STREAM_CHUNK_SIZE + 512);
    let eicar_sha256 = sha256_hex(&eicar_pdf_bytes);
    let eicar_src = env.quarantine_dir.join("fatura_infectada.pdf");
    write_file_with_mode(&eicar_src, &eicar_pdf_bytes, 0o755);

    let eicar_report = env
        .inspect_use_case
        .execute(&eicar_src)
        .await
        .expect("ClamAV signature match must isolate artifact and persist report");

    let expected_verdict = SecurityVerdict::MaliciousSignature {
        threat_name: "Win.Test.EICAR_HDB-1".to_string(),
    };
    let isolated_dir = env.quarantine_dir.join(".isolated");
    let isolated_eicar_path = isolated_dir.join("fatura_infectada.pdf");

    assert!(
        !eicar_src.exists(),
        "infected file must leave quarantine root"
    );
    assert_eq!(
        dir_entry_count(&env.approved_dir),
        0,
        "infected file must NEVER reach approved_dir"
    );
    assert!(isolated_dir.is_dir());
    assert_eq!(mode_bits(&isolated_dir), 0o700);
    assert!(
        isolated_eicar_path.exists(),
        "infected file must be isolated under quarantine_dir/.isolated"
    );
    assert_eq!(
        mode_bits(&isolated_eicar_path),
        0o600,
        "isolated file permissions must be 0o600"
    );
    assert_eq!(
        std::fs::read(&isolated_eicar_path).expect("read isolated EICAR PDF"),
        eicar_pdf_bytes
    );

    assert_eq!(eicar_report.verdict, expected_verdict);
    assert_eq!(
        eicar_report.artifact.detected_mime.as_deref(),
        Some("application/pdf")
    );
    assert_eq!(eicar_report.artifact.sha256_hash, eicar_sha256);
    assert_eq!(
        eicar_report.destination_path.as_ref(),
        Some(&isolated_eicar_path)
    );

    // 2. Spoofed ELF (.pdf), PE/MZ (.jpg), and empty 0-byte (.pdf) must short-circuit at 1st scanner.
    let elf_bytes = build_elf_payload(1_024);
    let elf_src = env.quarantine_dir.join("spoofed_elf.pdf");
    write_file_with_mode(&elf_src, &elf_bytes, 0o755);

    let elf_report = env
        .inspect_use_case
        .execute(&elf_src)
        .await
        .expect("spoofed ELF must be isolated by first scanner");

    assert_eq!(
        elf_report.verdict,
        SecurityVerdict::MaliciousSpoofing {
            expected_ext: "pdf".to_string(),
            actual_mime: "application/x-executable".to_string(),
        }
    );
    let isolated_elf_path = isolated_dir.join("spoofed_elf.pdf");
    assert!(isolated_elf_path.exists());
    assert_eq!(mode_bits(&isolated_elf_path), 0o600);

    let mut pe_bytes = vec![0u8; 128];
    pe_bytes[..4].copy_from_slice(&[0x4D, 0x5A, 0x90, 0x00]);
    let pe_src = env.quarantine_dir.join("spoofed_pe.jpg");
    write_file_with_mode(&pe_src, &pe_bytes, 0o755);

    let pe_report = env
        .inspect_use_case
        .execute(&pe_src)
        .await
        .expect("spoofed PE/MZ must be isolated by first scanner");
    assert_eq!(
        pe_report.verdict,
        SecurityVerdict::MaliciousSpoofing {
            expected_ext: "jpg".to_string(),
            actual_mime: "application/vnd.microsoft.portable-executable".to_string(),
        }
    );
    assert_eq!(mode_bits(&isolated_dir.join("spoofed_pe.jpg")), 0o600);

    let empty_src = env.quarantine_dir.join("vazio.pdf");
    write_file_with_mode(&empty_src, b"", 0o640);
    let empty_report = env
        .inspect_use_case
        .execute(&empty_src)
        .await
        .expect("empty file must be isolated by first scanner");
    assert_eq!(
        empty_report.verdict,
        SecurityVerdict::CorruptedOrUnreadable {
            reason: "empty file (0 bytes)".to_string(),
        }
    );
    assert_eq!(mode_bits(&isolated_dir.join("vazio.pdf")), 0o600);
    assert_eq!(dir_entry_count(&env.approved_dir), 0);

    let persisted = env
        .store
        .list_recent_reports(10)
        .await
        .expect("list persisted reports");
    assert_eq!(persisted.len(), 4);
    assert_eq!(persisted[0].verdict, empty_report.verdict);
    assert_eq!(persisted[1].verdict, pe_report.verdict);
    assert_eq!(persisted[2].verdict, elf_report.verdict);
    assert_eq!(persisted[3].verdict, expected_verdict);
    assert_eq!(
        persisted[3].destination_path.as_ref(),
        Some(&isolated_eicar_path)
    );

    let (_, instreams) = server.snapshot();
    assert_eq!(
        instreams.len(),
        1,
        "only the MIME-valid PDF may reach ClamAvScanner; spoofing/empty files must short-circuit"
    );
    assert_eq!(instreams[0].payload, eicar_pdf_bytes);

    server.shutdown().await;
}

#[tokio::test]
async fn clamd_socket_security_rejects_symlink_relative_and_forbidden_dir_without_side_effects() {
    let socket_dir = tempdir().expect("create socket tempdir");
    let canonical_socket_dir =
        std::fs::canonicalize(socket_dir.path()).expect("canonical socket dir");
    let real_socket_path = canonical_socket_dir.join("real_clamd.ctl");
    let server = MockClamdServer::start(
        real_socket_path.clone(),
        MockClamdBehavior::DetectEicarOrClean,
    );

    let env = setup_pipeline_env(real_socket_path.clone(), CLAMD_TEST_TIMEOUT).await;

    let pending_bytes = build_valid_pdf_bytes(4_096, 11);
    let pending_file = env.quarantine_dir.join("aguardando.pdf");
    write_file_with_mode(&pending_file, &pending_bytes, 0o640);

    // 1. Symlink pointing to a valid socket (and dangling symlink) -> PathTraversalAttempt.
    let symlink_socket = env.canonical_root.join("symlink_clamd.ctl");
    std::os::unix::fs::symlink(&real_socket_path, &symlink_socket).expect("create socket symlink");

    let dangling_symlink_socket = env.canonical_root.join("dangling_clamd.ctl");
    std::os::unix::fs::symlink(
        env.canonical_root.join("nonexistent_clamd.ctl"),
        &dangling_symlink_socket,
    )
    .expect("create dangling socket symlink");

    for sym_path in [symlink_socket, dangling_symlink_socket] {
        env.runtime_config.write().await.clamd_socket_path = sym_path;

        let ping_err = env
            .clamav_scanner
            .ping()
            .await
            .expect_err("symlink socket ping must fail");
        assert!(
            matches!(ping_err, DomainError::PathTraversalAttempt(_)),
            "expected PathTraversalAttempt on ping, got {ping_err:?}"
        );

        let scan_err = env
            .inspect_use_case
            .execute(&pending_file)
            .await
            .expect_err("symlink socket scan must fail");
        assert!(
            matches!(scan_err, DomainError::PathTraversalAttempt(_)),
            "expected PathTraversalAttempt on execute, got {scan_err:?}"
        );
    }

    // 2. Relative socket path -> InvalidPath (both in UpdateConfigUseCase and ClamAvScanner).
    let relative_socket = PathBuf::from("relative/clamd.ctl");
    let cfg_rel_err = env
        .update_config_use_case
        .execute(UpdateConfigRequest {
            quarantine_dir: env.quarantine_dir.clone(),
            approved_dir: env.approved_dir.clone(),
            clamd_socket_path: Some(relative_socket.clone()),
            suricata_eve_path: None,
        })
        .await
        .expect_err("relative clamd_socket_path must fail in UpdateConfigUseCase");
    assert!(matches!(cfg_rel_err, DomainError::InvalidPath(_)));

    env.runtime_config.write().await.clamd_socket_path = relative_socket;
    assert!(matches!(
        env.clamav_scanner.ping().await,
        Err(DomainError::InvalidPath(_))
    ));
    assert!(matches!(
        env.inspect_use_case.execute(&pending_file).await,
        Err(DomainError::InvalidPath(_))
    ));

    // 3. Forbidden system directories (/etc, /bin, /usr, /root + symlink ancestor to /etc) -> ForbiddenSystemDirectory.
    let etc_link = env.canonical_root.join("etc_link");
    std::os::unix::fs::symlink("/etc", &etc_link).expect("create symlink to /etc");

    for forbidden_socket in [
        PathBuf::from("/etc/clamd.ctl"),
        PathBuf::from("/bin/clamd.ctl"),
        PathBuf::from("/usr/clamd.ctl"),
        PathBuf::from("/root/clamd.ctl"),
        etc_link.join("clamd.ctl"),
    ] {
        let cfg_etc_err = env
            .update_config_use_case
            .execute(UpdateConfigRequest {
                quarantine_dir: env.quarantine_dir.clone(),
                approved_dir: env.approved_dir.clone(),
                clamd_socket_path: Some(forbidden_socket.clone()),
                suricata_eve_path: None,
            })
            .await
            .expect_err("forbidden system directory socket must fail in UpdateConfigUseCase");
        assert!(
            matches!(cfg_etc_err, DomainError::ForbiddenSystemDirectory(_)),
            "expected ForbiddenSystemDirectory in UpdateConfigUseCase for {}, got {cfg_etc_err:?}",
            forbidden_socket.display()
        );

        env.runtime_config.write().await.clamd_socket_path = forbidden_socket.clone();
        let ping_err = env
            .clamav_scanner
            .ping()
            .await
            .expect_err("forbidden socket ping must fail");
        assert!(
            matches!(ping_err, DomainError::ForbiddenSystemDirectory(_)),
            "expected ForbiddenSystemDirectory on ping for {}, got {ping_err:?}",
            forbidden_socket.display()
        );
        let scan_err = env
            .inspect_use_case
            .execute(&pending_file)
            .await
            .expect_err("forbidden socket scan must fail");
        assert!(
            matches!(scan_err, DomainError::ForbiddenSystemDirectory(_)),
            "expected ForbiddenSystemDirectory on scan for {}, got {scan_err:?}",
            forbidden_socket.display()
        );
    }

    // Verify zero side effects on quarantined file, approved/isolated dirs, SQLite, and real socket.
    assert!(
        pending_file.exists(),
        "quarantined file must remain in quarantine_dir after socket validation failures"
    );
    assert_eq!(mode_bits(&pending_file), 0o640);
    assert_eq!(
        std::fs::read(&pending_file).expect("read pending file"),
        pending_bytes
    );
    assert_eq!(dir_entry_count(&env.approved_dir), 0);
    assert!(!env.quarantine_dir.join(".isolated").exists());
    assert!(
        env.store
            .list_recent_reports(10)
            .await
            .expect("list persisted reports")
            .is_empty(),
        "no inspection report may be persisted on scanner errors"
    );

    let (pings, instreams) = server.snapshot();
    assert_eq!(pings, 0);
    assert!(instreams.is_empty());

    server.shutdown().await;
}

#[tokio::test]
async fn clamd_slow_response_times_out_with_inspection_error_without_side_effects() {
    let socket_dir = tempdir().expect("create socket tempdir");
    let canonical_socket_dir =
        std::fs::canonicalize(socket_dir.path()).expect("canonical socket dir");
    let socket_path = canonical_socket_dir.join("slow_clamd.ctl");
    let server = MockClamdServer::start(
        socket_path.clone(),
        MockClamdBehavior::SlowResponse(Duration::from_secs(2)),
    );

    let short_timeout = Duration::from_millis(80);
    let env = setup_pipeline_env(socket_path, short_timeout).await;

    let pdf_bytes = build_valid_pdf_bytes(4_096, 19);
    let src_path = env.quarantine_dir.join("timeout_check.pdf");
    write_file_with_mode(&src_path, &pdf_bytes, 0o640);

    let ping_err = env
        .clamav_scanner
        .ping()
        .await
        .expect_err("slow clamd ping must time out");
    assert!(
        matches!(ping_err, DomainError::InspectionError(_)),
        "expected InspectionError on slow ping, got {ping_err:?}"
    );

    let scan_err = env
        .inspect_use_case
        .execute(&src_path)
        .await
        .expect_err("slow clamd zINSTREAM must time out");
    assert!(
        matches!(scan_err, DomainError::InspectionError(_)),
        "expected InspectionError on slow scan, got {scan_err:?}"
    );

    assert!(src_path.exists());
    assert_eq!(std::fs::read(&src_path).expect("read src"), pdf_bytes);
    assert_eq!(dir_entry_count(&env.approved_dir), 0);
    assert!(!env.quarantine_dir.join(".isolated").exists());
    assert!(
        env.store
            .list_recent_reports(10)
            .await
            .expect("list persisted reports")
            .is_empty()
    );

    let (pings, instreams) = server.snapshot();
    assert_eq!(pings, 1);
    assert_eq!(instreams.len(), 1);
    assert_eq!(instreams[0].payload, pdf_bytes);

    server.shutdown().await;
}

#[tokio::test]
async fn clamd_socket_hot_reload_via_update_config_switches_ping_and_scan_to_new_listener() {
    let socket_dir = tempdir().expect("create socket tempdir");
    let canonical_socket_dir =
        std::fs::canonicalize(socket_dir.path()).expect("canonical socket dir");
    let run_one = canonical_socket_dir.join("run_one");
    let run_two = canonical_socket_dir.join("run_two");
    let run_three = canonical_socket_dir.join("run_three");
    std::fs::create_dir_all(&run_one).expect("create run_one");
    std::fs::create_dir_all(&run_two).expect("create run_two");
    std::fs::create_dir_all(&run_three).expect("create run_three");

    let socket_one = run_one.join("clamd.ctl");
    let socket_two = run_two.join("clamd.ctl");
    let socket_three = run_three.join("clamd.ctl");

    let server_one =
        MockClamdServer::start(socket_one.clone(), MockClamdBehavior::DetectEicarOrClean);
    let server_two =
        MockClamdServer::start(socket_two.clone(), MockClamdBehavior::DetectEicarOrClean);
    let server_three =
        MockClamdServer::start(socket_three.clone(), MockClamdBehavior::DetectEicarOrClean);

    let env = setup_pipeline_env(socket_one.clone(), CLAMD_TEST_TIMEOUT).await;

    // 1. Before reload: ping() and scan() hit socket_one.
    env.clamav_scanner
        .ping()
        .await
        .expect("initial ping on socket_one");

    let doc_one_bytes = build_valid_pdf_bytes(STREAM_CHUNK_SIZE + 512, 23);
    let doc_one_path = env.quarantine_dir.join("lote_socket_1.pdf");
    write_file_with_mode(&doc_one_path, &doc_one_bytes, 0o755);

    let report_one = env
        .inspect_use_case
        .execute(&doc_one_path)
        .await
        .expect("scan on socket_one");
    assert_eq!(report_one.verdict, SecurityVerdict::Clean);
    assert!(env.approved_dir.join("lote_socket_1.pdf").exists());

    let (pings_1, instreams_1) = server_one.snapshot();
    let (pings_2, instreams_2) = server_two.snapshot();
    assert_eq!(pings_1, 1);
    assert_eq!(instreams_1.len(), 1);
    assert_eq!(pings_2, 0);
    assert!(instreams_2.is_empty());

    // 2. Hot-reload clamd_socket_path via UpdateConfigUseCase -> persists to SQLite + updates RwLock.
    let updated_cfg = env
        .update_config_use_case
        .execute(UpdateConfigRequest {
            quarantine_dir: env.quarantine_dir.clone(),
            approved_dir: env.approved_dir.clone(),
            clamd_socket_path: Some(socket_two.clone()),
            suricata_eve_path: None,
        })
        .await
        .expect("UpdateConfigUseCase should hot-reload clamd_socket_path");
    assert_eq!(updated_cfg.clamd_socket_path, socket_two);
    assert_eq!(
        env.runtime_config.read().await.clamd_socket_path,
        socket_two
    );

    let reloaded_from_db = env
        .store
        .load_or_seed(&updated_cfg)
        .await
        .expect("read persisted config from SQLite");
    assert_eq!(reloaded_from_db.clamd_socket_path, socket_two);

    // 3. Immediately verify ping() and scan() target socket_two without rebuilding scanner/use-case.
    env.clamav_scanner
        .ping()
        .await
        .expect("ping after UpdateConfigUseCase hot-reload must use socket_two");

    let doc_two_clean_bytes = build_valid_pdf_bytes(STREAM_CHUNK_SIZE + 1_024, 31);
    let doc_two_clean_path = env.quarantine_dir.join("lote_socket_2_clean.pdf");
    write_file_with_mode(&doc_two_clean_path, &doc_two_clean_bytes, 0o755);

    let report_two = env
        .inspect_use_case
        .execute(&doc_two_clean_path)
        .await
        .expect("clean scan on socket_two");
    assert_eq!(report_two.verdict, SecurityVerdict::Clean);
    assert!(env.approved_dir.join("lote_socket_2_clean.pdf").exists());

    let doc_two_eicar_bytes = build_pdf_with_eicar_payload(256);
    let doc_two_eicar_path = env.quarantine_dir.join("lote_socket_2_eicar.pdf");
    write_file_with_mode(&doc_two_eicar_path, &doc_two_eicar_bytes, 0o755);

    let report_three = env
        .inspect_use_case
        .execute(&doc_two_eicar_path)
        .await
        .expect("EICAR scan on socket_two");
    assert_eq!(
        report_three.verdict,
        SecurityVerdict::MaliciousSignature {
            threat_name: "Win.Test.EICAR_HDB-1".to_string(),
        }
    );
    assert!(
        env.quarantine_dir
            .join(".isolated/lote_socket_2_eicar.pdf")
            .exists()
    );
    assert_eq!(
        mode_bits(&env.quarantine_dir.join(".isolated/lote_socket_2_eicar.pdf")),
        0o600
    );

    let (pings_1_after, instreams_1_after) = server_one.snapshot();
    let (pings_2_after, instreams_2_after) = server_two.snapshot();
    assert_eq!(
        pings_1_after, 1,
        "socket_one must not receive pings after reload"
    );
    assert_eq!(
        instreams_1_after.len(),
        1,
        "socket_one must not receive scans after reload"
    );
    assert_eq!(pings_2_after, 1);
    assert_eq!(instreams_2_after.len(), 2);
    assert_eq!(instreams_2_after[0].payload, doc_two_clean_bytes);
    assert_eq!(instreams_2_after[1].payload, doc_two_eicar_bytes);

    // 4. Direct RwLock<RuntimeConfig> update also takes effect immediately on next ping() and scan().
    {
        let mut guard = env.runtime_config.write().await;
        guard.clamd_socket_path = socket_three;
    }

    env.clamav_scanner
        .ping()
        .await
        .expect("ping after direct RwLock<RuntimeConfig> reload must hit socket_three");

    let doc_three_bytes = build_valid_pdf_bytes(8_192, 47);
    let doc_three_path = env.quarantine_dir.join("lote_socket_3.pdf");
    write_file_with_mode(&doc_three_path, &doc_three_bytes, 0o755);

    let report_four = env
        .inspect_use_case
        .execute(&doc_three_path)
        .await
        .expect("scan on socket_three");
    assert_eq!(report_four.verdict, SecurityVerdict::Clean);

    let (pings_3, instreams_3) = server_three.snapshot();
    assert_eq!(pings_3, 1);
    assert_eq!(instreams_3.len(), 1);
    assert_eq!(instreams_3[0].payload, doc_three_bytes);

    let persisted = env
        .store
        .list_recent_reports(10)
        .await
        .expect("list persisted reports");
    assert_eq!(persisted.len(), 4);

    server_one.shutdown().await;
    server_two.shutdown().await;
    server_three.shutdown().await;
}
