#![cfg(unix)]
//! End-to-end integration tests for Milestone 1 (`feat/m1-inotify-quarantine`).

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use sha2::{Digest, Sha256};
use tempfile::tempdir;
use tokio::io::AsyncWriteExt;
use tokio::sync::{RwLock, mpsc, watch};

use sentinel_guard::application::inspect_file::InspectFileUseCase;
use sentinel_guard::application::update_config::{UpdateConfigRequest, UpdateConfigUseCase};
use sentinel_guard::domain::entities::{InspectionReport, RuntimeConfig, SecurityVerdict};
use sentinel_guard::domain::errors::DomainError;
use sentinel_guard::domain::ports::{ConfigStore, FileScanner, QuarantineRepo};
use sentinel_guard::infrastructure::fs_watcher::{FsQuarantineMover, InotifyWatcher};
use sentinel_guard::infrastructure::magic_bytes::{
    MagicBytesInspector, STREAM_CHUNK_SIZE, StreamingHasher,
};
use sentinel_guard::infrastructure::sqlite_repo::SqliteStore;

const EVENT_CHANNEL_CAPACITY: usize = 256;
const WAIT_TIMEOUT: Duration = Duration::from_secs(5);

struct QuarantineHarness {
    store: Arc<SqliteStore>,
    inspect_use_case: Arc<InspectFileUseCase>,
    update_config_use_case: Arc<UpdateConfigUseCase>,
    shutdown_tx: watch::Sender<bool>,
    watcher_handle: tokio::task::JoinHandle<Result<(), DomainError>>,
    consumer_handle: tokio::task::JoinHandle<()>,
    processed_rx: mpsc::UnboundedReceiver<Result<InspectionReport, DomainError>>,
}

impl QuarantineHarness {
    async fn start(quarantine_dir: PathBuf, approved_dir: PathBuf) -> Self {
        let canonical_q = std::fs::canonicalize(&quarantine_dir).expect("canonical quarantine_dir");
        let canonical_a = std::fs::canonicalize(&approved_dir).expect("canonical approved_dir");

        let store = Arc::new(
            SqliteStore::connect_and_migrate("sqlite::memory:")
                .await
                .expect("in-memory sqlite migration"),
        );

        let defaults = RuntimeConfig {
            quarantine_dir: canonical_q.clone(),
            approved_dir: canonical_a,
            clamd_socket_path: PathBuf::from("/var/run/clamav/clamd.ctl"),
            suricata_eve_path: PathBuf::from("/var/log/suricata/eve.json"),
            updated_at: Utc::now(),
        };
        let mut initial_config = store
            .load_or_seed(&defaults)
            .await
            .expect("seed initial runtime config");

        let (dir_tx, dir_rx) = watch::channel(initial_config.quarantine_dir.clone());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (event_tx, mut event_rx) = mpsc::channel::<PathBuf>(EVENT_CHANNEL_CAPACITY);

        let watcher = InotifyWatcher::new(initial_config.quarantine_dir.clone(), dir_rx, event_tx)
            .expect("inotify watcher initialization");
        initial_config.quarantine_dir = watcher.current_dir().to_path_buf();

        let runtime_config = Arc::new(RwLock::new(initial_config));
        let hasher = Arc::new(StreamingHasher::new());
        let magic_inspector = Arc::new(MagicBytesInspector::new());
        let scanners: Vec<Arc<dyn FileScanner>> = vec![magic_inspector.clone()];
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
            dir_tx,
        ));

        let watcher_handle = tokio::spawn(async move { watcher.run(shutdown_rx).await });

        let (processed_tx, processed_rx) = mpsc::unbounded_channel();
        let consumer_config = runtime_config.clone();
        let consumer_inspect = inspect_use_case.clone();
        let consumer_handle = tokio::spawn(async move {
            while let Some(path) = event_rx.recv().await {
                let active_quarantine = {
                    let guard = consumer_config.read().await;
                    guard.quarantine_dir.clone()
                };
                if path.parent() != Some(active_quarantine.as_path()) {
                    continue;
                }
                let result = consumer_inspect.execute(&path).await;
                if processed_tx.send(result).is_err() {
                    break;
                }
            }
        });

        // Allow the watcher task to enter its tokio::select! loop.
        tokio::time::sleep(Duration::from_millis(50)).await;

        Self {
            store,
            inspect_use_case,
            update_config_use_case,
            shutdown_tx,
            watcher_handle,
            consumer_handle,
            processed_rx,
        }
    }

    async fn next_report(&mut self, timeout: Duration) -> InspectionReport {
        tokio::time::timeout(timeout, self.processed_rx.recv())
            .await
            .expect("timed out waiting for inspection pipeline report")
            .expect("processed report channel closed unexpectedly")
            .expect("inspection pipeline returned DomainError")
    }

    async fn shutdown(self) {
        self.shutdown_tx
            .send(true)
            .expect("send shutdown signal to watcher");

        tokio::time::timeout(WAIT_TIMEOUT, self.watcher_handle)
            .await
            .expect("timed out waiting for InotifyWatcher::run shutdown")
            .expect("watcher task panicked")
            .expect("watcher returned DomainError on shutdown");

        tokio::time::timeout(WAIT_TIMEOUT, self.consumer_handle)
            .await
            .expect("timed out waiting for consumer loop shutdown")
            .expect("consumer task panicked");
    }
}

fn build_payload(header: &[u8], total_len: usize, salt: u8) -> Vec<u8> {
    let mut payload = header.to_vec();
    let remaining = total_len.saturating_sub(payload.len());
    payload.extend(
        (0..remaining).map(|i| (((i.wrapping_mul(37) ^ (i >> 8)) + usize::from(salt)) % 251) as u8),
    );
    payload
}

fn build_pdf_payload(total_len: usize, salt: u8) -> Vec<u8> {
    build_payload(b"%PDF-1.5\n%\xe2\xe3\xcf\xd3\n", total_len, salt)
}

fn build_elf_payload(total_len: usize) -> Vec<u8> {
    let mut header = [0u8; 64];
    header[0..4].copy_from_slice(&[0x7F, 0x45, 0x4C, 0x46]);
    header[4] = 2; // 64-bit
    header[5] = 1; // little-endian
    header[6] = 1; // ELF version
    header[16] = 2; // ET_EXEC
    header[18] = 0x3E; // EM_X86_64
    header[20] = 1; // EV_CURRENT
    build_payload(&header, total_len, 17)
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

async fn write_executable_file_and_close(path: &Path, payload: &[u8]) {
    let mut options = tokio::fs::OpenOptions::new();
    options.create(true).write(true).truncate(true).mode(0o755);
    let mut file = options.open(path).await.expect("open target file");
    file.set_permissions(std::fs::Permissions::from_mode(0o755))
        .await
        .expect("chmod 0755");
    file.write_all(payload).await.expect("write payload");
    file.flush().await.expect("flush payload");
    drop(file);
}

#[tokio::test]
async fn slow_write_waits_for_in_close_write_approves_pdf_and_strips_exec_bits() {
    let root = tempdir().expect("tempdir");
    let quarantine_dir = root.path().join("quarantine");
    let approved_dir = root.path().join("approved");
    std::fs::create_dir_all(&quarantine_dir).expect("create quarantine_dir");
    std::fs::create_dir_all(&approved_dir).expect("create approved_dir");

    let canonical_q = std::fs::canonicalize(&quarantine_dir).expect("canonical quarantine");
    let canonical_a = std::fs::canonicalize(&approved_dir).expect("canonical approved");

    let mut harness = QuarantineHarness::start(quarantine_dir, approved_dir).await;

    let total_len = STREAM_CHUNK_SIZE * 2 + 1_337;
    let payload = build_pdf_payload(total_len, 3);
    let expected_sha256 = sha256_hex(&payload);

    let src_path = canonical_q.join("contrato_lento.pdf");
    let mut open_opts = tokio::fs::OpenOptions::new();
    open_opts
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o755);
    let mut file = open_opts.open(&src_path).await.expect("create slow pdf");
    file.set_permissions(std::fs::Permissions::from_mode(0o755))
        .await
        .expect("chmod 0755");
    assert_eq!(mode_bits(&src_path), 0o755);

    let chunk_size = payload.len().div_ceil(5);
    for chunk in payload.chunks(chunk_size) {
        file.write_all(chunk).await.expect("write chunk");
        tokio::time::sleep(Duration::from_millis(30)).await;

        assert!(
            src_path.exists(),
            "file must remain in quarantine while still open for writing"
        );
        assert_eq!(
            dir_entry_count(&canonical_a),
            0,
            "approved_dir must remain empty before IN_CLOSE_WRITE"
        );
        assert!(
            harness.processed_rx.try_recv().is_err(),
            "pipeline must not process open file on Modify events"
        );
        assert!(
            harness
                .store
                .list_recent_reports(10)
                .await
                .expect("list reports")
                .is_empty(),
            "no report may be persisted before IN_CLOSE_WRITE"
        );
    }

    file.flush().await.expect("flush open file");
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert!(
        src_path.exists(),
        "file must still wait in quarantine until descriptor is closed"
    );
    assert_eq!(dir_entry_count(&canonical_a), 0);
    assert!(
        harness
            .store
            .list_recent_reports(10)
            .await
            .expect("list reports")
            .is_empty()
    );

    // Closing the file descriptor triggers IN_CLOSE_WRITE.
    drop(file);

    let report = harness.next_report(WAIT_TIMEOUT).await;
    let approved_path = canonical_a.join("contrato_lento.pdf");

    assert!(
        !src_path.exists(),
        "processed file must be removed from quarantine_dir"
    );
    assert!(
        approved_path.exists(),
        "clean PDF must be moved to approved_dir"
    );

    let approved_mode = mode_bits(&approved_path);
    assert_eq!(approved_mode, 0o640);
    assert_eq!(
        approved_mode & 0o111,
        0,
        "all execution bits must be stripped"
    );

    let approved_bytes = std::fs::read(&approved_path).expect("read approved PDF");
    assert_eq!(approved_bytes, payload);
    assert_eq!(sha256_hex(&approved_bytes), expected_sha256);

    assert_eq!(report.verdict, SecurityVerdict::Clean);
    assert_eq!(report.artifact.sanitized_name, "contrato_lento.pdf");
    assert_eq!(report.artifact.extension.as_deref(), Some("pdf"));
    assert_eq!(report.artifact.size_bytes, payload.len() as u64);
    assert_eq!(report.artifact.sha256_hash, expected_sha256);
    assert_eq!(
        report.artifact.detected_mime.as_deref(),
        Some("application/pdf")
    );
    assert_eq!(report.destination_path.as_ref(), Some(&approved_path));

    let persisted = harness
        .store
        .list_recent_reports(10)
        .await
        .expect("list persisted reports");
    assert_eq!(persisted.len(), 1);
    assert_eq!(persisted[0].verdict, SecurityVerdict::Clean);
    assert_eq!(persisted[0].artifact.sha256_hash, expected_sha256);
    assert_eq!(persisted[0].destination_path.as_ref(), Some(&approved_path));

    harness.shutdown().await;
}

#[tokio::test]
async fn malicious_elf_spoofed_as_pdf_is_isolated_with_mode_0600_and_persisted() {
    let root = tempdir().expect("tempdir");
    let quarantine_dir = root.path().join("quarantine");
    let approved_dir = root.path().join("approved");
    std::fs::create_dir_all(&quarantine_dir).expect("create quarantine_dir");
    std::fs::create_dir_all(&approved_dir).expect("create approved_dir");

    let canonical_q = std::fs::canonicalize(&quarantine_dir).expect("canonical quarantine");
    let canonical_a = std::fs::canonicalize(&approved_dir).expect("canonical approved");

    let mut harness = QuarantineHarness::start(quarantine_dir, approved_dir).await;

    let elf_payload = build_elf_payload(2_048);
    let expected_sha256 = sha256_hex(&elf_payload);
    let src_path = canonical_q.join("relatorio.pdf");
    write_executable_file_and_close(&src_path, &elf_payload).await;

    let report = harness.next_report(WAIT_TIMEOUT).await;
    let isolated_dir = canonical_q.join(".isolated");
    let isolated_path = isolated_dir.join("relatorio.pdf");

    assert!(
        !src_path.exists(),
        "spoofed ELF must be removed from quarantine root"
    );
    assert_eq!(
        dir_entry_count(&canonical_a),
        0,
        "spoofed ELF must never appear in approved_dir"
    );
    assert!(isolated_dir.is_dir());
    assert_eq!(mode_bits(&isolated_dir), 0o700);
    assert!(
        isolated_path.exists(),
        "spoofed ELF must be moved to quarantine_dir/.isolated/"
    );

    let isolated_mode = mode_bits(&isolated_path);
    assert_eq!(isolated_mode, 0o600);
    assert_eq!(isolated_mode & 0o111, 0);
    assert_eq!(
        std::fs::read(&isolated_path).expect("read isolated ELF"),
        elf_payload
    );

    match &report.verdict {
        SecurityVerdict::MaliciousSpoofing {
            expected_ext,
            actual_mime,
        } => {
            assert_eq!(expected_ext, "pdf");
            assert_eq!(actual_mime, "application/x-executable");
        }
        other => panic!("expected MaliciousSpoofing verdict, got {other:?}"),
    }
    assert_eq!(report.destination_path.as_ref(), Some(&isolated_path));
    assert_eq!(report.artifact.sha256_hash, expected_sha256);

    let persisted = harness
        .store
        .list_recent_reports(10)
        .await
        .expect("list persisted reports");
    assert_eq!(persisted.len(), 1);
    assert_eq!(persisted[0].verdict, report.verdict);
    assert_eq!(persisted[0].destination_path.as_ref(), Some(&isolated_path));
    assert_eq!(persisted[0].artifact.sha256_hash, expected_sha256);

    harness.shutdown().await;
}

#[tokio::test]
async fn dynamic_config_reload_switches_quarantine_dir_ignores_probes_and_unwatches_old_dir() {
    let root = tempdir().expect("tempdir");
    let quarantine_a = root.path().join("quarantine_a");
    let quarantine_b = root.path().join("quarantine_b");
    let approved_dir = root.path().join("approved");
    std::fs::create_dir_all(&quarantine_a).expect("create quarantine_a");
    std::fs::create_dir_all(&quarantine_b).expect("create quarantine_b");
    std::fs::create_dir_all(&approved_dir).expect("create approved_dir");

    let canonical_q_a = std::fs::canonicalize(&quarantine_a).expect("canonical quarantine_a");
    let canonical_q_b = std::fs::canonicalize(&quarantine_b).expect("canonical quarantine_b");
    let canonical_approved = std::fs::canonicalize(&approved_dir).expect("canonical approved");

    let mut harness = QuarantineHarness::start(quarantine_a.clone(), approved_dir.clone()).await;

    // Hot-reload quarantine directory from quarantine_a to quarantine_b.
    let updated = harness
        .update_config_use_case
        .execute(UpdateConfigRequest {
            quarantine_dir: quarantine_b.clone(),
            approved_dir: approved_dir.clone(),
            clamd_socket_path: None,
            suricata_eve_path: None,
        })
        .await
        .expect("hot-reload to quarantine_b should succeed");
    assert_eq!(updated.quarantine_dir, canonical_q_b);
    assert_eq!(updated.approved_dir, canonical_approved);

    // Wait briefly for InotifyWatcher::reload_watched_dir to switch watches.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Trigger a write probe inside the already-watched quarantine_b via a second config update
    // (updating auxiliary socket path) to prove IN_CLOSE_WRITE on `.sentinel_guard_write_probe_*`
    // is ignored by the active watcher without emitting spurious reports.
    harness
        .update_config_use_case
        .execute(UpdateConfigRequest {
            quarantine_dir: quarantine_b.clone(),
            approved_dir: approved_dir.clone(),
            clamd_socket_path: Some(root.path().join("clamd.ctl")),
            suricata_eve_path: None,
        })
        .await
        .expect("auxiliary config update on active quarantine_b should succeed");

    tokio::time::sleep(Duration::from_millis(120)).await;
    assert!(
        harness.processed_rx.try_recv().is_err(),
        "write probe must not trigger inspection pipeline"
    );
    assert!(
        harness
            .store
            .list_recent_reports(10)
            .await
            .expect("list reports")
            .is_empty(),
        "no spurious probe reports may exist in SqliteStore"
    );
    assert_eq!(dir_entry_count(&canonical_q_b), 0);
    assert_eq!(dir_entry_count(&canonical_approved), 0);

    // Write a valid PDF into the new quarantine_b and confirm full processing.
    let pdf_b_payload = build_pdf_payload(STREAM_CHUNK_SIZE + 2_048, 9);
    let expected_sha256 = sha256_hex(&pdf_b_payload);
    let src_b = canonical_q_b.join("novo_lote.pdf");
    write_executable_file_and_close(&src_b, &pdf_b_payload).await;

    let report = harness.next_report(WAIT_TIMEOUT).await;
    let approved_b = canonical_approved.join("novo_lote.pdf");

    assert!(!src_b.exists());
    assert!(approved_b.exists());
    assert_eq!(mode_bits(&approved_b), 0o640);
    assert_eq!(
        std::fs::read(&approved_b).expect("read approved_b"),
        pdf_b_payload
    );
    assert_eq!(report.verdict, SecurityVerdict::Clean);
    assert_eq!(report.artifact.sanitized_name, "novo_lote.pdf");
    assert_eq!(report.artifact.sha256_hash, expected_sha256);
    assert_eq!(report.destination_path.as_ref(), Some(&approved_b));

    let persisted = harness
        .store
        .list_recent_reports(10)
        .await
        .expect("list persisted reports");
    assert_eq!(persisted.len(), 1);
    assert!(
        !persisted.iter().any(|r| r
            .artifact
            .sanitized_name
            .starts_with(".sentinel_guard_write_probe_")),
        "SqliteStore must contain no spurious write-probe reports"
    );

    // Write a file into old quarantine_a after unwatch and confirm it is ignored.
    let stale_a = canonical_q_a.join("antigo_nao_monitorado.pdf");
    let stale_payload = build_pdf_payload(4_096, 11);
    write_executable_file_and_close(&stale_a, &stale_payload).await;

    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(
        harness.processed_rx.try_recv().is_err(),
        "old quarantine_a must no longer emit watcher events"
    );
    assert!(
        stale_a.exists(),
        "file written to unwatched quarantine_a must remain untouched"
    );
    assert_eq!(dir_entry_count(&canonical_approved), 1);
    assert_eq!(
        harness
            .store
            .list_recent_reports(10)
            .await
            .expect("list persisted reports")
            .len(),
        1
    );

    // Graceful watcher shutdown via shutdown_tx.
    harness.shutdown().await;
}

#[tokio::test]
async fn sequential_duplicate_filenames_preserve_both_files_and_reject_traversal_vectors() {
    let root = tempdir().expect("tempdir");
    let quarantine_dir = root.path().join("quarantine");
    let approved_dir = root.path().join("approved");
    std::fs::create_dir_all(&quarantine_dir).expect("create quarantine_dir");
    std::fs::create_dir_all(&approved_dir).expect("create approved_dir");

    let canonical_q = std::fs::canonicalize(&quarantine_dir).expect("canonical quarantine");
    let canonical_a = std::fs::canonicalize(&approved_dir).expect("canonical approved");

    let mut harness = QuarantineHarness::start(quarantine_dir, approved_dir).await;

    // First valid file named `duplicado.pdf`.
    let payload_1 = build_pdf_payload(STREAM_CHUNK_SIZE + 512, 1);
    let sha_1 = sha256_hex(&payload_1);
    let src_path = canonical_q.join("duplicado.pdf");
    write_executable_file_and_close(&src_path, &payload_1).await;

    let report_1 = harness.next_report(WAIT_TIMEOUT).await;
    let dest_1 = canonical_a.join("duplicado.pdf");
    assert!(!src_path.exists());
    assert_eq!(report_1.verdict, SecurityVerdict::Clean);
    assert_eq!(report_1.destination_path.as_ref(), Some(&dest_1));
    assert_eq!(report_1.artifact.sha256_hash, sha_1);
    assert_eq!(mode_bits(&dest_1), 0o640);
    assert_eq!(std::fs::read(&dest_1).expect("read dest_1"), payload_1);

    // Second valid file with identical name `duplicado.pdf` closed sequentially.
    let payload_2 = build_pdf_payload(STREAM_CHUNK_SIZE + 1_024, 2);
    let sha_2 = sha256_hex(&payload_2);
    assert_ne!(sha_1, sha_2);
    write_executable_file_and_close(&src_path, &payload_2).await;

    let report_2 = harness.next_report(WAIT_TIMEOUT).await;
    let dest_2 = report_2
        .destination_path
        .clone()
        .expect("second destination path");

    assert!(!src_path.exists());
    assert_eq!(report_2.verdict, SecurityVerdict::Clean);
    assert_eq!(report_2.artifact.sha256_hash, sha_2);
    assert_ne!(
        dest_2, dest_1,
        "collision must generate a unique destination path"
    );
    assert_eq!(dest_2.parent(), Some(canonical_a.as_path()));
    assert_eq!(dest_2.extension().and_then(|e| e.to_str()), Some("pdf"));
    assert!(
        dest_2
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|name| name.starts_with("duplicado_") && name.ends_with(".pdf")),
        "colliding filename should preserve stem and extension: {}",
        dest_2.display()
    );

    assert_eq!(mode_bits(&dest_2), 0o640);
    assert_eq!(
        std::fs::read(&dest_1).expect("first file must remain intact"),
        payload_1
    );
    assert_eq!(
        std::fs::read(&dest_2).expect("second file content"),
        payload_2
    );
    assert_eq!(
        dir_entry_count(&canonical_a),
        2,
        "both duplicate files must be preserved in approved_dir"
    );

    // Verify sanitization and symlink/traversal rejection without side effects.
    let traversal_err = harness
        .inspect_use_case
        .execute(&canonical_q.join("../outside.pdf"))
        .await
        .expect_err("parent traversal path must be rejected");
    assert!(matches!(
        traversal_err,
        DomainError::PathTraversalAttempt(_)
    ));

    let outside_target = root.path().join("outside_secret.pdf");
    std::fs::write(&outside_target, &payload_1).expect("write outside target");
    let symlink_path = canonical_q.join("symlink_escape.pdf");
    std::os::unix::fs::symlink(&outside_target, &symlink_path).expect("create symlink");

    let symlink_err = harness
        .inspect_use_case
        .execute(&symlink_path)
        .await
        .expect_err("symlink inside quarantine must be rejected");
    assert!(matches!(symlink_err, DomainError::PathTraversalAttempt(_)));

    assert_eq!(dir_entry_count(&canonical_a), 2);
    let persisted = harness
        .store
        .list_recent_reports(10)
        .await
        .expect("list persisted reports");
    assert_eq!(persisted.len(), 2);

    harness.shutdown().await;
}
