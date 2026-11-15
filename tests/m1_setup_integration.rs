//! End-to-end integration tests for Milestone 1 (`feat/m1-project-setup`).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{Duration as ChronoDuration, Utc};
use secrecy::ExposeSecret;
use tempfile::tempdir;
use tokio::sync::{RwLock, watch};
use tokio::task::JoinSet;
use tokio_rusqlite::{Connection, OpenFlags};

use sentinel_guard::application::update_config::{UpdateConfigRequest, UpdateConfigUseCase};
use sentinel_guard::domain::entities::{
    FileArtifact, InspectionReport, RuntimeConfig, SecurityVerdict,
};
use sentinel_guard::domain::errors::DomainError;
use sentinel_guard::domain::ports::{ConfigStore, QuarantineRepo};
use sentinel_guard::infrastructure::config_env::BootstrapConfig;
use sentinel_guard::infrastructure::sqlite_repo::SqliteStore;

fn build_env_map<'a>(
    token: Option<&'a str>,
    db_url: &'a str,
    quarantine_dir: &'a str,
    approved_dir: &'a str,
) -> HashMap<&'a str, &'a str> {
    let mut vars = HashMap::from([
        ("APP_ENV", "production"),
        ("BIND_ADDRESS", "127.0.0.1:8080"),
        ("DATABASE_URL", db_url),
        ("DEFAULT_QUARANTINE_DIR", quarantine_dir),
        ("DEFAULT_APPROVED_DIR", approved_dir),
        ("CLAMD_SOCKET_PATH", "/var/run/clamav/clamd.ctl"),
        ("SURICATA_EVE_PATH", "/var/log/suricata/eve.json"),
    ]);

    if let Some(secret) = token {
        vars.insert("ADMIN_API_TOKEN", secret);
    }

    vars
}

#[test]
fn bootstrap_config_from_lookup_redacts_secret_and_validates_admin_token() {
    let secret_token = "integration_secret_token_9f8e7d6c5b4a3210";
    let vars = build_env_map(
        Some(secret_token),
        "sqlite::memory:",
        "/tmp/sentinel_q",
        "/tmp/sentinel_a",
    );

    let config = BootstrapConfig::from_lookup(|key| vars.get(key).map(|v| (*v).to_string()))
        .expect("valid bootstrap env map should load");

    assert_eq!(config.admin_api_token.expose_secret(), secret_token);

    let debug_output = format!("{config:?}");
    let pretty_debug_output = format!("{config:#?}");
    assert!(
        !debug_output.contains(secret_token),
        "Debug formatting must never leak ADMIN_API_TOKEN"
    );
    assert!(
        !pretty_debug_output.contains(secret_token),
        "Pretty Debug formatting must never leak ADMIN_API_TOKEN"
    );

    let missing_token_vars = build_env_map(
        None,
        "sqlite::memory:",
        "/tmp/sentinel_q",
        "/tmp/sentinel_a",
    );
    let missing_err =
        BootstrapConfig::from_lookup(|key| missing_token_vars.get(key).map(|v| (*v).to_string()))
            .expect_err("missing ADMIN_API_TOKEN must fail");
    assert!(matches!(missing_err, DomainError::ConfigError(_)));

    for empty_token in ["", "   \t\n  "] {
        let empty_token_vars = build_env_map(
            Some(empty_token),
            "sqlite::memory:",
            "/tmp/sentinel_q",
            "/tmp/sentinel_a",
        );
        let empty_err =
            BootstrapConfig::from_lookup(|key| empty_token_vars.get(key).map(|v| (*v).to_string()))
                .expect_err("empty ADMIN_API_TOKEN must fail");
        assert!(matches!(empty_err, DomainError::ConfigError(_)));
    }
}

#[tokio::test]
async fn sqlite_store_seeds_in_memory_and_preserves_updated_config_across_second_boot() {
    let mem_store = SqliteStore::connect_and_migrate("sqlite::memory:")
        .await
        .expect("in-memory sqlite migration should succeed");

    let mem_vars = build_env_map(
        Some("mem_token_123"),
        "sqlite::memory:",
        "/tmp/mem_q",
        "/tmp/mem_a",
    );
    let mem_bootstrap = BootstrapConfig::from_lookup(|k| mem_vars.get(k).map(|v| (*v).to_string()))
        .expect("bootstrap config");
    let mem_defaults = mem_bootstrap.to_default_runtime_config();
    let mem_seeded = mem_store
        .load_or_seed(&mem_defaults)
        .await
        .expect("in-memory initial seed should succeed");
    assert_eq!(mem_seeded, mem_defaults);

    // File-backed SQLite inside tempfile::tempdir() simulating Boot 1 -> Update -> Boot 2.
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("sentinel_guard.db");
    let db_url = format!("sqlite://{}?mode=rwc", db_path.display());

    let boot1_q = temp.path().join("boot1_quarantine");
    let boot1_a = temp.path().join("boot1_approved");
    let updated_q = temp.path().join("updated_quarantine");
    let updated_a = temp.path().join("updated_approved");
    std::fs::create_dir_all(&boot1_q).expect("create boot1_q");
    std::fs::create_dir_all(&boot1_a).expect("create boot1_a");
    std::fs::create_dir_all(&updated_q).expect("create updated_q");
    std::fs::create_dir_all(&updated_a).expect("create updated_a");

    let persisted_after_update: RuntimeConfig = {
        let q_str = boot1_q.to_string_lossy().into_owned();
        let a_str = boot1_a.to_string_lossy().into_owned();
        let boot1_vars = build_env_map(Some("boot1_secret"), &db_url, &q_str, &a_str);
        let boot1_cfg =
            BootstrapConfig::from_lookup(|k| boot1_vars.get(k).map(|v| (*v).to_string()))
                .expect("boot 1 bootstrap config");

        let store = Arc::new(
            SqliteStore::connect_and_migrate(&boot1_cfg.database_url)
                .await
                .expect("boot 1 sqlite connect and migrate"),
        );

        let initial_runtime = store
            .load_or_seed(&boot1_cfg.to_default_runtime_config())
            .await
            .expect("boot 1 seed should succeed");
        assert_eq!(initial_runtime.quarantine_dir, boot1_q);
        assert_eq!(initial_runtime.approved_dir, boot1_a);

        let runtime_lock = Arc::new(RwLock::new(initial_runtime.clone()));
        let (watcher_tx, mut watcher_rx) = watch::channel(initial_runtime.quarantine_dir.clone());
        let use_case = UpdateConfigUseCase::new(store.clone(), runtime_lock.clone(), watcher_tx);

        let updated = use_case
            .execute(UpdateConfigRequest {
                quarantine_dir: updated_q.clone(),
                approved_dir: updated_a.clone(),
                clamd_socket_path: None,
                suricata_eve_path: None,
            })
            .await
            .expect("boot 1 runtime config update should succeed");

        watcher_rx
            .changed()
            .await
            .expect("watcher should receive notification");
        let expected_q = std::fs::canonicalize(&updated_q).expect("canonical updated_q");
        let expected_a = std::fs::canonicalize(&updated_a).expect("canonical updated_a");
        assert_eq!(*watcher_rx.borrow_and_update(), expected_q);
        assert_eq!(runtime_lock.read().await.quarantine_dir, expected_q);
        assert_eq!(runtime_lock.read().await.approved_dir, expected_a);

        updated
    };

    // Boot 2: reopen the same SQLite database with completely different .env defaults.
    let boot2_q = temp.path().join("boot2_ignored_q");
    let boot2_a = temp.path().join("boot2_ignored_a");
    std::fs::create_dir_all(&boot2_q).expect("create boot2_q");
    std::fs::create_dir_all(&boot2_a).expect("create boot2_a");

    let q2_str = boot2_q.to_string_lossy().into_owned();
    let a2_str = boot2_a.to_string_lossy().into_owned();
    let boot2_vars = build_env_map(Some("boot2_secret"), &db_url, &q2_str, &a2_str);
    let boot2_cfg = BootstrapConfig::from_lookup(|k| boot2_vars.get(k).map(|v| (*v).to_string()))
        .expect("boot 2 bootstrap config");

    let store_boot2 = SqliteStore::connect_and_migrate(&boot2_cfg.database_url)
        .await
        .expect("boot 2 sqlite connect and migrate");
    let loaded_boot2 = store_boot2
        .load_or_seed(&boot2_cfg.to_default_runtime_config())
        .await
        .expect("boot 2 load_or_seed should return persisted row");

    assert_eq!(loaded_boot2, persisted_after_update);
    assert_ne!(loaded_boot2.quarantine_dir, boot2_q);
    assert_ne!(loaded_boot2.approved_dir, boot2_a);

    // Verify directly via tokio_rusqlite::Connection (read-only) that system_config contains 1 row with updated paths.
    let raw_conn = Connection::open_with_flags(&db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .await
        .expect("connect read-only with tokio_rusqlite");

    let (count, db_q, db_a): (i64, String, String) = raw_conn
        .call(|conn| {
            let count: i64 =
                conn.query_row("SELECT COUNT(*) FROM system_config", [], |row| row.get(0))?;
            let (db_q, db_a): (String, String) = conn.query_row(
                "SELECT quarantine_dir, approved_dir FROM system_config WHERE id = 1",
                [],
                |row| Ok((row.get("quarantine_dir")?, row.get("approved_dir")?)),
            )?;
            Ok::<_, tokio_rusqlite::rusqlite::Error>((count, db_q, db_a))
        })
        .await
        .expect("query system_config directly");

    assert_eq!(count, 1);
    assert_eq!(PathBuf::from(db_q), persisted_after_update.quarantine_dir);
    assert_eq!(PathBuf::from(db_a), persisted_after_update.approved_dir);
}

#[tokio::test]
async fn sqlite_quarantine_repo_persists_verdicts_across_restarts() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("quarantine_logs.db");
    let db_url = format!("sqlite://{}?mode=rwc", db_path.display());

    let base_time = Utc::now();
    let reports = vec![
        InspectionReport {
            id: None,
            artifact: FileArtifact {
                path: PathBuf::from("/quarantine/empty_note"),
                sanitized_name: "empty_note".to_string(),
                extension: None,
                size_bytes: 0,
                sha256_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    .to_string(),
                detected_mime: None,
            },
            verdict: SecurityVerdict::CorruptedOrUnreadable {
                reason: "Empty file (0 bytes)".to_string(),
            },
            destination_path: None,
            inspected_at: base_time,
        },
        InspectionReport {
            id: None,
            artifact: FileArtifact {
                path: PathBuf::from("/quarantine/invoice.pdf"),
                sanitized_name: "invoice.pdf".to_string(),
                extension: Some("pdf".to_string()),
                size_bytes: 4096,
                sha256_hash: "1".repeat(64),
                detected_mime: Some("application/x-executable".to_string()),
            },
            verdict: SecurityVerdict::MaliciousSpoofing {
                expected_ext: "pdf".to_string(),
                actual_mime: "application/x-executable".to_string(),
            },
            destination_path: Some(PathBuf::from("/quarantine/isolated/invoice.pdf")),
            inspected_at: base_time + ChronoDuration::seconds(1),
        },
        InspectionReport {
            id: None,
            artifact: FileArtifact {
                path: PathBuf::from("/quarantine/installer.exe"),
                sanitized_name: "installer.exe".to_string(),
                extension: Some("exe".to_string()),
                size_bytes: 262_144,
                sha256_hash: "2".repeat(64),
                detected_mime: Some("application/vnd.microsoft.portable-executable".to_string()),
            },
            verdict: SecurityVerdict::MaliciousSignature {
                threat_name: "Win.Trojan.Generic-999".to_string(),
            },
            destination_path: Some(PathBuf::from("/quarantine/isolated/installer.exe")),
            inspected_at: base_time + ChronoDuration::seconds(2),
        },
        InspectionReport {
            id: None,
            artifact: FileArtifact {
                path: PathBuf::from("/quarantine/archive.zip"),
                sanitized_name: "archive.zip".to_string(),
                extension: Some("zip".to_string()),
                size_bytes: 131_072,
                sha256_hash: "3".repeat(64),
                detected_mime: Some("application/zip".to_string()),
            },
            verdict: SecurityVerdict::SuspiciousNetworkCorrelation {
                alert_signature: "ET EXPLOIT Malicious Payload Transfer".to_string(),
                src_ip: "10.99.0.15".to_string(),
            },
            destination_path: Some(PathBuf::from("/quarantine/isolated/archive.zip")),
            inspected_at: base_time + ChronoDuration::seconds(3),
        },
        InspectionReport {
            id: None,
            artifact: FileArtifact {
                path: PathBuf::from("/quarantine/course_video.mp4"),
                sanitized_name: "course_video.mp4".to_string(),
                extension: Some("mp4".to_string()),
                size_bytes: 10_485_760,
                sha256_hash: "4".repeat(64),
                detected_mime: Some("video/mp4".to_string()),
            },
            verdict: SecurityVerdict::Clean,
            destination_path: Some(PathBuf::from("/approved/course_video.mp4")),
            inspected_at: base_time + ChronoDuration::seconds(4),
        },
    ];

    let mut saved_ids = Vec::with_capacity(reports.len());
    {
        let store = SqliteStore::connect_and_migrate(&db_url)
            .await
            .expect("connect and migrate");
        for report in &reports {
            let id = store
                .save_report(report)
                .await
                .expect("save_report should succeed");
            saved_ids.push(id);
        }
    }

    let reopened = SqliteStore::connect_and_migrate(&db_url)
        .await
        .expect("reopen sqlite store");
    let listed = reopened
        .list_recent_reports(10)
        .await
        .expect("list_recent_reports should succeed");

    assert_eq!(listed.len(), reports.len());

    // Ordered newest-first.
    for (idx, persisted) in listed.iter().enumerate() {
        let original_idx = reports.len() - 1 - idx;
        let expected = &reports[original_idx];
        assert_eq!(persisted.id, Some(saved_ids[original_idx]));
        assert_eq!(persisted.artifact, expected.artifact);
        assert_eq!(persisted.verdict, expected.verdict);
        assert_eq!(persisted.destination_path, expected.destination_path);
        assert_eq!(persisted.inspected_at, expected.inspected_at);
    }

    let top_two = reopened
        .list_recent_reports(2)
        .await
        .expect("limit=2 query should succeed");
    assert_eq!(top_two.len(), 2);
    assert_eq!(top_two[0].verdict, SecurityVerdict::Clean);
    assert!(matches!(
        top_two[1].verdict,
        SecurityVerdict::SuspiciousNetworkCorrelation { .. }
    ));
}

#[tokio::test]
async fn update_config_use_case_enforces_security_rules_with_real_sqlite_store() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("config_security.db");
    let db_url = format!("sqlite://{}?mode=rwc", db_path.display());

    let initial_q = temp.path().join("initial_q");
    let initial_a = temp.path().join("initial_a");
    let nested_q = initial_q.join("nested");
    let regular_file = temp.path().join("not_a_directory.txt");

    std::fs::create_dir_all(&nested_q).expect("create initial_q and nested");
    std::fs::create_dir_all(&initial_a).expect("create initial_a");
    std::fs::write(&regular_file, b"plain file").expect("create regular file");

    let canonical_initial_q = std::fs::canonicalize(&initial_q).expect("canonical initial_q");
    let canonical_initial_a = std::fs::canonicalize(&initial_a).expect("canonical initial_a");

    let store = Arc::new(
        SqliteStore::connect_and_migrate(&db_url)
            .await
            .expect("sqlite connect and migrate"),
    );

    let initial_cfg = RuntimeConfig {
        quarantine_dir: canonical_initial_q.clone(),
        approved_dir: canonical_initial_a.clone(),
        clamd_socket_path: PathBuf::from("/var/run/clamav/clamd.ctl"),
        suricata_eve_path: PathBuf::from("/var/log/suricata/eve.json"),
        updated_at: Utc::now(),
    };
    let seeded = store
        .load_or_seed(&initial_cfg)
        .await
        .expect("initial seed");

    let runtime_state = Arc::new(RwLock::new(seeded.clone()));
    let (tx, rx) = watch::channel(seeded.quarantine_dir.clone());
    let use_case = UpdateConfigUseCase::new(store.clone(), runtime_state.clone(), tx);

    // 1. Forbidden critical system directories.
    for critical in [
        "/etc", "/root", "/bin", "/usr", "/sbin", "/lib", "/lib64", "/proc", "/sys", "/dev",
        "/boot", "/",
    ] {
        let err = use_case
            .execute(UpdateConfigRequest {
                quarantine_dir: PathBuf::from(critical),
                approved_dir: initial_a.clone(),
                clamd_socket_path: None,
                suricata_eve_path: None,
            })
            .await
            .expect_err("critical system directory must be blocked");
        assert!(
            matches!(err, DomainError::ForbiddenSystemDirectory(_)),
            "expected ForbiddenSystemDirectory for {critical}, got {err:?}"
        );
    }

    // 2. Path traversal attempt ('..').
    let traversal_err = use_case
        .execute(UpdateConfigRequest {
            quarantine_dir: temp.path().join("../outside"),
            approved_dir: initial_a.clone(),
            clamd_socket_path: None,
            suricata_eve_path: None,
        })
        .await
        .expect_err("path traversal must be blocked");
    assert!(matches!(
        traversal_err,
        DomainError::PathTraversalAttempt(_)
    ));

    // 3. Nonexistent directory & regular file.
    let missing_err = use_case
        .execute(UpdateConfigRequest {
            quarantine_dir: temp.path().join("does_not_exist"),
            approved_dir: initial_a.clone(),
            clamd_socket_path: None,
            suricata_eve_path: None,
        })
        .await
        .expect_err("nonexistent directory must fail");
    assert!(matches!(missing_err, DomainError::InvalidPath(_)));

    let file_err = use_case
        .execute(UpdateConfigRequest {
            quarantine_dir: initial_q.clone(),
            approved_dir: regular_file,
            clamd_socket_path: None,
            suricata_eve_path: None,
        })
        .await
        .expect_err("regular file must fail");
    assert!(matches!(file_err, DomainError::InvalidPath(_)));

    // 4. Same directory or nested directory relationships.
    let same_err = use_case
        .execute(UpdateConfigRequest {
            quarantine_dir: initial_q.clone(),
            approved_dir: initial_q.clone(),
            clamd_socket_path: None,
            suricata_eve_path: None,
        })
        .await
        .expect_err("equal directories must fail");
    assert!(matches!(same_err, DomainError::InvalidPath(_)));

    let nested_a_in_q = use_case
        .execute(UpdateConfigRequest {
            quarantine_dir: initial_q.clone(),
            approved_dir: nested_q.clone(),
            clamd_socket_path: None,
            suricata_eve_path: None,
        })
        .await
        .expect_err("approved inside quarantine must fail");
    assert!(matches!(nested_a_in_q, DomainError::InvalidPath(_)));

    let nested_q_in_a = use_case
        .execute(UpdateConfigRequest {
            quarantine_dir: nested_q,
            approved_dir: initial_q,
            clamd_socket_path: None,
            suricata_eve_path: None,
        })
        .await
        .expect_err("quarantine inside approved must fail");
    assert!(matches!(nested_q_in_a, DomainError::InvalidPath(_)));

    // Confirm zero side effects in DB, memory lock, or watcher channel after all failed attempts.
    assert!(!rx.has_changed().expect("watch receiver open"));
    assert_eq!(
        runtime_state.read().await.quarantine_dir,
        canonical_initial_q
    );
    assert_eq!(runtime_state.read().await.approved_dir, canonical_initial_a);

    let persisted = store
        .load_or_seed(&RuntimeConfig {
            quarantine_dir: PathBuf::from("/tmp/unused"),
            approved_dir: PathBuf::from("/tmp/unused2"),
            clamd_socket_path: PathBuf::from("/tmp/unused3"),
            suricata_eve_path: PathBuf::from("/tmp/unused4"),
            updated_at: Utc::now(),
        })
        .await
        .expect("reload config");
    assert_eq!(persisted.quarantine_dir, canonical_initial_q);
    assert_eq!(persisted.approved_dir, canonical_initial_a);
}

#[tokio::test]
async fn auxiliary_paths_reject_relative_and_dangling_symlinks_and_sqlite_db_is_0600() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("hardened_permissions.db");
    let db_url = format!("sqlite://{}?mode=rwc", db_path.display());

    let valid_q = temp.path().join("valid_q");
    let valid_a = temp.path().join("valid_a");
    std::fs::create_dir_all(&valid_q).expect("create valid_q");
    std::fs::create_dir_all(&valid_a).expect("create valid_a");

    let store = Arc::new(
        SqliteStore::connect_and_migrate(&db_url)
            .await
            .expect("sqlite connect and migrate"),
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let db_mode = std::fs::metadata(&db_path)
            .expect("sqlite db file metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            db_mode, 0o600,
            "SQLite database file must be hardened to 0o600, got {db_mode:#o}"
        );

        for sidecar_suffix in ["-wal", "-shm"] {
            let sidecar_path = PathBuf::from(format!("{}{}", db_path.display(), sidecar_suffix));
            if sidecar_path.exists() {
                let sidecar_mode = std::fs::metadata(&sidecar_path)
                    .expect("sidecar metadata")
                    .permissions()
                    .mode()
                    & 0o777;
                assert_eq!(
                    sidecar_mode,
                    0o600,
                    "SQLite sidecar file {} must be hardened to 0o600, got {sidecar_mode:#o}",
                    sidecar_path.display()
                );
            }
        }
    }

    let initial_cfg = RuntimeConfig {
        quarantine_dir: std::fs::canonicalize(&valid_q).expect("canonical valid_q"),
        approved_dir: std::fs::canonicalize(&valid_a).expect("canonical valid_a"),
        clamd_socket_path: temp.path().join("clamd.ctl"),
        suricata_eve_path: temp.path().join("eve.json"),
        updated_at: Utc::now(),
    };
    let seeded = store
        .load_or_seed(&initial_cfg)
        .await
        .expect("initial seed");

    let runtime_state = Arc::new(RwLock::new(seeded.clone()));
    let (tx, rx) = watch::channel(seeded.quarantine_dir.clone());
    let use_case = UpdateConfigUseCase::new(store.clone(), runtime_state.clone(), tx);

    // Relative paths must be rejected for clamd_socket_path and suricata_eve_path.
    for (case_name, clamd, eve) in [
        (
            "relative_clamd_socket_path",
            Some(PathBuf::from("relative/clamd.ctl")),
            None,
        ),
        (
            "relative_suricata_eve_path",
            None,
            Some(PathBuf::from("eve.json")),
        ),
    ] {
        let err = use_case
            .execute(UpdateConfigRequest {
                quarantine_dir: valid_q.clone(),
                approved_dir: valid_a.clone(),
                clamd_socket_path: clamd,
                suricata_eve_path: eve,
            })
            .await
            .expect_err("relative auxiliary path must fail");
        assert!(
            matches!(err, DomainError::InvalidPath(_)),
            "case '{case_name}' expected InvalidPath, got {err:?}"
        );
    }

    // Dangling absolute and relative symlinks pointing into /etc or / must be rejected.
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let dangling_abs_etc = temp.path().join("dangling_abs_etc_clamd");
        symlink("/etc/sentinel_nonexistent_clamd.ctl", &dangling_abs_etc)
            .expect("create dangling abs /etc symlink");

        let dangling_abs_root = temp.path().join("dangling_abs_root_eve");
        symlink("/sentinel_nonexistent_root_eve.json", &dangling_abs_root)
            .expect("create dangling abs / symlink");

        let dangling_rel_etc = temp.path().join("dangling_rel_etc_clamd");
        symlink(
            "../../../../../../../../etc/sentinel_nonexistent_clamd.ctl",
            &dangling_rel_etc,
        )
        .expect("create dangling rel /etc symlink");

        let dangling_rel_root = temp.path().join("dangling_rel_root_eve");
        symlink(
            "../../../../../../../../sentinel_nonexistent_root_eve.json",
            &dangling_rel_root,
        )
        .expect("create dangling rel / symlink");

        let symlink_cases = [
            ("dangling_abs_etc_clamd", Some(dangling_abs_etc), None),
            ("dangling_abs_root_eve", None, Some(dangling_abs_root)),
            ("dangling_rel_etc_clamd", Some(dangling_rel_etc), None),
            ("dangling_rel_root_eve", None, Some(dangling_rel_root)),
        ];

        for (case_name, clamd, eve) in symlink_cases {
            let err = use_case
                .execute(UpdateConfigRequest {
                    quarantine_dir: valid_q.clone(),
                    approved_dir: valid_a.clone(),
                    clamd_socket_path: clamd,
                    suricata_eve_path: eve,
                })
                .await
                .expect_err("dangling symlink targeting /etc or / must be rejected");
            assert!(
                matches!(err, DomainError::ForbiddenSystemDirectory(_)),
                "case '{case_name}' expected ForbiddenSystemDirectory, got {err:?}"
            );
        }
    }

    assert!(!rx.has_changed().expect("watch receiver open"));
    assert_eq!(*runtime_state.read().await, seeded);
}

#[cfg(unix)]
fn assert_sqlite_wal_files_mode_0600(db_path: &Path, stage: &str) {
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt;

    let mut wal_os = OsString::from(db_path.as_os_str());
    wal_os.push("-wal");
    let mut shm_os = OsString::from(db_path.as_os_str());
    shm_os.push("-shm");

    for path in [db_path, Path::new(&wal_os), Path::new(&shm_os)] {
        let meta = std::fs::symlink_metadata(path).unwrap_or_else(|err| {
            panic!(
                "[{stage}] expected SQLite file {} to exist: {err}",
                path.display()
            )
        });
        assert!(
            !meta.file_type().is_symlink(),
            "[{stage}] SQLite file {} must not be a symlink",
            path.display()
        );
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode,
            0o600,
            "[{stage}] SQLite file {} must have 0o600 permissions, got {mode:#o}",
            path.display()
        );
    }
}

#[tokio::test]
async fn sqlite_store_supports_concurrent_tokio_tasks_and_preserves_0600_wal_permissions() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("concurrent_wal.db");
    let db_url = format!("sqlite://{}?mode=rwc", db_path.display());

    let q1 = temp.path().join("q1");
    let a1 = temp.path().join("a1");
    let q2 = temp.path().join("q2");
    let a2 = temp.path().join("a2");
    for dir in [&q1, &a1, &q2, &a2] {
        std::fs::create_dir_all(dir).expect("create test dirs");
    }

    let q1_str = q1.to_string_lossy().into_owned();
    let a1_str = a1.to_string_lossy().into_owned();
    let vars = build_env_map(Some("concurrent_secret"), &db_url, &q1_str, &a1_str);
    let bootstrap = BootstrapConfig::from_lookup(|k| vars.get(k).map(|v| (*v).to_string()))
        .expect("bootstrap config");

    {
        let store = Arc::new(
            SqliteStore::connect_and_migrate(&bootstrap.database_url)
                .await
                .expect("primary store connect and migrate"),
        );
        let secondary_store = Arc::new(
            SqliteStore::connect_and_migrate(&bootstrap.database_url)
                .await
                .expect("secondary store connect and migrate"),
        );

        let seeded = store
            .load_or_seed(&bootstrap.to_default_runtime_config())
            .await
            .expect("seed runtime config");
        let runtime_lock = Arc::new(RwLock::new(seeded.clone()));
        let (watcher_tx, _watcher_rx) = watch::channel(seeded.quarantine_dir.clone());
        let use_case = Arc::new(UpdateConfigUseCase::new(
            store.clone(),
            runtime_lock.clone(),
            watcher_tx,
        ));

        let writer_count = 20usize;
        let base_time = Utc::now();
        let mut tasks = JoinSet::new();

        for idx in 0..writer_count {
            let repo = if idx % 2 == 0 {
                store.clone()
            } else {
                secondary_store.clone()
            };
            tasks.spawn(async move {
                let report = InspectionReport {
                    id: None,
                    artifact: FileArtifact {
                        path: PathBuf::from(format!("/quarantine/item_{idx}.pdf")),
                        sanitized_name: format!("item_{idx}.pdf"),
                        extension: Some("pdf".to_string()),
                        size_bytes: 1024 + idx as u64,
                        sha256_hash: format!("{idx:064x}"),
                        detected_mime: Some("application/pdf".to_string()),
                    },
                    verdict: if idx % 4 == 0 {
                        SecurityVerdict::MaliciousSpoofing {
                            expected_ext: "pdf".to_string(),
                            actual_mime: "application/x-executable".to_string(),
                        }
                    } else {
                        SecurityVerdict::Clean
                    },
                    destination_path: Some(PathBuf::from(format!("/approved/item_{idx}.pdf"))),
                    inspected_at: base_time + ChronoDuration::milliseconds(idx as i64),
                };

                repo.save_report(&report)
                    .await
                    .expect("concurrent save_report must not fail with database is locked")
            });
        }

        let mut reader_tasks = JoinSet::new();
        for idx in 0..10usize {
            let repo = if idx % 2 == 0 {
                store.clone()
            } else {
                secondary_store.clone()
            };
            let defaults = bootstrap.to_default_runtime_config();
            reader_tasks.spawn(async move {
                let _ = repo
                    .list_recent_reports(10)
                    .await
                    .expect("concurrent list_recent_reports must succeed");
                let _ = repo
                    .load_or_seed(&defaults)
                    .await
                    .expect("concurrent load_or_seed must succeed");
            });
        }

        let update_fut = use_case.execute(UpdateConfigRequest {
            quarantine_dir: q2.clone(),
            approved_dir: a2.clone(),
            clamd_socket_path: None,
            suricata_eve_path: None,
        });
        let joined_report = InspectionReport {
            id: None,
            artifact: FileArtifact {
                path: PathBuf::from("/quarantine/joined.pdf"),
                sanitized_name: "joined.pdf".to_string(),
                extension: Some("pdf".to_string()),
                size_bytes: 2048,
                sha256_hash: "f".repeat(64),
                detected_mime: Some("application/pdf".to_string()),
            },
            verdict: SecurityVerdict::Clean,
            destination_path: Some(PathBuf::from("/approved/joined.pdf")),
            inspected_at: base_time + ChronoDuration::seconds(1),
        };
        let extra_write_fut = secondary_store.save_report(&joined_report);
        let extra_read_fut = store.list_recent_reports(25);

        let (update_res, extra_write_res, extra_read_res) =
            tokio::join!(update_fut, extra_write_fut, extra_read_fut);
        update_res.expect("concurrent config update should succeed");
        let joined_id = extra_write_res.expect("concurrent joined write should succeed");
        extra_read_res.expect("concurrent joined read should succeed");

        let mut ids = HashSet::with_capacity(writer_count + 1);
        ids.insert(joined_id);
        while let Some(res) = tasks.join_next().await {
            let id = res.expect("writer task must not panic");
            assert!(id > 0);
            assert!(ids.insert(id), "duplicate inserted report id {id}");
        }
        assert_eq!(ids.len(), writer_count + 1);

        while let Some(res) = reader_tasks.join_next().await {
            res.expect("reader task must not panic");
        }

        #[cfg(unix)]
        assert_sqlite_wal_files_mode_0600(&db_path, "after_concurrent_writes");
    }

    // Reopen DB, perform additional writes, and verify WAL + count + 0o600 preservation.
    {
        let reopened = SqliteStore::connect_and_migrate(&bootstrap.database_url)
            .await
            .expect("reopen sqlite store");
        reopened
            .save_report(&InspectionReport {
                id: None,
                artifact: FileArtifact {
                    path: PathBuf::from("/quarantine/reopened.pdf"),
                    sanitized_name: "reopened.pdf".to_string(),
                    extension: Some("pdf".to_string()),
                    size_bytes: 512,
                    sha256_hash: "e".repeat(64),
                    detected_mime: Some("application/pdf".to_string()),
                },
                verdict: SecurityVerdict::Clean,
                destination_path: Some(PathBuf::from("/approved/reopened.pdf")),
                inspected_at: Utc::now(),
            })
            .await
            .expect("save_report after reopen");

        #[cfg(unix)]
        assert_sqlite_wal_files_mode_0600(&db_path, "after_reopen_and_write");

        let raw_conn = Connection::open_with_flags(&db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .await
            .expect("open read-only connection");
        let (journal_mode, count): (String, i64) = raw_conn
            .call(|conn| {
                let mode: String = conn.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
                let count: i64 =
                    conn.query_row("SELECT COUNT(*) FROM quarantine_logs", [], |r| r.get(0))?;
                Ok::<_, tokio_rusqlite::rusqlite::Error>((mode, count))
            })
            .await
            .expect("inspect journal_mode and quarantine_logs count");
        assert_eq!(journal_mode.to_lowercase(), "wal");
        assert_eq!(count, 22);
    }
}

#[tokio::test]
async fn sqlite_store_rejects_malicious_urls_traversal_system_dirs_and_symlinks() {
    for traversal_url in [
        "../sentinel.db",
        "sqlite://../sentinel.db",
        "sqlite:///tmp/../etc/sentinel.db",
        "sqlite://..",
    ] {
        let err = SqliteStore::connect_and_migrate(traversal_url)
            .await
            .expect_err("path traversal URL must be rejected");
        assert!(
            matches!(err, DomainError::PathTraversalAttempt(_)),
            "expected PathTraversalAttempt for {traversal_url:?}, got {err:?}"
        );
    }

    for null_url in ["sqlite:///tmp/sentinel\0.db", "sqlite::memory:\0", "\0"] {
        let err = SqliteStore::connect_and_migrate(null_url)
            .await
            .expect_err("null byte URL must be rejected");
        assert!(
            matches!(err, DomainError::InvalidPath(_)),
            "expected InvalidPath for {null_url:?}, got {err:?}"
        );
    }

    for system_url in [
        "/etc/sentinel.db",
        "sqlite:///etc/sentinel.db",
        "sqlite:/etc/sentinel.db",
        "/root/sentinel.db",
        "sqlite:///root/sentinel.db",
        "sqlite:/root/sentinel.db",
        "sqlite:///bin/sentinel.db",
        "sqlite:///usr/sentinel.db",
    ] {
        let err = SqliteStore::connect_and_migrate(system_url)
            .await
            .expect_err("forbidden OS directory URL must be rejected");
        assert!(
            matches!(err, DomainError::ForbiddenSystemDirectory(_)),
            "expected ForbiddenSystemDirectory for {system_url:?}, got {err:?}"
        );
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let temp = tempdir().expect("tempdir");
        let target_file = temp.path().join("target.bin");
        std::fs::write(&target_file, b"target").expect("create target file");

        // Symlinked .db file (existing target & dangling).
        let db_link = temp.path().join("db_link.db");
        symlink(&target_file, &db_link).expect("create db symlink");
        let db_link_err =
            SqliteStore::connect_and_migrate(&format!("sqlite://{}", db_link.display()))
                .await
                .expect_err("symlink .db must be rejected");
        assert!(matches!(db_link_err, DomainError::PathTraversalAttempt(_)));

        // Symlinked -wal and -shm sidecars (existing target & dangling).
        for suffix in ["-wal", "-shm"] {
            let db_for_existing = temp
                .path()
                .join(format!("sidecar_existing_{}.db", &suffix[1..]));
            let sidecar_existing =
                PathBuf::from(format!("{}{}", db_for_existing.display(), suffix));
            symlink(&target_file, &sidecar_existing).expect("create existing sidecar symlink");
            let err_existing = SqliteStore::connect_and_migrate(&format!(
                "sqlite://{}",
                db_for_existing.display()
            ))
            .await
            .expect_err("symlinked sidecar must be rejected");
            assert!(
                matches!(err_existing, DomainError::PathTraversalAttempt(_)),
                "expected PathTraversalAttempt for {suffix} existing symlink, got {err_existing:?}"
            );

            let db_for_dangling = temp
                .path()
                .join(format!("sidecar_dangling_{}.db", &suffix[1..]));
            let sidecar_dangling =
                PathBuf::from(format!("{}{}", db_for_dangling.display(), suffix));
            symlink("/etc/nonexistent_wal_target", &sidecar_dangling)
                .expect("create dangling sidecar symlink");
            let err_dangling = SqliteStore::connect_and_migrate(&format!(
                "sqlite://{}",
                db_for_dangling.display()
            ))
            .await
            .expect_err("dangling symlinked sidecar must be rejected");
            assert!(
                matches!(err_dangling, DomainError::PathTraversalAttempt(_)),
                "expected PathTraversalAttempt for {suffix} dangling symlink, got {err_dangling:?}"
            );
        }

        // Ancestor symlink pointing directly to /etc and via /.
        let etc_alias = temp.path().join("etc_alias");
        symlink("/etc", &etc_alias).expect("create etc ancestor symlink");
        let etc_alias_err = SqliteStore::connect_and_migrate(&format!(
            "sqlite://{}/sentinel.db",
            etc_alias.display()
        ))
        .await
        .expect_err("ancestor symlink to /etc must be rejected");
        assert!(matches!(
            etc_alias_err,
            DomainError::ForbiddenSystemDirectory(_)
        ));

        let root_alias = temp.path().join("root_alias");
        symlink("/", &root_alias).expect("create root ancestor symlink");
        let root_etc_err = SqliteStore::connect_and_migrate(&format!(
            "sqlite://{}/etc/sentinel.db",
            root_alias.display()
        ))
        .await
        .expect_err("ancestor symlink via / to /etc must be rejected");
        assert!(matches!(
            root_etc_err,
            DomainError::ForbiddenSystemDirectory(_)
        ));
    }
}

#[tokio::test]
async fn sqlite_store_enforces_hardened_memory_mode_and_path_hygiene() {
    for valid_mem in [
        ":memory:",
        "sqlite::memory:",
        "sqlite://:memory:",
        "sqlite:///ignored.db?mode=memory",
    ] {
        let store = SqliteStore::connect_and_migrate(valid_mem)
            .await
            .expect("valid in-memory URL should connect");
        assert!(
            store
                .list_recent_reports(5)
                .await
                .expect("query empty reports")
                .is_empty()
        );
    }

    for forbidden_mem in [
        "sqlite:///etc/sentinel.db?mode=memory",
        "sqlite:///root/sentinel.db?mode=memory",
        "sqlite:///usr/sentinel.db?mode=memory",
        "sqlite:///?mode=memory",
    ] {
        let err = SqliteStore::connect_and_migrate(forbidden_mem)
            .await
            .expect_err("forbidden OS dir with ?mode=memory must be rejected");
        assert!(
            matches!(err, DomainError::ForbiddenSystemDirectory(_)),
            "expected ForbiddenSystemDirectory for {forbidden_mem:?}, got {err:?}"
        );
    }

    for traversal_mem in [
        "sqlite:///tmp/../etc/sentinel.db?mode=memory",
        "sqlite://../ignored.db?mode=memory",
        "sqlite:///tmp\\..\\etc\\sentinel.db",
    ] {
        let err = SqliteStore::connect_and_migrate(traversal_mem)
            .await
            .expect_err("traversal URL must be rejected even with ?mode=memory");
        assert!(
            matches!(err, DomainError::PathTraversalAttempt(_)),
            "expected PathTraversalAttempt for {traversal_mem:?}, got {err:?}"
        );
    }

    for invalid_hygiene in [
        "sqlite:///tmp/./sentinel.db",
        "sqlite:///tmp/./ignored.db?mode=memory",
        "sqlite://./sentinel.db",
        "sqlite:///tmp\\.\\sentinel.db",
        "sqlite:///tmp/.hidden.db",
        "sqlite:///tmp/bad\nname.db",
        "sqlite:///tmp/ignored.db?mode=memory\t",
    ] {
        let err = SqliteStore::connect_and_migrate(invalid_hygiene)
            .await
            .expect_err("relative '.', backslash, hidden name, and control chars must be rejected");
        assert!(
            matches!(err, DomainError::InvalidPath(_)),
            "expected InvalidPath for {invalid_hygiene:?}, got {err:?}"
        );
    }

    for bad_mode in [
        "?mode=memory",
        "sqlite://?mode=memory",
        "sqlite:///tmp/test.db?mode=rwc&mode=memory",
        "sqlite:///tmp/test.db?mode=memory&mode=rwc",
        "sqlite:///tmp/test.db?mode=ro",
        "sqlite:///tmp/test.db?mode=",
        "sqlite:///tmp/test.db?mode",
        "sqlite://:memory:?mode=rwc",
    ] {
        let err = SqliteStore::connect_and_migrate(bad_mode)
            .await
            .expect_err("contradictory or unsupported mode query must be rejected");
        assert!(
            matches!(err, DomainError::StorageError(_)),
            "expected StorageError for {bad_mode:?}, got {err:?}"
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn sqlite_store_hardens_preexisting_permissive_db_and_wal_before_open_and_rejects_fifos() {
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    let temp = tempdir().expect("tempdir");

    // 1. Pre-existing permissive (0o644) .db and -wal/-shm files must be hardened to 0o600
    // before SQLite opens them (verified even when SQLite fails on corrupt content).
    let corrupt_db = temp.path().join("corrupt_preexisting.db");
    let corrupt_wal = PathBuf::from(format!("{}-wal", corrupt_db.display()));
    let corrupt_shm = PathBuf::from(format!("{}-shm", corrupt_db.display()));
    std::fs::write(&corrupt_db, b"NOT SQLITE").expect("write corrupt db");
    std::fs::write(&corrupt_wal, b"corrupt wal").expect("write corrupt wal");
    std::fs::write(&corrupt_shm, b"corrupt shm").expect("write corrupt shm");
    for path in [&corrupt_db, &corrupt_wal, &corrupt_shm] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))
            .expect("set permissive 0o644 mode");
    }

    let corrupt_err =
        SqliteStore::connect_and_migrate(&format!("sqlite://{}", corrupt_db.display()))
            .await
            .expect_err("corrupt db must fail migration");
    assert!(matches!(corrupt_err, DomainError::StorageError(_)));

    let corrupt_db_meta =
        std::fs::symlink_metadata(&corrupt_db).expect("corrupt_db must exist after pre-open");
    assert!(
        !corrupt_db_meta.file_type().is_symlink(),
        "corrupt_db must not be a symlink"
    );
    assert_eq!(
        corrupt_db_meta.permissions().mode() & 0o777,
        0o600,
        "corrupt_db must be hardened to 0o600 prior to SQLite open failure"
    );

    for sidecar in [&corrupt_wal, &corrupt_shm] {
        match std::fs::symlink_metadata(sidecar) {
            Ok(meta) => {
                assert!(
                    !meta.file_type().is_symlink(),
                    "corrupt sidecar {} must not be a symlink",
                    sidecar.display()
                );
                assert_eq!(
                    meta.permissions().mode() & 0o777,
                    0o600,
                    "corrupt sidecar {} must be hardened to 0o600 if still present",
                    sidecar.display()
                );
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => panic!(
                "unexpected metadata error inspecting {}: {err}",
                sidecar.display()
            ),
        }
    }

    // 2. Valid migrated .db whose permissions drifted to 0o644 (with permissive leftover -wal)
    // must be hardened to 0o600 on reopen and stay 0o600 after writes.
    let valid_db = temp.path().join("drifted_valid.db");
    let valid_url = format!("sqlite://{}?mode=rwc", valid_db.display());
    {
        let store = SqliteStore::connect_and_migrate(&valid_url)
            .await
            .expect("initial valid connect");
        store
            .save_report(&InspectionReport {
                id: None,
                artifact: FileArtifact {
                    path: PathBuf::from("/quarantine/initial.pdf"),
                    sanitized_name: "initial.pdf".to_string(),
                    extension: Some("pdf".to_string()),
                    size_bytes: 128,
                    sha256_hash: "a".repeat(64),
                    detected_mime: Some("application/pdf".to_string()),
                },
                verdict: SecurityVerdict::Clean,
                destination_path: Some(PathBuf::from("/approved/initial.pdf")),
                inspected_at: Utc::now(),
            })
            .await
            .expect("initial write");
        store.close().await.expect("close initial store");
    }
    std::fs::set_permissions(&valid_db, std::fs::Permissions::from_mode(0o644))
        .expect("simulate permissive 0o644 drift on valid db");
    let valid_wal = PathBuf::from(format!("{}-wal", valid_db.display()));
    if !valid_wal.exists() {
        std::fs::write(&valid_wal, b"").expect("create deterministic leftover -wal");
    }
    std::fs::set_permissions(&valid_wal, std::fs::Permissions::from_mode(0o644))
        .expect("simulate permissive 0o644 drift on valid wal");

    let reopened = SqliteStore::connect_and_migrate(&valid_url)
        .await
        .expect("reopen drifted valid db");
    reopened
        .save_report(&InspectionReport {
            id: None,
            artifact: FileArtifact {
                path: PathBuf::from("/quarantine/after_reopen.pdf"),
                sanitized_name: "after_reopen.pdf".to_string(),
                extension: Some("pdf".to_string()),
                size_bytes: 256,
                sha256_hash: "b".repeat(64),
                detected_mime: Some("application/pdf".to_string()),
            },
            verdict: SecurityVerdict::Clean,
            destination_path: Some(PathBuf::from("/approved/after_reopen.pdf")),
            inspected_at: Utc::now(),
        })
        .await
        .expect("write after reopen");
    assert_sqlite_wal_files_mode_0600(&valid_db, "reopened_drifted_valid_db");
    reopened.close().await.expect("close reopened store");

    // 3. Non-regular files (FIFO) on .db or -wal/-shm sidecars must be rejected before open.
    let fifo_db = temp.path().join("named_pipe.db");
    let status = Command::new("mkfifo")
        .arg(&fifo_db)
        .status()
        .expect("create fifo db");
    assert!(status.success(), "mkfifo must succeed");
    let fifo_db_err = SqliteStore::connect_and_migrate(&format!("sqlite://{}", fifo_db.display()))
        .await
        .expect_err("FIFO database path must be rejected");
    assert!(matches!(fifo_db_err, DomainError::StorageError(_)));

    for suffix in ["-wal", "-shm"] {
        let host_db = temp
            .path()
            .join(format!("fifo_sidecar_{}.db", &suffix[1..]));
        let fifo_sidecar = PathBuf::from(format!("{}{}", host_db.display(), suffix));
        let sidecar_status = Command::new("mkfifo")
            .arg(&fifo_sidecar)
            .status()
            .expect("create fifo sidecar");
        assert!(sidecar_status.success(), "mkfifo sidecar must succeed");
        let sidecar_err =
            SqliteStore::connect_and_migrate(&format!("sqlite://{}", host_db.display()))
                .await
                .expect_err("FIFO sidecar must be rejected");
        assert!(
            matches!(sidecar_err, DomainError::StorageError(_)),
            "expected StorageError for FIFO {suffix}, got {sidecar_err:?}"
        );
    }
}
