//! End-to-end integration tests for Milestone 1 (`feat/m1-project-setup`).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use chrono::{Duration as ChronoDuration, Utc};
use secrecy::ExposeSecret;
use sqlx::Row;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use tempfile::tempdir;
use tokio::sync::{RwLock, watch};

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

    // Verify directly via SqliteConnectOptions that system_config contains 1 row with updated paths.
    let inspect_opts = SqliteConnectOptions::new()
        .filename(&db_path)
        .create_if_missing(false);
    let raw_pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(inspect_opts)
        .await
        .expect("connect with SqliteConnectOptions");

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM system_config")
        .fetch_one(&raw_pool)
        .await
        .expect("count system_config rows");
    assert_eq!(count, 1);

    let row = sqlx::query("SELECT quarantine_dir, approved_dir FROM system_config WHERE id = 1")
        .fetch_one(&raw_pool)
        .await
        .expect("fetch id=1 system_config row");
    let db_q: String = row
        .try_get("quarantine_dir")
        .expect("quarantine_dir column");
    let db_a: String = row.try_get("approved_dir").expect("approved_dir column");
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
