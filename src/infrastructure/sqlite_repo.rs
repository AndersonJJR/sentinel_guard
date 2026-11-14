//! SQLite persistence adapter implementing [`ConfigStore`] and [`QuarantineRepo`].

use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteRow};
use sqlx::{Row, SqlitePool};

use crate::domain::entities::{FileArtifact, InspectionReport, RuntimeConfig, SecurityVerdict};
use crate::domain::errors::DomainError;
use crate::domain::ports::{ConfigStore, QuarantineRepo};

/// SQLite-backed repository for runtime configuration and quarantine inspection logs.
#[derive(Debug, Clone)]
pub struct SqliteStore {
    pool: SqlitePool,
}

#[derive(Debug, Serialize, Deserialize)]
struct SpoofingDetail {
    expected_ext: String,
    actual_mime: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SignatureDetail {
    threat_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct NetworkCorrelationDetail {
    alert_signature: String,
    src_ip: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CorruptedDetail {
    reason: String,
}

impl SqliteStore {
    /// Connects to the SQLite database at `database_url`, creates it if missing, and runs migrations.
    pub async fn connect_and_migrate(database_url: &str) -> Result<Self, DomainError> {
        let is_memory = is_in_memory_url(database_url);
        let mut options = SqliteConnectOptions::from_str(database_url)
            .map_err(map_storage_err)?
            .create_if_missing(true)
            .busy_timeout(Duration::from_secs(5));

        if !is_memory {
            options = options.journal_mode(SqliteJournalMode::Wal);
        }

        let db_file_path = (!is_memory).then(|| options.get_filename().to_path_buf());
        let max_connections = if is_memory { 1 } else { 5 };
        let pool = SqlitePoolOptions::new()
            .max_connections(max_connections)
            .connect_with(options)
            .await
            .map_err(map_storage_err)?;

        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .map_err(map_storage_err)?;

        if let Some(db_path) = db_file_path {
            tokio::task::spawn_blocking(move || harden_sqlite_file_permissions(&db_path))
                .await
                .map_err(map_storage_err)??;
        }

        Ok(Self { pool })
    }
}

#[async_trait]
impl ConfigStore for SqliteStore {
    async fn load_or_seed(&self, defaults: &RuntimeConfig) -> Result<RuntimeConfig, DomainError> {
        if let Some(existing) = self.fetch_config().await? {
            return Ok(existing);
        }

        let quarantine_dir = path_to_str(&defaults.quarantine_dir)?;
        let approved_dir = path_to_str(&defaults.approved_dir)?;
        let clamd_socket_path = path_to_str(&defaults.clamd_socket_path)?;
        let suricata_eve_path = path_to_str(&defaults.suricata_eve_path)?;
        let updated_at = defaults.updated_at.to_rfc3339();

        sqlx::query(
            r#"
            INSERT OR IGNORE INTO system_config (
                id, quarantine_dir, approved_dir, clamd_socket_path, suricata_eve_path, updated_at
            ) VALUES (1, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(quarantine_dir)
        .bind(approved_dir)
        .bind(clamd_socket_path)
        .bind(suricata_eve_path)
        .bind(&updated_at)
        .execute(&self.pool)
        .await
        .map_err(map_storage_err)?;

        self.fetch_config().await?.ok_or_else(|| {
            DomainError::StorageError("Failed to seed system_config row".to_string())
        })
    }

    async fn save_config(&self, config: &RuntimeConfig) -> Result<(), DomainError> {
        let quarantine_dir = path_to_str(&config.quarantine_dir)?;
        let approved_dir = path_to_str(&config.approved_dir)?;
        let clamd_socket_path = path_to_str(&config.clamd_socket_path)?;
        let suricata_eve_path = path_to_str(&config.suricata_eve_path)?;
        let updated_at = config.updated_at.to_rfc3339();

        sqlx::query(
            r#"
            INSERT INTO system_config (
                id, quarantine_dir, approved_dir, clamd_socket_path, suricata_eve_path, updated_at
            ) VALUES (1, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                quarantine_dir = excluded.quarantine_dir,
                approved_dir = excluded.approved_dir,
                clamd_socket_path = excluded.clamd_socket_path,
                suricata_eve_path = excluded.suricata_eve_path,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(quarantine_dir)
        .bind(approved_dir)
        .bind(clamd_socket_path)
        .bind(suricata_eve_path)
        .bind(&updated_at)
        .execute(&self.pool)
        .await
        .map_err(map_storage_err)?;

        Ok(())
    }
}

#[async_trait]
impl QuarantineRepo for SqliteStore {
    async fn save_report(&self, report: &InspectionReport) -> Result<i64, DomainError> {
        let source_path = path_to_str(&report.artifact.path)?;
        let destination_path = report
            .destination_path
            .as_deref()
            .map(path_to_str)
            .transpose()?;
        let size_bytes = i64::try_from(report.artifact.size_bytes).map_err(|err| {
            DomainError::StorageError(format!("File size exceeds SQLite INTEGER range: {err}"))
        })?;
        let (verdict_type, verdict_detail) = encode_verdict(&report.verdict)?;
        let inspected_at = report.inspected_at.to_rfc3339();

        let result = sqlx::query(
            r#"
            INSERT INTO quarantine_logs (
                file_name, source_path, destination_path, sha256_hash,
                size_bytes, detected_mime, verdict_type, verdict_detail, inspected_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&report.artifact.sanitized_name)
        .bind(source_path)
        .bind(destination_path)
        .bind(&report.artifact.sha256_hash)
        .bind(size_bytes)
        .bind(report.artifact.detected_mime.as_deref())
        .bind(verdict_type)
        .bind(verdict_detail.as_deref())
        .bind(&inspected_at)
        .execute(&self.pool)
        .await
        .map_err(map_storage_err)?;

        Ok(result.last_insert_rowid())
    }

    async fn list_recent_reports(&self, limit: u32) -> Result<Vec<InspectionReport>, DomainError> {
        let rows = sqlx::query(
            r#"
            SELECT id, file_name, source_path, destination_path, sha256_hash,
                   size_bytes, detected_mime, verdict_type, verdict_detail, inspected_at
            FROM quarantine_logs
            ORDER BY inspected_at DESC, id DESC
            LIMIT ?
            "#,
        )
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(map_storage_err)?;

        rows.iter().map(row_to_inspection_report).collect()
    }
}

impl SqliteStore {
    async fn fetch_config(&self) -> Result<Option<RuntimeConfig>, DomainError> {
        let row = sqlx::query(
            r#"
            SELECT quarantine_dir, approved_dir, clamd_socket_path, suricata_eve_path, updated_at
            FROM system_config
            WHERE id = 1
            "#,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_storage_err)?;

        row.as_ref().map(row_to_runtime_config).transpose()
    }
}

fn is_in_memory_url(database_url: &str) -> bool {
    if database_url.contains(":memory:") {
        return true;
    }
    if let Some((_, query)) = database_url.split_once('?') {
        return query.split('&').any(|pair| pair == "mode=memory");
    }
    false
}

#[cfg(unix)]
fn harden_sqlite_file_permissions(db_path: &Path) -> Result<(), DomainError> {
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt;

    let mut wal_os = OsString::from(db_path.as_os_str());
    wal_os.push("-wal");
    let wal_path = PathBuf::from(wal_os);

    let mut shm_os = OsString::from(db_path.as_os_str());
    shm_os.push("-shm");
    let shm_path = PathBuf::from(shm_os);

    for path in [db_path, wal_path.as_path(), shm_path.as_path()] {
        if path.exists() {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(map_storage_err)?;
        }
    }

    Ok(())
}

#[cfg(not(unix))]
fn harden_sqlite_file_permissions(_db_path: &Path) -> Result<(), DomainError> {
    Ok(())
}

fn map_storage_err(err: impl std::fmt::Display) -> DomainError {
    DomainError::StorageError(err.to_string())
}

fn path_to_str(path: &Path) -> Result<&str, DomainError> {
    path.to_str().ok_or_else(|| {
        DomainError::InvalidPath(format!(
            "Path contains invalid UTF-8 characters: {}",
            path.display()
        ))
    })
}

fn parse_utc_timestamp(raw: &str) -> Result<DateTime<Utc>, DomainError> {
    DateTime::parse_from_rfc3339(raw)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|err| {
            DomainError::StorageError(format!("Invalid RFC3339 timestamp '{raw}': {err}"))
        })
}

fn row_to_runtime_config(row: &SqliteRow) -> Result<RuntimeConfig, DomainError> {
    let quarantine_dir: String = row.try_get("quarantine_dir").map_err(map_storage_err)?;
    let approved_dir: String = row.try_get("approved_dir").map_err(map_storage_err)?;
    let clamd_socket_path: String = row.try_get("clamd_socket_path").map_err(map_storage_err)?;
    let suricata_eve_path: String = row.try_get("suricata_eve_path").map_err(map_storage_err)?;
    let updated_at_raw: String = row.try_get("updated_at").map_err(map_storage_err)?;

    Ok(RuntimeConfig {
        quarantine_dir: PathBuf::from(quarantine_dir),
        approved_dir: PathBuf::from(approved_dir),
        clamd_socket_path: PathBuf::from(clamd_socket_path),
        suricata_eve_path: PathBuf::from(suricata_eve_path),
        updated_at: parse_utc_timestamp(&updated_at_raw)?,
    })
}

fn encode_verdict(
    verdict: &SecurityVerdict,
) -> Result<(&'static str, Option<String>), DomainError> {
    match verdict {
        SecurityVerdict::Clean => Ok(("Clean", None)),
        SecurityVerdict::MaliciousSpoofing {
            expected_ext,
            actual_mime,
        } => {
            let detail = serde_json::to_string(&SpoofingDetail {
                expected_ext: expected_ext.clone(),
                actual_mime: actual_mime.clone(),
            })
            .map_err(map_storage_err)?;
            Ok(("MaliciousSpoofing", Some(detail)))
        }
        SecurityVerdict::MaliciousSignature { threat_name } => {
            let detail = serde_json::to_string(&SignatureDetail {
                threat_name: threat_name.clone(),
            })
            .map_err(map_storage_err)?;
            Ok(("MaliciousSignature", Some(detail)))
        }
        SecurityVerdict::SuspiciousNetworkCorrelation {
            alert_signature,
            src_ip,
        } => {
            let detail = serde_json::to_string(&NetworkCorrelationDetail {
                alert_signature: alert_signature.clone(),
                src_ip: src_ip.clone(),
            })
            .map_err(map_storage_err)?;
            Ok(("SuspiciousNetworkCorrelation", Some(detail)))
        }
        SecurityVerdict::CorruptedOrUnreadable { reason } => {
            let detail = serde_json::to_string(&CorruptedDetail {
                reason: reason.clone(),
            })
            .map_err(map_storage_err)?;
            Ok(("CorruptedOrUnreadable", Some(detail)))
        }
    }
}

fn decode_verdict(
    verdict_type: &str,
    verdict_detail: Option<&str>,
) -> Result<SecurityVerdict, DomainError> {
    match verdict_type {
        "Clean" | "clean" => Ok(SecurityVerdict::Clean),
        "MaliciousSpoofing" | "malicious_spoofing" => {
            let raw = require_verdict_detail(verdict_type, verdict_detail)?;
            let parsed: SpoofingDetail = serde_json::from_str(raw).map_err(map_storage_err)?;
            Ok(SecurityVerdict::MaliciousSpoofing {
                expected_ext: parsed.expected_ext,
                actual_mime: parsed.actual_mime,
            })
        }
        "MaliciousSignature" | "malicious_signature" => {
            let raw = require_verdict_detail(verdict_type, verdict_detail)?;
            let parsed: SignatureDetail = serde_json::from_str(raw).map_err(map_storage_err)?;
            Ok(SecurityVerdict::MaliciousSignature {
                threat_name: parsed.threat_name,
            })
        }
        "SuspiciousNetworkCorrelation" | "suspicious_network_correlation" => {
            let raw = require_verdict_detail(verdict_type, verdict_detail)?;
            let parsed: NetworkCorrelationDetail =
                serde_json::from_str(raw).map_err(map_storage_err)?;
            Ok(SecurityVerdict::SuspiciousNetworkCorrelation {
                alert_signature: parsed.alert_signature,
                src_ip: parsed.src_ip,
            })
        }
        "CorruptedOrUnreadable" | "corrupted_or_unreadable" => {
            let raw = require_verdict_detail(verdict_type, verdict_detail)?;
            let parsed: CorruptedDetail = serde_json::from_str(raw).map_err(map_storage_err)?;
            Ok(SecurityVerdict::CorruptedOrUnreadable {
                reason: parsed.reason,
            })
        }
        other => Err(DomainError::StorageError(format!(
            "Unknown security verdict_type in database: '{other}'"
        ))),
    }
}

fn require_verdict_detail<'a>(
    verdict_type: &str,
    verdict_detail: Option<&'a str>,
) -> Result<&'a str, DomainError> {
    verdict_detail.ok_or_else(|| {
        DomainError::StorageError(format!(
            "Missing verdict_detail for verdict_type '{verdict_type}'"
        ))
    })
}

fn row_to_inspection_report(row: &SqliteRow) -> Result<InspectionReport, DomainError> {
    let id: i64 = row.try_get("id").map_err(map_storage_err)?;
    let file_name: String = row.try_get("file_name").map_err(map_storage_err)?;
    let source_path_raw: String = row.try_get("source_path").map_err(map_storage_err)?;
    let destination_path_raw: Option<String> =
        row.try_get("destination_path").map_err(map_storage_err)?;
    let sha256_hash: String = row.try_get("sha256_hash").map_err(map_storage_err)?;
    let size_bytes_raw: i64 = row.try_get("size_bytes").map_err(map_storage_err)?;
    let size_bytes = u64::try_from(size_bytes_raw).map_err(|err| {
        DomainError::StorageError(format!("Negative size_bytes value in database: {err}"))
    })?;
    let detected_mime: Option<String> = row.try_get("detected_mime").map_err(map_storage_err)?;
    let verdict_type: String = row.try_get("verdict_type").map_err(map_storage_err)?;
    let verdict_detail: Option<String> = row.try_get("verdict_detail").map_err(map_storage_err)?;
    let inspected_at_raw: String = row.try_get("inspected_at").map_err(map_storage_err)?;

    let extension = Path::new(&file_name)
        .extension()
        .or_else(|| Path::new(&source_path_raw).extension())
        .and_then(|ext| ext.to_str())
        .map(ToString::to_string);

    Ok(InspectionReport {
        id: Some(id),
        artifact: FileArtifact {
            path: PathBuf::from(source_path_raw),
            sanitized_name: file_name,
            extension,
            size_bytes,
            sha256_hash,
            detected_mime,
        },
        verdict: decode_verdict(&verdict_type, verdict_detail.as_deref())?,
        destination_path: destination_path_raw.map(PathBuf::from),
        inspected_at: parse_utc_timestamp(&inspected_at_raw)?,
    })
}

#[cfg(test)]
mod tests {
    use chrono::Duration as ChronoDuration;

    use super::*;

    fn sample_runtime_config(suffix: &str) -> RuntimeConfig {
        RuntimeConfig {
            quarantine_dir: PathBuf::from(format!("/tmp/quarantine_{suffix}")),
            approved_dir: PathBuf::from(format!("/tmp/approved_{suffix}")),
            clamd_socket_path: PathBuf::from("/var/run/clamav/clamd.ctl"),
            suricata_eve_path: PathBuf::from("/var/log/suricata/eve.json"),
            updated_at: Utc::now(),
        }
    }

    fn sample_report(
        name: &str,
        verdict: SecurityVerdict,
        inspected_at: DateTime<Utc>,
    ) -> InspectionReport {
        InspectionReport {
            id: None,
            artifact: FileArtifact {
                path: PathBuf::from(format!("/quarantine/{name}")),
                sanitized_name: name.to_string(),
                extension: Path::new(name)
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(ToString::to_string),
                size_bytes: 1024,
                sha256_hash: "a".repeat(64),
                detected_mime: Some("application/octet-stream".to_string()),
            },
            verdict,
            destination_path: Some(PathBuf::from(format!("/isolated/{name}"))),
            inspected_at,
        }
    }

    #[tokio::test]
    async fn load_or_seed_seeds_first_time_and_returns_persisted_thereafter() {
        let store = SqliteStore::connect_and_migrate("sqlite::memory:")
            .await
            .expect("in-memory sqlite migration should succeed");

        let defaults = sample_runtime_config("initial");
        let loaded = store
            .load_or_seed(&defaults)
            .await
            .expect("initial seed should succeed");
        assert_eq!(loaded, defaults);

        let different_defaults = sample_runtime_config("ignored");
        let loaded_again = store
            .load_or_seed(&different_defaults)
            .await
            .expect("existing config should be returned");
        assert_eq!(loaded_again, defaults);

        let updated = sample_runtime_config("updated");
        store
            .save_config(&updated)
            .await
            .expect("save_config should overwrite existing row");
        let after_update = store
            .load_or_seed(&different_defaults)
            .await
            .expect("updated config should load");
        assert_eq!(after_update, updated);
    }

    #[tokio::test]
    async fn connect_and_migrate_creates_file_database_and_persists_across_reopen() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("sentinel_test.db");
        let db_url = format!("sqlite://{}", db_path.display());

        let initial = sample_runtime_config("persisted");
        {
            let store = SqliteStore::connect_and_migrate(&db_url)
                .await
                .expect("file sqlite migration should succeed");

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let db_mode = std::fs::metadata(&db_path)
                    .expect("db file metadata")
                    .permissions()
                    .mode()
                    & 0o777;
                assert_eq!(db_mode, 0o600, "sqlite file must have 0o600 permissions");

                for suffix in ["-wal", "-shm"] {
                    let aux_path = PathBuf::from(format!("{}{}", db_path.display(), suffix));
                    if aux_path.exists() {
                        let aux_mode = std::fs::metadata(&aux_path)
                            .expect("aux db file metadata")
                            .permissions()
                            .mode()
                            & 0o777;
                        assert_eq!(
                            aux_mode, 0o600,
                            "sqlite auxiliary file {suffix} must have 0o600 permissions"
                        );
                    }
                }
            }

            let loaded = store
                .load_or_seed(&initial)
                .await
                .expect("initial seed should succeed");
            assert_eq!(loaded, initial);
        }

        let reopened = SqliteStore::connect_and_migrate(&db_url)
            .await
            .expect("reopening migrated file sqlite should succeed");
        let other = sample_runtime_config("other");
        let loaded_after_reopen = reopened
            .load_or_seed(&other)
            .await
            .expect("should return previously persisted config");
        assert_eq!(loaded_after_reopen, initial);
    }

    #[tokio::test]
    async fn second_boot_preserves_modified_config_and_ignores_new_env_defaults() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("second_boot.db");
        let db_url = format!("sqlite://{}", db_path.display());

        let boot1_env_defaults = sample_runtime_config("boot1_env");
        let dynamically_updated = RuntimeConfig {
            quarantine_dir: PathBuf::from("/mnt/custom_quarantine"),
            approved_dir: PathBuf::from("/mnt/custom_approved"),
            clamd_socket_path: PathBuf::from("/tmp/custom_clamd.ctl"),
            suricata_eve_path: PathBuf::from("/tmp/custom_eve.json"),
            updated_at: Utc::now() + ChronoDuration::seconds(30),
        };

        // Boot 1: seed from .env defaults, then save user-updated config.
        {
            let store = SqliteStore::connect_and_migrate(&db_url)
                .await
                .expect("boot 1 migration should succeed");
            let seeded = store
                .load_or_seed(&boot1_env_defaults)
                .await
                .expect("boot 1 seed should succeed");
            assert_eq!(seeded, boot1_env_defaults);

            store
                .save_config(&dynamically_updated)
                .await
                .expect("saving modified config should succeed");
        }

        // Boot 2: reopen DB and pass different .env defaults; DB row must win.
        let boot2_env_defaults = sample_runtime_config("boot2_env_should_not_override");
        let store_boot2 = SqliteStore::connect_and_migrate(&db_url)
            .await
            .expect("boot 2 migration should succeed");
        let loaded = store_boot2
            .load_or_seed(&boot2_env_defaults)
            .await
            .expect("boot 2 load_or_seed should succeed");
        assert_eq!(loaded, dynamically_updated);
    }

    #[tokio::test]
    async fn save_and_list_recent_reports_round_trips_all_verdicts() {
        let store = SqliteStore::connect_and_migrate("sqlite::memory:")
            .await
            .expect("in-memory sqlite migration should succeed");

        let base_time = Utc::now();
        let verdicts = [
            SecurityVerdict::Clean,
            SecurityVerdict::MaliciousSpoofing {
                expected_ext: "pdf".to_string(),
                actual_mime: "application/x-executable".to_string(),
            },
            SecurityVerdict::MaliciousSignature {
                threat_name: "Win.Test.EICAR_HDB-1".to_string(),
            },
            SecurityVerdict::SuspiciousNetworkCorrelation {
                alert_signature: "ET MALWARE Suspicious Payload".to_string(),
                src_ip: "10.8.0.42".to_string(),
            },
            SecurityVerdict::CorruptedOrUnreadable {
                reason: "Permission denied reading header".to_string(),
            },
        ];

        let mut inserted_ids = Vec::with_capacity(verdicts.len());
        for (idx, verdict) in verdicts.iter().enumerate() {
            let report = InspectionReport {
                id: None,
                artifact: FileArtifact {
                    path: PathBuf::from(format!("/quarantine/file_{idx}.pdf")),
                    sanitized_name: format!("file_{idx}.pdf"),
                    extension: Some("pdf".to_string()),
                    size_bytes: 65536 * (idx as u64 + 1),
                    sha256_hash: format!("{idx:064x}"),
                    detected_mime: Some("application/pdf".to_string()),
                },
                verdict: verdict.clone(),
                destination_path: Some(PathBuf::from(format!("/approved/file_{idx}.pdf"))),
                inspected_at: base_time + ChronoDuration::seconds(idx as i64),
            };

            let row_id = store
                .save_report(&report)
                .await
                .expect("report insert should succeed");
            assert!(row_id > 0);
            inserted_ids.push(row_id);
        }

        let recent = store
            .list_recent_reports(3)
            .await
            .expect("listing recent reports should succeed");
        assert_eq!(recent.len(), 3);
        assert_eq!(recent[0].id, Some(inserted_ids[4]));
        assert_eq!(recent[0].verdict, verdicts[4]);
        assert_eq!(recent[1].id, Some(inserted_ids[3]));
        assert_eq!(recent[1].verdict, verdicts[3]);
        assert_eq!(recent[2].id, Some(inserted_ids[2]));
        assert_eq!(recent[2].verdict, verdicts[2]);
        assert_eq!(recent[0].artifact.extension.as_deref(), Some("pdf"));

        let all = store
            .list_recent_reports(10)
            .await
            .expect("listing all reports should succeed");
        assert_eq!(all.len(), 5);
        assert_eq!(all[4].verdict, SecurityVerdict::Clean);
    }

    #[tokio::test]
    async fn quarantine_repo_handles_empty_zero_limit_optional_fields_and_tie_ordering() {
        let store = SqliteStore::connect_and_migrate("sqlite::memory:")
            .await
            .expect("in-memory sqlite migration should succeed");

        assert!(
            store
                .list_recent_reports(10)
                .await
                .expect("empty listing should succeed")
                .is_empty()
        );

        let same_time = Utc::now();
        let older_time = same_time - ChronoDuration::seconds(10);

        let empty_file_report = InspectionReport {
            id: None,
            artifact: FileArtifact {
                path: PathBuf::from("/quarantine/README"),
                sanitized_name: "README".to_string(),
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
            inspected_at: older_time,
        };
        let id_old = store
            .save_report(&empty_file_report)
            .await
            .expect("saving report without optional fields should succeed");

        let tie_first = sample_report("first_tie.bin", SecurityVerdict::Clean, same_time);
        let tie_second = sample_report(
            "second_tie.exe",
            SecurityVerdict::MaliciousSignature {
                threat_name: "Trojan.Test".to_string(),
            },
            same_time,
        );
        let id_tie1 = store
            .save_report(&tie_first)
            .await
            .expect("saving first tie report should succeed");
        let id_tie2 = store
            .save_report(&tie_second)
            .await
            .expect("saving second tie report should succeed");

        assert!(
            store
                .list_recent_reports(0)
                .await
                .expect("zero-limit listing should succeed")
                .is_empty()
        );

        let all = store
            .list_recent_reports(50)
            .await
            .expect("listing all reports should succeed");
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].id, Some(id_tie2));
        assert_eq!(all[1].id, Some(id_tie1));
        assert_eq!(all[2].id, Some(id_old));

        assert_eq!(all[2].artifact.size_bytes, 0);
        assert_eq!(all[2].artifact.extension, None);
        assert_eq!(all[2].artifact.detected_mime, None);
        assert_eq!(all[2].destination_path, None);
    }

    #[tokio::test]
    async fn quarantine_repo_rejects_oversized_file_and_invalid_storage_inputs() {
        let store = SqliteStore::connect_and_migrate("sqlite::memory:")
            .await
            .expect("in-memory sqlite migration should succeed");

        let mut oversized = sample_report("huge.iso", SecurityVerdict::Clean, Utc::now());
        oversized.artifact.size_bytes = u64::MAX;
        let err = store
            .save_report(&oversized)
            .await
            .expect_err("u64::MAX size_bytes exceeds SQLite i64 range");
        assert!(matches!(err, DomainError::StorageError(_)));

        let invalid_db =
            SqliteStore::connect_and_migrate("sqlite:///nonexistent_sentinel_dir_999999/test.db")
                .await
                .expect_err("invalid database parent path should fail");
        assert!(matches!(invalid_db, DomainError::StorageError(_)));
    }

    #[test]
    fn verdict_decoder_and_timestamp_parser_validate_variants_and_errors() {
        assert_eq!(
            decode_verdict("clean", None).expect("clean alias"),
            SecurityVerdict::Clean
        );
        assert_eq!(
            decode_verdict(
                "malicious_spoofing",
                Some(r#"{"expected_ext":"jpg","actual_mime":"application/x-dosexec"}"#)
            )
            .expect("spoofing alias"),
            SecurityVerdict::MaliciousSpoofing {
                expected_ext: "jpg".to_string(),
                actual_mime: "application/x-dosexec".to_string(),
            }
        );
        assert_eq!(
            decode_verdict("malicious_signature", Some(r#"{"threat_name":"EICAR"}"#))
                .expect("signature alias"),
            SecurityVerdict::MaliciousSignature {
                threat_name: "EICAR".to_string(),
            }
        );
        assert_eq!(
            decode_verdict(
                "suspicious_network_correlation",
                Some(r#"{"alert_signature":"ET CNC","src_ip":"192.168.1.50"}"#)
            )
            .expect("network correlation alias"),
            SecurityVerdict::SuspiciousNetworkCorrelation {
                alert_signature: "ET CNC".to_string(),
                src_ip: "192.168.1.50".to_string(),
            }
        );
        assert_eq!(
            decode_verdict(
                "corrupted_or_unreadable",
                Some(r#"{"reason":"I/O truncated"}"#)
            )
            .expect("corrupted alias"),
            SecurityVerdict::CorruptedOrUnreadable {
                reason: "I/O truncated".to_string(),
            }
        );

        assert!(matches!(
            decode_verdict("UnknownVerdict", None),
            Err(DomainError::StorageError(_))
        ));
        assert!(matches!(
            decode_verdict("MaliciousSignature", None),
            Err(DomainError::StorageError(_))
        ));
        assert!(matches!(
            decode_verdict("MaliciousSpoofing", Some("not-json")),
            Err(DomainError::StorageError(_))
        ));
        assert!(matches!(
            parse_utc_timestamp("not-a-timestamp"),
            Err(DomainError::StorageError(_))
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn non_utf8_paths_are_rejected_with_invalid_path() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let store = SqliteStore::connect_and_migrate("sqlite::memory:")
            .await
            .expect("in-memory sqlite migration should succeed");

        let invalid_path = PathBuf::from(OsString::from_vec(vec![0x66, 0x6f, 0x80, 0x6f]));
        let mut cfg = sample_runtime_config("utf8");
        cfg.quarantine_dir = invalid_path.clone();

        let cfg_err = store
            .save_config(&cfg)
            .await
            .expect_err("non-UTF-8 path must be rejected");
        assert!(matches!(cfg_err, DomainError::InvalidPath(_)));

        let mut report = sample_report("bad.bin", SecurityVerdict::Clean, Utc::now());
        report.artifact.path = invalid_path;
        let report_err = store
            .save_report(&report)
            .await
            .expect_err("non-UTF-8 report path must be rejected");
        assert!(matches!(report_err, DomainError::InvalidPath(_)));
    }
}
