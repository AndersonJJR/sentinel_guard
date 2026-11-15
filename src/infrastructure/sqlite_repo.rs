//! SQLite persistence adapter implementing [`ConfigStore`] and [`QuarantineRepo`].

use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio_rusqlite::{Connection, OpenFlags, OptionalExtension, params};

use crate::domain::entities::{FileArtifact, InspectionReport, RuntimeConfig, SecurityVerdict};
use crate::domain::errors::DomainError;
use crate::domain::path_policy::reject_forbidden_system_dir;
use crate::domain::ports::{ConfigStore, QuarantineRepo};

const INIT_MIGRATION_SQL: &str = include_str!("../../migrations/20261114000001_init.sql");

/// SQLite-backed repository for runtime configuration and quarantine inspection logs.
#[derive(Debug, Clone)]
pub struct SqliteStore {
    conn: Connection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DatabaseTarget {
    InMemory,
    File(PathBuf),
}

struct RawRuntimeConfig {
    quarantine_dir: String,
    approved_dir: String,
    clamd_socket_path: String,
    suricata_eve_path: String,
    updated_at: String,
}

struct RawInspectionReport {
    id: i64,
    file_name: String,
    source_path: String,
    destination_path: Option<String>,
    sha256_hash: String,
    size_bytes: i64,
    detected_mime: Option<String>,
    verdict_type: String,
    verdict_detail: Option<String>,
    inspected_at: String,
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
        let owned_url = database_url.to_owned();
        let target = tokio::task::spawn_blocking(move || -> Result<DatabaseTarget, DomainError> {
            let target = resolve_database_target(&owned_url)?;
            if let DatabaseTarget::File(ref db_path) = target {
                prepare_sqlite_files_before_open(db_path)?;
            }
            Ok(target)
        })
        .await
        .map_err(map_storage_err)??;

        let (conn, db_file_path) = match target {
            DatabaseTarget::InMemory => {
                let conn = Connection::open_in_memory()
                    .await
                    .map_err(map_storage_err)?;
                (conn, None)
            }
            DatabaseTarget::File(db_path) => {
                let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
                    | OpenFlags::SQLITE_OPEN_CREATE
                    | OpenFlags::SQLITE_OPEN_NO_MUTEX;
                let conn = Connection::open_with_flags(&db_path, flags)
                    .await
                    .map_err(map_storage_err)?;
                (conn, Some(db_path))
            }
        };

        let is_memory = db_file_path.is_none();
        conn.call(move |raw_conn| -> Result<(), DomainError> {
            raw_conn
                .busy_timeout(Duration::from_secs(5))
                .map_err(map_storage_err)?;
            if !is_memory {
                raw_conn
                    .pragma_update(None, "journal_mode", "WAL")
                    .map_err(map_storage_err)?;
            }
            raw_conn
                .execute_batch(INIT_MIGRATION_SQL)
                .map_err(map_storage_err)?;
            Ok(())
        })
        .await
        .map_err(map_call_err)?;

        if let Some(db_path) = db_file_path {
            tokio::task::spawn_blocking(move || harden_sqlite_file_permissions(&db_path))
                .await
                .map_err(map_storage_err)??;
        }

        Ok(Self { conn })
    }
}

#[async_trait]
impl ConfigStore for SqliteStore {
    async fn load_or_seed(&self, defaults: &RuntimeConfig) -> Result<RuntimeConfig, DomainError> {
        if let Some(existing) = self.fetch_config().await? {
            return Ok(existing);
        }

        let quarantine_dir = path_to_str(&defaults.quarantine_dir)?.to_owned();
        let approved_dir = path_to_str(&defaults.approved_dir)?.to_owned();
        let clamd_socket_path = path_to_str(&defaults.clamd_socket_path)?.to_owned();
        let suricata_eve_path = path_to_str(&defaults.suricata_eve_path)?.to_owned();
        let updated_at = defaults.updated_at.to_rfc3339();

        self.conn
            .call(move |raw_conn| -> Result<(), DomainError> {
                raw_conn
                    .execute(
                        r#"
                        INSERT OR IGNORE INTO system_config (
                            id, quarantine_dir, approved_dir, clamd_socket_path, suricata_eve_path, updated_at
                        ) VALUES (1, ?1, ?2, ?3, ?4, ?5)
                        "#,
                        params![
                            quarantine_dir,
                            approved_dir,
                            clamd_socket_path,
                            suricata_eve_path,
                            updated_at,
                        ],
                    )
                    .map_err(map_storage_err)?;
                Ok(())
            })
            .await
            .map_err(map_call_err)?;

        self.fetch_config().await?.ok_or_else(|| {
            DomainError::StorageError("Failed to seed system_config row".to_string())
        })
    }

    async fn save_config(&self, config: &RuntimeConfig) -> Result<(), DomainError> {
        let quarantine_dir = path_to_str(&config.quarantine_dir)?.to_owned();
        let approved_dir = path_to_str(&config.approved_dir)?.to_owned();
        let clamd_socket_path = path_to_str(&config.clamd_socket_path)?.to_owned();
        let suricata_eve_path = path_to_str(&config.suricata_eve_path)?.to_owned();
        let updated_at = config.updated_at.to_rfc3339();

        self.conn
            .call(move |raw_conn| -> Result<(), DomainError> {
                raw_conn
                    .execute(
                        r#"
                        INSERT INTO system_config (
                            id, quarantine_dir, approved_dir, clamd_socket_path, suricata_eve_path, updated_at
                        ) VALUES (1, ?1, ?2, ?3, ?4, ?5)
                        ON CONFLICT(id) DO UPDATE SET
                            quarantine_dir = excluded.quarantine_dir,
                            approved_dir = excluded.approved_dir,
                            clamd_socket_path = excluded.clamd_socket_path,
                            suricata_eve_path = excluded.suricata_eve_path,
                            updated_at = excluded.updated_at
                        "#,
                        params![
                            quarantine_dir,
                            approved_dir,
                            clamd_socket_path,
                            suricata_eve_path,
                            updated_at,
                        ],
                    )
                    .map_err(map_storage_err)?;
                Ok(())
            })
            .await
            .map_err(map_call_err)
    }
}

#[async_trait]
impl QuarantineRepo for SqliteStore {
    async fn save_report(&self, report: &InspectionReport) -> Result<i64, DomainError> {
        let file_name = report.artifact.sanitized_name.clone();
        let source_path = path_to_str(&report.artifact.path)?.to_owned();
        let destination_path = report
            .destination_path
            .as_deref()
            .map(path_to_str)
            .transpose()?
            .map(str::to_owned);
        let sha256_hash = report.artifact.sha256_hash.clone();
        let size_bytes = i64::try_from(report.artifact.size_bytes).map_err(|err| {
            DomainError::StorageError(format!("File size exceeds SQLite INTEGER range: {err}"))
        })?;
        let detected_mime = report.artifact.detected_mime.clone();
        let (verdict_type, verdict_detail) = encode_verdict(&report.verdict)?;
        let inspected_at = report.inspected_at.to_rfc3339();

        self.conn
            .call(move |raw_conn| -> Result<i64, DomainError> {
                raw_conn
                    .execute(
                        r#"
                        INSERT INTO quarantine_logs (
                            file_name, source_path, destination_path, sha256_hash,
                            size_bytes, detected_mime, verdict_type, verdict_detail, inspected_at
                        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                        "#,
                        params![
                            file_name,
                            source_path,
                            destination_path,
                            sha256_hash,
                            size_bytes,
                            detected_mime,
                            verdict_type,
                            verdict_detail,
                            inspected_at,
                        ],
                    )
                    .map_err(map_storage_err)?;

                Ok(raw_conn.last_insert_rowid())
            })
            .await
            .map_err(map_call_err)
    }

    async fn list_recent_reports(&self, limit: u32) -> Result<Vec<InspectionReport>, DomainError> {
        let limit_i64 = i64::from(limit);

        self.conn
            .call(
                move |raw_conn| -> Result<Vec<InspectionReport>, DomainError> {
                    let mut stmt = raw_conn
                        .prepare(
                            r#"
                        SELECT id, file_name, source_path, destination_path, sha256_hash,
                               size_bytes, detected_mime, verdict_type, verdict_detail, inspected_at
                        FROM quarantine_logs
                        ORDER BY inspected_at DESC, id DESC
                        LIMIT ?1
                        "#,
                        )
                        .map_err(map_storage_err)?;

                    let raw_rows = stmt
                        .query_map(params![limit_i64], |row| {
                            Ok(RawInspectionReport {
                                id: row.get("id")?,
                                file_name: row.get("file_name")?,
                                source_path: row.get("source_path")?,
                                destination_path: row.get("destination_path")?,
                                sha256_hash: row.get("sha256_hash")?,
                                size_bytes: row.get("size_bytes")?,
                                detected_mime: row.get("detected_mime")?,
                                verdict_type: row.get("verdict_type")?,
                                verdict_detail: row.get("verdict_detail")?,
                                inspected_at: row.get("inspected_at")?,
                            })
                        })
                        .map_err(map_storage_err)?
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(map_storage_err)?;

                    raw_rows.into_iter().map(raw_to_inspection_report).collect()
                },
            )
            .await
            .map_err(map_call_err)
    }
}

impl SqliteStore {
    async fn fetch_config(&self) -> Result<Option<RuntimeConfig>, DomainError> {
        self.conn
            .call(|raw_conn| -> Result<Option<RuntimeConfig>, DomainError> {
                let mut stmt = raw_conn
                    .prepare(
                        r#"
                        SELECT quarantine_dir, approved_dir, clamd_socket_path, suricata_eve_path, updated_at
                        FROM system_config
                        WHERE id = 1
                        "#,
                    )
                    .map_err(map_storage_err)?;

                let raw_opt = stmt
                    .query_row([], |row| {
                        Ok(RawRuntimeConfig {
                            quarantine_dir: row.get("quarantine_dir")?,
                            approved_dir: row.get("approved_dir")?,
                            clamd_socket_path: row.get("clamd_socket_path")?,
                            suricata_eve_path: row.get("suricata_eve_path")?,
                            updated_at: row.get("updated_at")?,
                        })
                    })
                    .optional()
                    .map_err(map_storage_err)?;

                raw_opt.map(raw_to_runtime_config).transpose()
            })
            .await
            .map_err(map_call_err)
    }
}

fn resolve_database_target(database_url: &str) -> Result<DatabaseTarget, DomainError> {
    if database_url.trim().is_empty() {
        return Err(DomainError::StorageError(
            "Database URL must not be empty".to_string(),
        ));
    }

    if database_url.contains('\0') {
        return Err(DomainError::InvalidPath(
            "Database URL contains null byte".to_string(),
        ));
    }

    if matches!(
        database_url,
        "sqlite::memory:" | "sqlite://:memory:" | ":memory:"
    ) {
        return Ok(DatabaseTarget::InMemory);
    }

    let (base, query_opt) = match database_url.split_once('?') {
        Some((base, query)) => (base, Some(query)),
        None => (database_url, None),
    };

    let parsed_mode = parse_and_validate_query_mode(query_opt)?;

    if matches!(base, "sqlite::memory:" | "sqlite://:memory:" | ":memory:") {
        if parsed_mode == Some("memory") {
            return Ok(DatabaseTarget::InMemory);
        }
        return Err(DomainError::StorageError(
            "Contradictory query parameters for ':memory:' database URL".to_string(),
        ));
    }

    let raw_path = base
        .strip_prefix("sqlite://")
        .or_else(|| base.strip_prefix("sqlite:"))
        .unwrap_or(base);

    validate_database_path_hygiene(raw_path)?;

    if parsed_mode == Some("memory") {
        return Ok(DatabaseTarget::InMemory);
    }

    let db_path = Path::new(raw_path);
    let file_name = db_path.file_name().ok_or_else(|| {
        DomainError::StorageError(format!(
            "Database URL path does not include a file name: {}",
            db_path.display()
        ))
    })?;

    let raw_parent = db_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    let canonical_parent = match std::fs::canonicalize(raw_parent) {
        Ok(canonical) => canonical,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            return Err(DomainError::StorageError(format!(
                "Database parent directory does not exist: {}",
                raw_parent.display()
            )));
        }
        Err(err) => return Err(map_storage_err(err)),
    };

    reject_forbidden_system_dir(&canonical_parent)?;

    let parent_meta = std::fs::metadata(&canonical_parent).map_err(map_storage_err)?;
    if !parent_meta.is_dir() {
        return Err(DomainError::StorageError(format!(
            "Database parent path is not a directory: {}",
            canonical_parent.display()
        )));
    }

    let resolved_path = canonical_parent.join(file_name);
    reject_forbidden_system_dir(&resolved_path)?;

    ensure_not_symlink_or_non_regular(&resolved_path)?;
    for sidecar_path in sqlite_sidecar_paths(&resolved_path) {
        ensure_not_symlink_or_non_regular(&sidecar_path)?;
    }

    Ok(DatabaseTarget::File(resolved_path))
}

fn parse_and_validate_query_mode(query_opt: Option<&str>) -> Result<Option<&str>, DomainError> {
    let Some(query) = query_opt else {
        return Ok(None);
    };

    if query
        .chars()
        .any(|ch| ch.is_ascii_control() || ch.is_control())
    {
        return Err(DomainError::InvalidPath(
            "Database URL query contains control characters".to_string(),
        ));
    }

    let mut parsed_mode: Option<&str> = None;
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let Some((key, value)) = pair.split_once('=') else {
            if pair == "mode" {
                return Err(DomainError::StorageError(
                    "Malformed 'mode' query parameter in database URL".to_string(),
                ));
            }
            continue;
        };

        if key == "mode" {
            if !matches!(value, "memory" | "rwc" | "rw") {
                return Err(DomainError::StorageError(format!(
                    "Unsupported SQLite 'mode' query value '{value}'"
                )));
            }
            if let Some(prev) = parsed_mode
                && prev != value
            {
                return Err(DomainError::StorageError(format!(
                    "Contradictory 'mode' query parameters in database URL: '{prev}' vs '{value}'"
                )));
            }
            parsed_mode = Some(value);
        }
    }

    Ok(parsed_mode)
}

fn validate_database_path_hygiene(raw_path: &str) -> Result<(), DomainError> {
    if raw_path.trim().is_empty() {
        return Err(DomainError::StorageError(
            "Database URL path must not be empty".to_string(),
        ));
    }

    if raw_path
        .chars()
        .any(|ch| ch.is_ascii_control() || ch.is_control())
    {
        return Err(DomainError::InvalidPath(format!(
            "Database URL path contains control characters: {raw_path}"
        )));
    }

    if raw_path.split(['/', '\\']).any(|segment| segment == "..") {
        return Err(DomainError::PathTraversalAttempt(format!(
            "Parent directory traversal ('..') is not allowed in database URL: {raw_path}"
        )));
    }

    let db_path = Path::new(raw_path);
    for component in db_path.components() {
        if matches!(component, Component::ParentDir) {
            return Err(DomainError::PathTraversalAttempt(format!(
                "Parent directory traversal ('..') is not allowed in database URL: {}",
                db_path.display()
            )));
        }
    }

    reject_forbidden_system_dir(db_path)?;

    if raw_path.contains('\\')
        || raw_path == "."
        || raw_path.starts_with("./")
        || raw_path.contains("/./")
        || raw_path.ends_with("/.")
    {
        return Err(DomainError::InvalidPath(format!(
            "Database URL path must not contain relative '.' markers or backslashes: {raw_path}"
        )));
    }

    if raw_path.ends_with('/') {
        return Err(DomainError::StorageError(format!(
            "Database URL must target a file rather than a directory: {}",
            db_path.display()
        )));
    }

    let file_name = db_path.file_name().ok_or_else(|| {
        DomainError::StorageError(format!(
            "Database URL path does not include a file name: {}",
            db_path.display()
        ))
    })?;

    let file_name_str = path_to_str(Path::new(file_name))?;
    if file_name_str == "."
        || file_name_str == ".."
        || file_name_str.starts_with('.')
        || file_name_str
            .chars()
            .any(|ch| ch.is_ascii_control() || ch.is_control())
    {
        return Err(DomainError::InvalidPath(format!(
            "Invalid database file name '{file_name_str}' in URL: {raw_path}"
        )));
    }

    Ok(())
}

fn ensure_not_symlink_or_non_regular(path: &Path) -> Result<(), DomainError> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            Err(DomainError::PathTraversalAttempt(format!(
                "Database file path must not be a symlink: {}",
                path.display()
            )))
        }
        Ok(meta) if !meta.file_type().is_file() => Err(DomainError::StorageError(format!(
            "Database file path is not a regular file: {}",
            path.display()
        ))),
        Ok(_) => Ok(()),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(map_storage_err(err)),
    }
}

fn sqlite_sidecar_paths(db_path: &Path) -> [PathBuf; 2] {
    use std::ffi::OsString;

    let mut wal_os = OsString::from(db_path.as_os_str());
    wal_os.push("-wal");

    let mut shm_os = OsString::from(db_path.as_os_str());
    shm_os.push("-shm");

    [PathBuf::from(wal_os), PathBuf::from(shm_os)]
}

#[cfg(unix)]
fn prepare_sqlite_files_before_open(db_path: &Path) -> Result<(), DomainError> {
    ensure_db_file_mode_0600(db_path)?;
    let [wal_path, shm_path] = sqlite_sidecar_paths(db_path);
    harden_paths_0600(&[wal_path.as_path(), shm_path.as_path()])
}

#[cfg(not(unix))]
fn prepare_sqlite_files_before_open(db_path: &Path) -> Result<(), DomainError> {
    const MAX_ATTEMPTS: usize = 3;
    for _attempt in 0..MAX_ATTEMPTS {
        match std::fs::symlink_metadata(db_path) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(DomainError::PathTraversalAttempt(format!(
                        "SQLite file path must not be a symlink: {}",
                        db_path.display()
                    )));
                }
                if !meta.file_type().is_file() {
                    return Err(DomainError::StorageError(format!(
                        "SQLite file path is not a regular file: {}",
                        db_path.display()
                    )));
                }
                return Ok(());
            }
            Err(err) if err.kind() == ErrorKind::NotFound => {
                match std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(db_path)
                {
                    Ok(file) => {
                        let fd_meta = file.metadata().map_err(map_storage_err)?;
                        if !fd_meta.file_type().is_file() {
                            return Err(DomainError::StorageError(format!(
                                "Created SQLite handle is not a regular file: {}",
                                db_path.display()
                            )));
                        }
                        return Ok(());
                    }
                    Err(err) if err.kind() == ErrorKind::AlreadyExists => continue,
                    Err(err) => return Err(map_storage_err(err)),
                }
            }
            Err(err) => return Err(map_storage_err(err)),
        }
    }

    Err(DomainError::StorageError(format!(
        "Failed to stabilize SQLite database file after concurrent creation races: {}",
        db_path.display()
    )))
}

#[cfg(unix)]
fn ensure_db_file_mode_0600(db_path: &Path) -> Result<(), DomainError> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    const MAX_ATTEMPTS: usize = 3;
    for _attempt in 0..MAX_ATTEMPTS {
        match std::fs::symlink_metadata(db_path) {
            Ok(meta) => return ensure_fd_mode_0600(db_path, &meta),
            Err(err) if err.kind() == ErrorKind::NotFound => {
                let mut opts = std::fs::OpenOptions::new();
                opts.write(true).create_new(true);
                opts.mode(0o600);
                opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);

                match opts.open(db_path) {
                    Ok(file) => {
                        let fd_meta = file.metadata().map_err(map_storage_err)?;
                        if !fd_meta.file_type().is_file() {
                            return Err(DomainError::StorageError(format!(
                                "Created SQLite handle is not a regular file: {}",
                                db_path.display()
                            )));
                        }
                        file.set_permissions(std::fs::Permissions::from_mode(0o600))
                            .map_err(map_storage_err)?;
                        return Ok(());
                    }
                    Err(err) if err.kind() == ErrorKind::AlreadyExists => continue,
                    Err(err) => return Err(map_open_nofollow_err(db_path, err)),
                }
            }
            Err(err) => return Err(map_storage_err(err)),
        }
    }

    Err(DomainError::StorageError(format!(
        "Failed to stabilize SQLite database file after concurrent creation races: {}",
        db_path.display()
    )))
}

#[cfg(unix)]
fn ensure_fd_mode_0600(path: &Path, lstat_meta: &std::fs::Metadata) -> Result<(), DomainError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    if lstat_meta.file_type().is_symlink() {
        return Err(DomainError::PathTraversalAttempt(format!(
            "Refusing to set permissions on symlinked SQLite file: {}",
            path.display()
        )));
    }
    if !lstat_meta.file_type().is_file() {
        return Err(DomainError::StorageError(format!(
            "Refusing to set permissions on non-regular SQLite file: {}",
            path.display()
        )));
    }

    if (lstat_meta.permissions().mode() & 0o777) == 0o600 {
        return Ok(());
    }

    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);

    let file = opts
        .open(path)
        .map_err(|err| map_open_nofollow_err(path, err))?;
    let fd_meta = file.metadata().map_err(map_storage_err)?;

    if !fd_meta.file_type().is_file() {
        return Err(DomainError::StorageError(format!(
            "Opened SQLite handle is not a regular file: {}",
            path.display()
        )));
    }
    if (fd_meta.dev(), fd_meta.ino()) != (lstat_meta.dev(), lstat_meta.ino()) {
        return Err(DomainError::PathTraversalAttempt(format!(
            "SQLite file identity changed before fchmod (TOCTOU): {}",
            path.display()
        )));
    }

    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(map_storage_err)?;

    Ok(())
}

#[cfg(unix)]
fn map_open_nofollow_err(path: &Path, err: std::io::Error) -> DomainError {
    if err.raw_os_error() == Some(libc::ELOOP) {
        DomainError::PathTraversalAttempt(format!(
            "SQLite file path must not be a symlink (O_NOFOLLOW): {}",
            path.display()
        ))
    } else {
        DomainError::StorageError(format!(
            "Failed to open SQLite file '{}': {err}",
            path.display()
        ))
    }
}

#[cfg(unix)]
fn harden_paths_0600(paths: &[&Path]) -> Result<(), DomainError> {
    for path in paths {
        match std::fs::symlink_metadata(path) {
            Ok(meta) => ensure_fd_mode_0600(path, &meta)?,
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            Err(err) => return Err(map_storage_err(err)),
        }
    }

    Ok(())
}

#[cfg(unix)]
fn harden_sqlite_file_permissions(db_path: &Path) -> Result<(), DomainError> {
    let [wal_path, shm_path] = sqlite_sidecar_paths(db_path);
    harden_paths_0600(&[db_path, wal_path.as_path(), shm_path.as_path()])
}

#[cfg(not(unix))]
fn harden_sqlite_file_permissions(_db_path: &Path) -> Result<(), DomainError> {
    Ok(())
}

fn map_storage_err(err: impl std::fmt::Display) -> DomainError {
    DomainError::StorageError(err.to_string())
}

fn map_call_err(err: tokio_rusqlite::Error<DomainError>) -> DomainError {
    match err {
        tokio_rusqlite::Error::ConnectionClosed => {
            DomainError::StorageError("SQLite background connection is closed".to_string())
        }
        tokio_rusqlite::Error::Close((_, rusqlite_err)) => {
            DomainError::StorageError(rusqlite_err.to_string())
        }
        tokio_rusqlite::Error::Error(domain_err) => domain_err,
        other => DomainError::StorageError(other.to_string()),
    }
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

fn raw_to_runtime_config(raw: RawRuntimeConfig) -> Result<RuntimeConfig, DomainError> {
    Ok(RuntimeConfig {
        quarantine_dir: PathBuf::from(raw.quarantine_dir),
        approved_dir: PathBuf::from(raw.approved_dir),
        clamd_socket_path: PathBuf::from(raw.clamd_socket_path),
        suricata_eve_path: PathBuf::from(raw.suricata_eve_path),
        updated_at: parse_utc_timestamp(&raw.updated_at)?,
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

fn raw_to_inspection_report(raw: RawInspectionReport) -> Result<InspectionReport, DomainError> {
    let size_bytes = u64::try_from(raw.size_bytes).map_err(|err| {
        DomainError::StorageError(format!("Negative size_bytes value in database: {err}"))
    })?;

    let extension = FileArtifact::normalize_extension(Path::new(&raw.file_name))
        .or_else(|| FileArtifact::normalize_extension(Path::new(&raw.source_path)));

    Ok(InspectionReport {
        id: Some(raw.id),
        artifact: FileArtifact {
            path: PathBuf::from(raw.source_path),
            sanitized_name: raw.file_name,
            extension,
            size_bytes,
            sha256_hash: raw.sha256_hash,
            detected_mime: raw.detected_mime,
        },
        verdict: decode_verdict(&raw.verdict_type, raw.verdict_detail.as_deref())?,
        destination_path: raw.destination_path.map(PathBuf::from),
        inspected_at: parse_utc_timestamp(&raw.inspected_at)?,
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
                extension: FileArtifact::normalize_extension(Path::new(name)),
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

    #[tokio::test]
    async fn connect_and_migrate_supports_in_memory_and_valid_file_url_variants() {
        for mem_url in [
            "sqlite::memory:",
            "sqlite://:memory:",
            "sqlite:///ignored.db?mode=memory",
        ] {
            let store = SqliteStore::connect_and_migrate(mem_url)
                .await
                .expect("in-memory URL variant should succeed");
            assert!(
                store
                    .list_recent_reports(5)
                    .await
                    .expect("query")
                    .is_empty()
            );
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let direct_path = dir.path().join("direct.db");
        let single_prefix_path = dir.path().join("single_prefix.db");
        let query_path = dir.path().join("query.db");

        let url_variants = [
            direct_path.to_string_lossy().into_owned(),
            format!("sqlite:{}", single_prefix_path.display()),
            format!("sqlite://{}?mode=rwc", query_path.display()),
        ];

        for url in url_variants {
            let store = SqliteStore::connect_and_migrate(&url)
                .await
                .expect("valid file-backed database URL variant should succeed");
            let cfg = sample_runtime_config("variant");
            assert_eq!(store.load_or_seed(&cfg).await.expect("seed"), cfg);
        }
    }

    #[tokio::test]
    async fn connect_and_migrate_rejects_unsafe_database_urls_and_symlinks() {
        for empty_url in ["", "   ", "sqlite://", "sqlite:", "sqlite://?mode=rwc"] {
            let err = SqliteStore::connect_and_migrate(empty_url)
                .await
                .expect_err("empty database URL must be rejected");
            assert!(
                matches!(err, DomainError::StorageError(_)),
                "expected StorageError for {empty_url:?}, got {err:?}"
            );
        }

        for null_url in ["sqlite:///tmp/sentinel\0.db", "sqlite::memory:\0", "\0"] {
            let err = SqliteStore::connect_and_migrate(null_url)
                .await
                .expect_err("null byte in database URL must be rejected");
            assert!(
                matches!(err, DomainError::InvalidPath(_)),
                "expected InvalidPath for {null_url:?}, got {err:?}"
            );
        }

        for traversal_url in [
            "sqlite:///tmp/../etc/sentinel.db",
            "sqlite://../sentinel.db",
            "../sentinel.db",
            "sqlite:/var/lib/sentinel/../db.sqlite",
        ] {
            let err = SqliteStore::connect_and_migrate(traversal_url)
                .await
                .expect_err("parent directory traversal in database URL must be rejected");
            assert!(
                matches!(err, DomainError::PathTraversalAttempt(_)),
                "expected PathTraversalAttempt for {traversal_url:?}, got {err:?}"
            );
        }

        for forbidden_url in [
            "sqlite:///etc/sentinel.db",
            "sqlite:/etc/sentinel.db",
            "/etc/sentinel.db",
            "sqlite:///bin/sentinel.db",
            "sqlite:///usr/sentinel.db",
            "sqlite:///root/sentinel.db",
            "sqlite:///",
        ] {
            let err = SqliteStore::connect_and_migrate(forbidden_url)
                .await
                .expect_err("forbidden system directory in database URL must be rejected");
            assert!(
                matches!(err, DomainError::ForbiddenSystemDirectory(_)),
                "expected ForbiddenSystemDirectory for {forbidden_url:?}, got {err:?}"
            );
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let dir = tempfile::tempdir().expect("tempdir");

            let symlink_to_etc = dir.path().join("etc_alias");
            symlink("/etc", &symlink_to_etc).expect("create symlink to /etc");
            let via_etc_symlink = format!("sqlite://{}/sentinel.db", symlink_to_etc.display());
            let parent_err = SqliteStore::connect_and_migrate(&via_etc_symlink)
                .await
                .expect_err("symlinked parent directory targeting /etc must be rejected");
            assert!(matches!(
                parent_err,
                DomainError::ForbiddenSystemDirectory(_)
            ));

            let real_db = dir.path().join("real.db");
            std::fs::write(&real_db, b"").expect("create dummy target file");
            let db_symlink = dir.path().join("symlink.db");
            symlink(&real_db, &db_symlink).expect("create symlinked .db");

            let symlink_url = format!("sqlite://{}", db_symlink.display());
            let db_sym_err = SqliteStore::connect_and_migrate(&symlink_url)
                .await
                .expect_err("existing symlink .db file must be rejected");
            assert!(matches!(db_sym_err, DomainError::PathTraversalAttempt(_)));

            let dangling_db_symlink = dir.path().join("dangling.db");
            symlink(dir.path().join("missing_target.db"), &dangling_db_symlink)
                .expect("create dangling .db symlink");
            let dangling_url = format!("sqlite://{}", dangling_db_symlink.display());
            let dangling_err = SqliteStore::connect_and_migrate(&dangling_url)
                .await
                .expect_err("dangling symlink .db file must be rejected");
            assert!(matches!(dangling_err, DomainError::PathTraversalAttempt(_)));
        }
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

    #[tokio::test]
    async fn quarantine_repo_normalizes_extensions_on_round_trip_and_fallback() {
        let store = SqliteStore::connect_and_migrate("sqlite::memory:")
            .await
            .expect("in-memory sqlite migration should succeed");

        let base_time = Utc::now();
        let uppercase_ext = sample_report("Manual.PDF", SecurityVerdict::Clean, base_time);
        assert_eq!(uppercase_ext.artifact.extension.as_deref(), Some("pdf"));

        let trailing_dot = sample_report(
            "trailing.",
            SecurityVerdict::Clean,
            base_time + ChronoDuration::seconds(1),
        );
        assert_eq!(trailing_dot.artifact.extension, None);

        let mut fallback_source = sample_report(
            "renamed_without_ext",
            SecurityVerdict::Clean,
            base_time + ChronoDuration::seconds(2),
        );
        fallback_source.artifact.path = PathBuf::from("/quarantine/Original.JPG");

        store
            .save_report(&uppercase_ext)
            .await
            .expect("save uppercase");
        store
            .save_report(&trailing_dot)
            .await
            .expect("save trailing dot");
        store
            .save_report(&fallback_source)
            .await
            .expect("save fallback source");

        let reports = store.list_recent_reports(10).await.expect("list reports");
        assert_eq!(reports.len(), 3);
        assert_eq!(reports[0].artifact.extension.as_deref(), Some("jpg"));
        assert_eq!(reports[1].artifact.extension, None);
        assert_eq!(reports[2].artifact.extension.as_deref(), Some("pdf"));
    }

    #[tokio::test]
    async fn connect_and_migrate_rejects_sidecar_symlinks_and_additional_malicious_urls() {
        for traversal_url in ["..", "sqlite://..", "sqlite:///tmp/./../etc/sentinel.db"] {
            let err = SqliteStore::connect_and_migrate(traversal_url)
                .await
                .expect_err("traversal URL must be rejected");
            assert!(
                matches!(err, DomainError::PathTraversalAttempt(_)),
                "expected PathTraversalAttempt for {traversal_url:?}, got {err:?}"
            );
        }

        let query_null_err =
            SqliteStore::connect_and_migrate("sqlite:///tmp/sentinel.db?mode=rwc\0")
                .await
                .expect_err("null byte in query string must be rejected");
        assert!(matches!(query_null_err, DomainError::InvalidPath(_)));

        for forbidden_url in [
            "/root/sentinel.db",
            "sqlite:/root/sentinel.db",
            "sqlite:///sbin/sentinel.db",
            "sqlite:///lib/sentinel.db",
            "sqlite:///proc/sentinel.db",
            "sqlite:///sys/sentinel.db",
            "sqlite:///dev/sentinel.db",
            "sqlite:///boot/sentinel.db",
            "/sentinel.db",
            "sqlite:///sentinel.db",
        ] {
            let err = SqliteStore::connect_and_migrate(forbidden_url)
                .await
                .expect_err("critical system directory must be rejected");
            assert!(
                matches!(err, DomainError::ForbiddenSystemDirectory(_)),
                "expected ForbiddenSystemDirectory for {forbidden_url:?}, got {err:?}"
            );
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let existing_dir_target = dir.path().join("dir_instead_of_file");
        std::fs::create_dir(&existing_dir_target).expect("create directory target");
        let dir_url = format!("sqlite://{}", existing_dir_target.display());
        let dir_err = SqliteStore::connect_and_migrate(&dir_url)
            .await
            .expect_err("existing directory as db path must be rejected");
        assert!(matches!(dir_err, DomainError::StorageError(_)));

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let etc_alias = dir.path().join("etc_link");
            symlink("/etc", &etc_alias).expect("create symlink to /etc");
            let bare_etc_alias_url = format!("{}/sentinel.db", etc_alias.display());
            let bare_etc_err = SqliteStore::connect_and_migrate(&bare_etc_alias_url)
                .await
                .expect_err("bare path through symlinked /etc ancestor must be rejected");
            assert!(matches!(
                bare_etc_err,
                DomainError::ForbiddenSystemDirectory(_)
            ));

            let root_alias = dir.path().join("root_fs_link");
            symlink("/", &root_alias).expect("create symlink to /");
            let multi_hop_etc = format!("sqlite://{}/etc/sentinel.db", root_alias.display());
            let multi_hop_err = SqliteStore::connect_and_migrate(&multi_hop_etc)
                .await
                .expect_err("multi-hop ancestor symlink into /etc must be rejected");
            assert!(matches!(
                multi_hop_err,
                DomainError::ForbiddenSystemDirectory(_)
            ));

            let dummy_target = dir.path().join("existing_target.bin");
            std::fs::write(&dummy_target, b"decoy").expect("create decoy target");

            for suffix in ["-wal", "-shm"] {
                let fresh_db = dir.path().join(format!("fresh_{}.db", &suffix[1..]));
                let sidecar_existing = PathBuf::from(format!("{}{}", fresh_db.display(), suffix));
                symlink(&dummy_target, &sidecar_existing)
                    .expect("create existing-target sidecar symlink");
                let err_existing =
                    SqliteStore::connect_and_migrate(&format!("sqlite://{}", fresh_db.display()))
                        .await
                        .expect_err("existing-target sidecar symlink must be rejected");
                assert!(
                    matches!(err_existing, DomainError::PathTraversalAttempt(_)),
                    "expected PathTraversalAttempt for {suffix} existing symlink, got {err_existing:?}"
                );

                let dangling_db = dir.path().join(format!("dangling_{}.db", &suffix[1..]));
                let sidecar_dangling =
                    PathBuf::from(format!("{}{}", dangling_db.display(), suffix));
                symlink("/etc/nonexistent_sentinel_sidecar", &sidecar_dangling)
                    .expect("create dangling sidecar symlink");
                let err_dangling = SqliteStore::connect_and_migrate(&format!(
                    "sqlite://{}",
                    dangling_db.display()
                ))
                .await
                .expect_err("dangling sidecar symlink must be rejected");
                assert!(
                    matches!(err_dangling, DomainError::PathTraversalAttempt(_)),
                    "expected PathTraversalAttempt for {suffix} dangling symlink, got {err_dangling:?}"
                );
            }

            // Reopening a legitimate DB after a malicious sidecar symlink was planted must fail.
            let legit_db = dir.path().join("legit_then_poisoned.db");
            let legit_url = format!("sqlite://{}", legit_db.display());
            {
                let store = SqliteStore::connect_and_migrate(&legit_url)
                    .await
                    .expect("initial legitimate connect should succeed");
                store
                    .save_report(&sample_report("ok.pdf", SecurityVerdict::Clean, Utc::now()))
                    .await
                    .expect("initial write should succeed");
                store.conn.close().await.expect("close initial store");
            }
            for suffix in ["-wal", "-shm"] {
                let sidecar = PathBuf::from(format!("{}{}", legit_db.display(), suffix));
                if sidecar.exists() {
                    std::fs::remove_file(&sidecar).expect("remove existing sidecar");
                }
                symlink(&dummy_target, &sidecar).expect("plant malicious sidecar symlink");
                let reopen_err = SqliteStore::connect_and_migrate(&legit_url)
                    .await
                    .expect_err("reopening db with symlinked sidecar must fail");
                assert!(
                    matches!(reopen_err, DomainError::PathTraversalAttempt(_)),
                    "expected PathTraversalAttempt on reopen for {suffix}, got {reopen_err:?}"
                );
                std::fs::remove_file(&sidecar).expect("cleanup planted sidecar symlink");
            }
        }
    }

    #[tokio::test]
    async fn connect_and_migrate_enables_wal_and_supports_concurrent_tokio_tasks() {
        use std::collections::HashSet;
        use tokio::task::JoinSet;

        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("concurrent.db");
        let db_url = format!("sqlite://{}?mode=rwc", db_path.display());

        let primary_store = SqliteStore::connect_and_migrate(&db_url)
            .await
            .expect("primary connect and migrate");
        let secondary_store = SqliteStore::connect_and_migrate(&db_url)
            .await
            .expect("secondary connect and migrate");

        let (journal_mode, busy_timeout): (String, i64) = primary_store
            .conn
            .call(|raw_conn| {
                let mode: String =
                    raw_conn.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
                let timeout: i64 =
                    raw_conn.query_row("PRAGMA busy_timeout", [], |row| row.get(0))?;
                Ok::<_, tokio_rusqlite::rusqlite::Error>((mode, timeout))
            })
            .await
            .expect("query SQLite PRAGMAs");
        assert_eq!(journal_mode.to_lowercase(), "wal");
        assert_eq!(busy_timeout, 5000);

        let initial_cfg = sample_runtime_config("concurrent_init");
        primary_store
            .load_or_seed(&initial_cfg)
            .await
            .expect("seed config");

        let mut writers = JoinSet::new();
        let total_reports = 24usize;
        let base_time = Utc::now();

        for idx in 0..total_reports {
            let store = if idx % 2 == 0 {
                primary_store.clone()
            } else {
                secondary_store.clone()
            };
            let report = sample_report(
                &format!("concurrent_{idx}.pdf"),
                if idx % 3 == 0 {
                    SecurityVerdict::MaliciousSignature {
                        threat_name: format!("Test.Threat.{idx}"),
                    }
                } else {
                    SecurityVerdict::Clean
                },
                base_time + ChronoDuration::milliseconds(idx as i64),
            );
            writers.spawn(async move {
                store
                    .save_report(&report)
                    .await
                    .expect("concurrent save_report must not fail with database is locked")
            });
        }

        let mut readers = JoinSet::new();
        for idx in 0..12usize {
            let store = if idx % 2 == 0 {
                primary_store.clone()
            } else {
                secondary_store.clone()
            };
            let fallback = sample_runtime_config(&format!("reader_{idx}"));
            readers.spawn(async move {
                let _ = store
                    .list_recent_reports(10)
                    .await
                    .expect("concurrent list_recent_reports must succeed");
                let _ = store
                    .load_or_seed(&fallback)
                    .await
                    .expect("concurrent load_or_seed must succeed");
            });
        }

        let cfg_store_a = primary_store.clone();
        let cfg_store_b = secondary_store.clone();
        let cfg_a = sample_runtime_config("concurrent_cfg_a");
        let cfg_b = sample_runtime_config("concurrent_cfg_b");
        let (res_a, res_b) = tokio::join!(
            cfg_store_a.save_config(&cfg_a),
            cfg_store_b.save_config(&cfg_b)
        );
        res_a.expect("concurrent save_config A must succeed");
        res_b.expect("concurrent save_config B must succeed");

        let mut inserted_ids = HashSet::with_capacity(total_reports);
        while let Some(joined) = writers.join_next().await {
            let id = joined.expect("writer task must not panic");
            assert!(id > 0);
            assert!(inserted_ids.insert(id), "duplicate row id {id} inserted");
        }
        assert_eq!(inserted_ids.len(), total_reports);

        while let Some(joined) = readers.join_next().await {
            joined.expect("reader task must not panic");
        }

        let persisted = primary_store
            .list_recent_reports(50)
            .await
            .expect("list all persisted reports");
        assert_eq!(persisted.len(), total_reports);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn file_permissions_remain_0600_on_db_wal_and_shm_after_multiple_writes_and_reopen() {
        use std::os::unix::fs::PermissionsExt;

        fn assert_all_sqlite_files_0600(db_path: &Path, stage: &str) {
            let [wal_path, shm_path] = sqlite_sidecar_paths(db_path);
            for path in [db_path, wal_path.as_path(), shm_path.as_path()] {
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

        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("wal_permissions.db");
        let db_url = format!("sqlite://{}?mode=rwc", db_path.display());

        // Phase 1: Initial creation + multiple config and report writes.
        {
            let store = SqliteStore::connect_and_migrate(&db_url)
                .await
                .expect("initial connect and migrate");
            let initial_cfg = sample_runtime_config("perms_phase1");
            store.load_or_seed(&initial_cfg).await.expect("seed config");
            store
                .save_config(&sample_runtime_config("perms_phase1_updated"))
                .await
                .expect("save updated config");

            for idx in 0..15 {
                store
                    .save_report(&sample_report(
                        &format!("phase1_{idx}.pdf"),
                        SecurityVerdict::Clean,
                        Utc::now(),
                    ))
                    .await
                    .expect("phase 1 save_report");
            }

            assert_all_sqlite_files_0600(&db_path, "phase1_after_writes");
            store.conn.close().await.expect("close phase 1 store");
        }

        // Phase 2: Reopen DB and perform multiple new writes + WAL checkpoint + more writes.
        {
            let reopened = SqliteStore::connect_and_migrate(&db_url)
                .await
                .expect("reopen connect and migrate");
            reopened
                .save_config(&sample_runtime_config("perms_phase2"))
                .await
                .expect("phase 2 save_config");

            for idx in 0..15 {
                reopened
                    .save_report(&sample_report(
                        &format!("phase2_{idx}.pdf"),
                        SecurityVerdict::Clean,
                        Utc::now(),
                    ))
                    .await
                    .expect("phase 2 save_report");
            }

            assert_all_sqlite_files_0600(&db_path, "phase2_after_reopen_writes");

            reopened
                .conn
                .call(|raw_conn| {
                    raw_conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
                    Ok::<_, tokio_rusqlite::rusqlite::Error>(())
                })
                .await
                .expect("wal checkpoint truncate");

            reopened
                .save_report(&sample_report(
                    "phase2_post_checkpoint.pdf",
                    SecurityVerdict::Clean,
                    Utc::now(),
                ))
                .await
                .expect("post-checkpoint save_report");

            assert_all_sqlite_files_0600(&db_path, "phase2_post_checkpoint_write");
            reopened.conn.close().await.expect("close phase 2 store");
        }

        // Phase 3: Pre-existing permissive (0o644) database file must be hardened to 0o600
        // and subsequent WAL/SHM creation must preserve 0o600.
        let permissive_db = dir.path().join("preexisting_permissive.db");
        std::fs::write(&permissive_db, b"").expect("create empty permissive db file");
        std::fs::set_permissions(&permissive_db, std::fs::Permissions::from_mode(0o644))
            .expect("set permissive 0o644 permissions");

        let permissive_store =
            SqliteStore::connect_and_migrate(&format!("sqlite://{}", permissive_db.display()))
                .await
                .expect("connect to preexisting permissive file");
        for idx in 0..5 {
            permissive_store
                .save_report(&sample_report(
                    &format!("hardened_{idx}.pdf"),
                    SecurityVerdict::Clean,
                    Utc::now(),
                ))
                .await
                .expect("write to hardened db");
        }
        assert_all_sqlite_files_0600(&permissive_db, "phase3_preexisting_permissive_hardened");

        // Phase 4: Already-migrated DB whose permissions drifted to 0o644 while closed
        // must be re-hardened to 0o600 on reopen before creating new -wal/-shm sidecars.
        permissive_store
            .conn
            .close()
            .await
            .expect("close phase 3 store");
        std::fs::set_permissions(&permissive_db, std::fs::Permissions::from_mode(0o644))
            .expect("simulate external 0o644 permission drift on migrated db");
        let rehardened =
            SqliteStore::connect_and_migrate(&format!("sqlite://{}", permissive_db.display()))
                .await
                .expect("reopen drifted migrated db");
        rehardened
            .save_report(&sample_report(
                "rehardened_after_drift.pdf",
                SecurityVerdict::Clean,
                Utc::now(),
            ))
            .await
            .expect("write after re-hardening");
        assert_all_sqlite_files_0600(&permissive_db, "phase4_drifted_migrated_db_rehardened");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn pre_open_hardening_creates_0600_files_and_rejects_non_regular_files_and_eloop() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        use std::process::Command;

        let dir = tempfile::tempdir().expect("tempdir");

        // 1. Pre-open atomic creation directly at 0o600 without SQLite creating a 0o644 file.
        let fresh_db = dir.path().join("pre_open_atomic.db");
        prepare_sqlite_files_before_open(&fresh_db)
            .expect("pre-open creation should create db directly at 0o600");
        let fresh_meta = std::fs::symlink_metadata(&fresh_db).expect("fresh db metadata");
        assert!(fresh_meta.file_type().is_file());
        assert!(!fresh_meta.file_type().is_symlink());
        assert_eq!(fresh_meta.permissions().mode() & 0o777, 0o600);

        // 2. Pre-existing permissive .db and -wal files are fchmod-hardened to 0o600 before open,
        // even if SQLite later fails during pragma/migration on corrupt content.
        let corrupt_db = dir.path().join("corrupt_permissive.db");
        let [corrupt_wal, _] = sqlite_sidecar_paths(&corrupt_db);
        std::fs::write(&corrupt_db, b"NOT A VALID SQLITE DATABASE HEADER")
            .expect("write corrupt db");
        std::fs::write(&corrupt_wal, b"corrupt wal").expect("write corrupt wal");
        std::fs::set_permissions(&corrupt_db, std::fs::Permissions::from_mode(0o644))
            .expect("set permissive 0o644 on corrupt db");
        std::fs::set_permissions(&corrupt_wal, std::fs::Permissions::from_mode(0o644))
            .expect("set permissive 0o644 on corrupt wal");

        let corrupt_err =
            SqliteStore::connect_and_migrate(&format!("sqlite://{}", corrupt_db.display()))
                .await
                .expect_err("corrupt sqlite file must fail migration");
        assert!(matches!(corrupt_err, DomainError::StorageError(_)));
        assert_eq!(
            std::fs::symlink_metadata(&corrupt_db)
                .expect("corrupt db metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600,
            "corrupt db must already be hardened to 0o600 prior to SQLite open failure"
        );
        assert_eq!(
            std::fs::symlink_metadata(&corrupt_wal)
                .expect("corrupt wal metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600,
            "pre-existing wal must already be hardened to 0o600 prior to SQLite open failure"
        );

        // 3. harden_sqlite_file_permissions is a no-op when already 0o600 and rejects non-regular files & symlinks.
        harden_sqlite_file_permissions(&fresh_db)
            .expect("already-0o600 file should pass without unnecessary reopen");

        let dir_target = dir.path().join("not_a_file_dir");
        std::fs::create_dir(&dir_target).expect("mkdir");
        assert!(matches!(
            harden_sqlite_file_permissions(&dir_target),
            Err(DomainError::StorageError(_))
        ));

        let fifo_db = dir.path().join("fifo.db");
        let mkfifo_status = Command::new("mkfifo")
            .arg(&fifo_db)
            .status()
            .expect("invoke mkfifo");
        assert!(mkfifo_status.success(), "mkfifo must succeed");
        assert!(matches!(
            harden_sqlite_file_permissions(&fifo_db),
            Err(DomainError::StorageError(_))
        ));
        let fifo_connect_err =
            SqliteStore::connect_and_migrate(&format!("sqlite://{}", fifo_db.display()))
                .await
                .expect_err("FIFO database path must be rejected");
        assert!(matches!(fifo_connect_err, DomainError::StorageError(_)));

        // FIFO as -wal sidecar must also be rejected before SQLite opens it.
        let db_with_fifo_wal = dir.path().join("with_fifo_wal.db");
        let [fifo_wal, _] = sqlite_sidecar_paths(&db_with_fifo_wal);
        let mkfifo_wal_status = Command::new("mkfifo")
            .arg(&fifo_wal)
            .status()
            .expect("invoke mkfifo for wal");
        assert!(mkfifo_wal_status.success(), "mkfifo wal must succeed");
        assert!(matches!(
            harden_sqlite_file_permissions(&db_with_fifo_wal),
            Err(DomainError::StorageError(_))
        ));
        let fifo_wal_err =
            SqliteStore::connect_and_migrate(&format!("sqlite://{}", db_with_fifo_wal.display()))
                .await
                .expect_err("FIFO sidecar must be rejected");
        assert!(matches!(fifo_wal_err, DomainError::StorageError(_)));

        let symlink_target = dir.path().join("sym_target.db");
        std::fs::write(&symlink_target, b"").expect("write symlink target");
        let symlink_db = dir.path().join("sym.db");
        symlink(&symlink_target, &symlink_db).expect("create symlink");
        assert!(matches!(
            harden_sqlite_file_permissions(&symlink_db),
            Err(DomainError::PathTraversalAttempt(_))
        ));
        assert!(matches!(
            map_open_nofollow_err(&symlink_db, std::io::Error::from_raw_os_error(libc::ELOOP)),
            DomainError::PathTraversalAttempt(_)
        ));
    }

    #[tokio::test]
    async fn resolve_database_target_enforces_strict_mode_memory_and_path_hygiene() {
        for mem_url in [
            "sqlite::memory:",
            "sqlite://:memory:",
            ":memory:",
            "sqlite:///ignored.db?mode=memory",
            "sqlite:///tmp/ignored.db?mode=memory",
        ] {
            let store = SqliteStore::connect_and_migrate(mem_url)
                .await
                .expect("valid in-memory URL must succeed");
            assert!(
                store
                    .list_recent_reports(5)
                    .await
                    .expect("query")
                    .is_empty()
            );
        }

        for contradictory_or_empty in [
            "?mode=memory",
            "sqlite://?mode=memory",
            "sqlite:?mode=memory",
            "sqlite:///tmp/test.db?mode=rwc&mode=memory",
            "sqlite:///tmp/test.db?mode=memory&mode=rwc",
            "sqlite:///tmp/test.db?mode=rw&mode=rwc",
            "sqlite:///tmp/test.db?mode=ro",
            "sqlite:///tmp/test.db?mode=",
            "sqlite:///tmp/test.db?mode",
            "sqlite://:memory:?mode=rwc",
            "sqlite:///tmp/subdir/?mode=memory",
        ] {
            let err = SqliteStore::connect_and_migrate(contradictory_or_empty)
                .await
                .expect_err("empty or contradictory mode URL must be rejected");
            assert!(
                matches!(err, DomainError::StorageError(_)),
                "expected StorageError for {contradictory_or_empty:?}, got {err:?}"
            );
        }

        for forbidden_mem_url in [
            "sqlite:///etc/sentinel.db?mode=memory",
            "sqlite:///root/sentinel.db?mode=memory",
            "sqlite:///usr/sentinel.db?mode=memory",
        ] {
            let err = SqliteStore::connect_and_migrate(forbidden_mem_url)
                .await
                .expect_err("forbidden OS directory with ?mode=memory must be rejected");
            assert!(
                matches!(err, DomainError::ForbiddenSystemDirectory(_)),
                "expected ForbiddenSystemDirectory for {forbidden_mem_url:?}, got {err:?}"
            );
        }

        for traversal_url in [
            "sqlite:///tmp/../etc/sentinel.db?mode=memory",
            "sqlite://../ignored.db?mode=memory",
            "sqlite:///tmp\\..\\etc\\sentinel.db",
        ] {
            let err = SqliteStore::connect_and_migrate(traversal_url)
                .await
                .expect_err("traversal URL must be rejected before checking mode=memory");
            assert!(
                matches!(err, DomainError::PathTraversalAttempt(_)),
                "expected PathTraversalAttempt for {traversal_url:?}, got {err:?}"
            );
        }

        for hygiene_invalid_url in [
            "sqlite:///tmp/./sentinel.db",
            "sqlite:///tmp/./ignored.db?mode=memory",
            "sqlite:///tmp/.",
            "sqlite://./sentinel.db",
            "sqlite:///tmp\\.\\sentinel.db",
            "sqlite:///tmp\\.",
            "sqlite:///tmp/.hidden.db",
            "sqlite:///tmp/bad\nname.db",
            "sqlite:///tmp/bad\tname.db",
            "sqlite:///tmp/ignored.db?mode=memory\n",
        ] {
            let err = SqliteStore::connect_and_migrate(hygiene_invalid_url)
                .await
                .expect_err("relative '.' markers, backslashes, hidden db names, and control chars must be rejected");
            assert!(
                matches!(err, DomainError::InvalidPath(_)),
                "expected InvalidPath for {hygiene_invalid_url:?}, got {err:?}"
            );
        }
    }
}
