//! Port traits (Dependency Inversion Principle boundaries) implemented by infrastructure adapters.

use std::path::{Path, PathBuf};

use async_trait::async_trait;

use crate::domain::entities::{FileArtifact, InspectionReport, RuntimeConfig, SecurityVerdict};
use crate::domain::errors::DomainError;

/// Calculates cryptographic SHA-256 digests and byte sizes via streaming I/O.
#[async_trait]
pub trait HashCalculator: Send + Sync {
    /// Computes the lowercase hex SHA-256 digest and total byte size for the file at `path`.
    async fn calculate_sha256(&self, path: &Path) -> Result<(String, u64), DomainError>;
}

/// Detects binary MIME types using file magic bytes rather than trusting extensions.
#[async_trait]
pub trait MimeValidator: Send + Sync {
    /// Inspects the leading bytes of `path` and returns the detected MIME type, if any.
    async fn detect_mime(&self, path: &Path) -> Result<Option<String>, DomainError>;
}

/// Evaluates a [`FileArtifact`] against a specific security check (e.g., spoofing, AV, IDS).
#[async_trait]
pub trait FileScanner: Send + Sync {
    /// Returns the human-readable scanner identifier for logging and diagnostics.
    fn name(&self) -> &'static str;

    /// Inspects `artifact` and returns a [`SecurityVerdict`].
    async fn scan(&self, artifact: &FileArtifact) -> Result<SecurityVerdict, DomainError>;
}

/// Handles permission hardening and atomic/safe file disposition between directories.
#[async_trait]
pub trait QuarantineMover: Send + Sync {
    /// Enforces restrictive non-executable file permissions (`0o600` when isolated, `0o640` otherwise).
    async fn harden_permissions(&self, path: &Path, isolated: bool) -> Result<(), DomainError>;

    /// Moves a verified clean file from quarantine into `approved_dir`.
    async fn move_to_approved(
        &self,
        source: &Path,
        approved_dir: &Path,
    ) -> Result<PathBuf, DomainError>;

    /// Isolates a rejected or suspicious file safely within `quarantine_dir`.
    async fn isolate_rejected(
        &self,
        source: &Path,
        quarantine_dir: &Path,
    ) -> Result<PathBuf, DomainError>;
}

/// Persistent storage contract for dynamic [`RuntimeConfig`].
#[async_trait]
pub trait ConfigStore: Send + Sync {
    /// Loads the persisted runtime configuration, or seeds it with `defaults` on first run.
    async fn load_or_seed(&self, defaults: &RuntimeConfig) -> Result<RuntimeConfig, DomainError>;

    /// Persists an updated [`RuntimeConfig`].
    async fn save_config(&self, config: &RuntimeConfig) -> Result<(), DomainError>;
}

/// Persistent repository contract for [`InspectionReport`] audit logs.
#[async_trait]
pub trait QuarantineRepo: Send + Sync {
    /// Saves an inspection report and returns its generated record ID.
    async fn save_report(&self, report: &InspectionReport) -> Result<i64, DomainError>;

    /// Lists up to `limit` most recent inspection reports ordered newest-first.
    async fn list_recent_reports(&self, limit: u32) -> Result<Vec<InspectionReport>, DomainError>;
}
