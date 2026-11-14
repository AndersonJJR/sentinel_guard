//! Unified domain error definitions for Sentinel Guard.

use thiserror::Error;

/// Domain-level error enum shared across core, application, and infrastructure layers.
#[derive(Debug, Error)]
pub enum DomainError {
    /// Underlying I/O failure.
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Invalid or inaccessible filesystem path.
    #[error("Invalid path: {0}")]
    InvalidPath(String),

    /// Path traversal attempt detected (e.g. `..` components or null bytes).
    #[error("Path traversal attempt detected: {0}")]
    PathTraversalAttempt(String),

    /// Attempt to configure or target a critical operating system directory.
    #[error("Forbidden system directory: {0}")]
    ForbiddenSystemDirectory(String),

    /// Bootstrap or runtime configuration error.
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Persistence or database mapping error.
    #[error("Storage error: {0}")]
    StorageError(String),

    /// File inspection or scanner pipeline failure.
    #[error("Inspection error: {0}")]
    InspectionError(String),

    /// Quarantine file movement or permission hardening failure.
    #[error("Quarantine error: {0}")]
    QuarantineError(String),
}
