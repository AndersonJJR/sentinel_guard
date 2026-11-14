//! Pure domain entities representing inspected artifacts, verdicts, configuration, and alerts.

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Metadata and cryptographic identity of a file entering the inspection pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileArtifact {
    /// Current path of the file under inspection.
    pub path: PathBuf,
    /// Sanitized file name (guaranteed free of directory traversal components).
    pub sanitized_name: String,
    /// Normalized file extension, if present.
    pub extension: Option<String>,
    /// File size in bytes.
    pub size_bytes: u64,
    /// Hex-encoded SHA-256 digest computed via streaming I/O.
    pub sha256_hash: String,
    /// Detected MIME type based on binary magic bytes, if recognized.
    pub detected_mime: Option<String>,
}

/// Security outcome emitted by a scanner or the overall inspection pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityVerdict {
    /// File passed all integrity, signature, and correlation checks.
    Clean,
    /// File extension does not match the detected binary MIME magic bytes.
    MaliciousSpoofing {
        /// Expected file extension or category claimed by the file name.
        expected_ext: String,
        /// Actual MIME type detected from binary content.
        actual_mime: String,
    },
    /// File matched a known malware signature (e.g., ClamAV).
    MaliciousSignature {
        /// Signature or threat identifier reported by the scanner.
        threat_name: String,
    },
    /// File activity correlates with a suspicious network alert (e.g., Suricata).
    SuspiciousNetworkCorrelation {
        /// Suricata alert signature name.
        alert_signature: String,
        /// Source IP associated with the alert.
        src_ip: String,
    },
    /// File could not be read or parsed safely during inspection.
    CorruptedOrUnreadable {
        /// Diagnostic reason explaining why the file could not be verified.
        reason: String,
    },
}

/// Persisted inspection report capturing an artifact, its verdict, and final disposition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InspectionReport {
    /// Database primary key once persisted.
    pub id: Option<i64>,
    /// Inspected file metadata and hash.
    pub artifact: FileArtifact,
    /// Security verdict determined by the inspection pipeline.
    pub verdict: SecurityVerdict,
    /// Final destination path after approval or isolation, if moved.
    pub destination_path: Option<PathBuf>,
    /// UTC timestamp when the inspection completed.
    pub inspected_at: DateTime<Utc>,
}

/// Dynamically reloadable runtime paths persisted in storage and cached in memory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeConfig {
    /// Directory monitored for incoming untrusted files.
    pub quarantine_dir: PathBuf,
    /// Destination directory for verified clean files.
    pub approved_dir: PathBuf,
    /// Unix socket path for ClamAV daemon communication.
    pub clamd_socket_path: PathBuf,
    /// Path to Suricata `eve.json` alert log.
    pub suricata_eve_path: PathBuf,
    /// UTC timestamp of the last configuration update.
    pub updated_at: DateTime<Utc>,
}

/// Network intrusion alert parsed from IDS telemetry (Suricata `eve.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkAlert {
    /// UTC timestamp of the network event.
    pub timestamp: DateTime<Utc>,
    /// Source IP address of the suspicious traffic.
    pub src_ip: String,
    /// Destination IP address of the suspicious traffic.
    pub dest_ip: String,
    /// IDS alert signature description.
    pub signature: String,
    /// Alert severity level reported by the IDS.
    pub severity: u8,
}
