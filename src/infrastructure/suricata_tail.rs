//! Streaming Suricata `eve.json` alert tailer and network-threat correlator.

use std::collections::VecDeque;
use std::io::{ErrorKind, SeekFrom};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};
use tokio::sync::{Mutex, RwLock};

use crate::domain::entities::{FileArtifact, NetworkAlert, RuntimeConfig, SecurityVerdict};
use crate::domain::errors::DomainError;
use crate::domain::path_policy::{
    reject_forbidden_system_dir, validate_absolute_non_system_file_path,
};
use crate::domain::ports::FileScanner;
use crate::infrastructure::magic_bytes::{STREAM_CHUNK_SIZE, open_regular_file_safely};

/// Default time window during which Suricata alerts remain eligible for correlation (10 minutes).
pub const DEFAULT_CORRELATION_WINDOW: Duration = Duration::from_secs(600);

/// Default maximum Suricata severity level treated as suspicious (`1` = High, `2` = Medium).
pub const DEFAULT_MAX_SEVERITY_THRESHOLD: u8 = 2;

/// Hard upper bound on active network alerts retained in memory.
pub const MAX_RECENT_ALERTS: usize = 1_024;

/// Maximum trailing byte window scanned on initial attach to an existing large `eve.json` file (256 KB).
pub const INITIAL_TAIL_BYTES: u64 = 256 * 1_024;

/// Hard upper bound on a single `eve.json` NDJSON line before it is discarded without buffering (64 KB).
pub const MAX_EVE_LINE_BYTES: usize = 65_536;

#[derive(Debug, Default)]
struct SuricataTailState {
    last_path: Option<PathBuf>,
    last_dev_ino: Option<(u64, u64)>,
    offset: u64,
    recent_alerts: VecDeque<NetworkAlert>,
}

#[derive(Debug, Deserialize)]
struct RawEveEvent {
    event_type: Option<String>,
    timestamp: Option<String>,
    src_ip: Option<String>,
    dest_ip: Option<String>,
    alert: Option<RawSuricataAlert>,
}

#[derive(Debug, Deserialize)]
struct RawSuricataAlert {
    signature: Option<String>,
    severity: Option<u8>,
}

/// Asynchronous Suricata `eve.json` streaming tailer implementing [`FileScanner`].
///
/// Reads `suricata_eve_path` dynamically from [`RuntimeConfig`] on each synchronization so
/// configuration reloads apply without restarting the daemon. Bounds memory usage via 64 KB
/// chunked reading and a strict [`MAX_RECENT_ALERTS`] ring buffer.
#[derive(Debug, Clone)]
pub struct SuricataCorrelator {
    runtime_config: Arc<RwLock<RuntimeConfig>>,
    correlation_window: Duration,
    max_severity_threshold: u8,
    monitored_subnet_prefixes: Vec<String>,
    state: Arc<Mutex<SuricataTailState>>,
}

impl SuricataCorrelator {
    /// Creates a new [`SuricataCorrelator`] with default policy (`600s` window, severity `<= 2`, all subnets).
    pub fn new(runtime_config: Arc<RwLock<RuntimeConfig>>) -> Self {
        Self::with_policy(
            runtime_config,
            DEFAULT_CORRELATION_WINDOW,
            DEFAULT_MAX_SEVERITY_THRESHOLD,
            Vec::new(),
        )
    }

    /// Creates a new [`SuricataCorrelator`] with explicit correlation window, severity threshold, and subnet prefixes.
    pub fn with_policy(
        runtime_config: Arc<RwLock<RuntimeConfig>>,
        correlation_window: Duration,
        max_severity_threshold: u8,
        monitored_subnet_prefixes: Vec<String>,
    ) -> Self {
        let cleaned_prefixes = monitored_subnet_prefixes
            .into_iter()
            .map(|prefix| prefix.trim().to_string())
            .filter(|prefix| !prefix.is_empty())
            .collect();

        Self {
            runtime_config,
            correlation_window,
            max_severity_threshold,
            monitored_subnet_prefixes: cleaned_prefixes,
            state: Arc::new(Mutex::new(SuricataTailState::default())),
        }
    }

    /// Incrementally tails new `eve.json` lines, handles rotation/truncation, and prunes expired alerts.
    pub async fn sync_alerts(&self) -> Result<(), DomainError> {
        let _ = self.sync_internal(false).await?;
        Ok(())
    }

    /// Synchronizes with `eve.json` and returns all non-expired alerts matching the configured policy.
    pub async fn active_alerts(&self) -> Result<Vec<NetworkAlert>, DomainError> {
        self.sync_internal(true).await
    }

    async fn sync_internal(
        &self,
        collect_matching: bool,
    ) -> Result<Vec<NetworkAlert>, DomainError> {
        let configured_path = {
            let guard = self.runtime_config.read().await;
            guard.suricata_eve_path.clone()
        };

        let canonical_eve_path = validate_eve_path_and_parent(&configured_path).await?;
        let cutoff = compute_cutoff(Utc::now(), self.correlation_window)?;

        let mut state = self.state.lock().await;
        if state.last_path.as_ref() != Some(&canonical_eve_path) {
            state.recent_alerts.clear();
            state.offset = 0;
            state.last_dev_ino = None;
            state.last_path = Some(canonical_eve_path.clone());
        }

        let mut file = match open_regular_file_safely(&canonical_eve_path).await {
            Ok(file) => file,
            Err(DomainError::IoError(err)) if err.kind() == ErrorKind::NotFound => {
                // Safe parent exists, but Suricata has not emitted or rotated eve.json yet.
                state.offset = 0;
                state.last_dev_ino = None;
                prune_expired_alerts(&mut state.recent_alerts, cutoff);
                return Ok(if collect_matching {
                    self.collect_matching_alerts(&state.recent_alerts)
                } else {
                    Vec::new()
                });
            }
            Err(err) => return Err(err),
        };

        let file_meta = file.metadata().await?;
        let file_len = file_meta.len();
        let current_dev_ino = extract_dev_ino(&file_meta);

        if state.last_dev_ino != current_dev_ino || file_len < state.offset {
            state.offset = 0;
            state.last_dev_ino = current_dev_ino;
        }

        prune_expired_alerts(&mut state.recent_alerts, cutoff);

        if state.offset == 0 && file_len > INITIAL_TAIL_BYTES {
            let start_pos = file_len - INITIAL_TAIL_BYTES;
            file.seek(SeekFrom::Start(start_pos)).await?;
            let mut reader = BufReader::with_capacity(STREAM_CHUNK_SIZE, file);

            match discard_partial_line(&mut reader, &canonical_eve_path).await? {
                Some(skipped) => {
                    let tail_start = start_pos.checked_add(skipped).ok_or_else(|| {
                        DomainError::InspectionError(format!(
                            "Tail offset overflowed u64 for {}",
                            canonical_eve_path.display()
                        ))
                    })?;
                    state.offset = read_complete_lines(
                        &mut reader,
                        &canonical_eve_path,
                        tail_start,
                        cutoff,
                        &mut state.recent_alerts,
                    )
                    .await?;
                }
                None => {
                    state.offset = start_pos;
                }
            }
        } else if state.offset < file_len {
            let start_offset = state.offset;
            file.seek(SeekFrom::Start(start_offset)).await?;
            let mut reader = BufReader::with_capacity(STREAM_CHUNK_SIZE, file);
            state.offset = read_complete_lines(
                &mut reader,
                &canonical_eve_path,
                start_offset,
                cutoff,
                &mut state.recent_alerts,
            )
            .await?;
        }

        prune_expired_alerts(&mut state.recent_alerts, cutoff);

        Ok(if collect_matching {
            self.collect_matching_alerts(&state.recent_alerts)
        } else {
            Vec::new()
        })
    }

    fn collect_matching_alerts(&self, alerts: &VecDeque<NetworkAlert>) -> Vec<NetworkAlert> {
        alerts
            .iter()
            .filter(|alert| self.alert_matches_policy(alert))
            .cloned()
            .collect()
    }

    fn alert_matches_policy(&self, alert: &NetworkAlert) -> bool {
        if alert.severity > self.max_severity_threshold {
            return false;
        }
        if self.monitored_subnet_prefixes.is_empty() {
            return true;
        }
        self.monitored_subnet_prefixes
            .iter()
            .any(|prefix| alert.src_ip.starts_with(prefix) || alert.dest_ip.starts_with(prefix))
    }
}

#[async_trait]
impl FileScanner for SuricataCorrelator {
    fn name(&self) -> &'static str {
        "suricata_eve_correlator"
    }

    async fn scan(&self, artifact: &FileArtifact) -> Result<SecurityVerdict, DomainError> {
        let matching_alerts = self.active_alerts().await?;
        let Some(selected) = select_highest_priority_alert(&matching_alerts) else {
            return Ok(SecurityVerdict::Clean);
        };

        tracing::warn!(
            scanner = self.name(),
            file_name = %artifact.sanitized_name,
            alert_signature = %selected.signature,
            src_ip = %selected.src_ip,
            dest_ip = %selected.dest_ip,
            severity = selected.severity,
            "Correlated quarantined artifact with active Suricata IDS alert"
        );

        Ok(SecurityVerdict::SuspiciousNetworkCorrelation {
            alert_signature: selected.signature.clone(),
            src_ip: selected.src_ip.clone(),
        })
    }
}

#[cfg(unix)]
fn extract_dev_ino(meta: &std::fs::Metadata) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    Some((meta.dev(), meta.ino()))
}

#[cfg(not(unix))]
fn extract_dev_ino(_meta: &std::fs::Metadata) -> Option<(u64, u64)> {
    None
}

fn compute_cutoff(now: DateTime<Utc>, window: Duration) -> Result<DateTime<Utc>, DomainError> {
    let chrono_window = chrono::Duration::from_std(window).map_err(|err| {
        DomainError::ConfigError(format!("Invalid Suricata correlation_window: {err}"))
    })?;
    Ok(now - chrono_window)
}

fn prune_expired_alerts(alerts: &mut VecDeque<NetworkAlert>, cutoff: DateTime<Utc>) {
    alerts.retain(|alert| alert.timestamp >= cutoff);
}

fn push_bounded_alert(alerts: &mut VecDeque<NetworkAlert>, alert: NetworkAlert) {
    while alerts.len() >= MAX_RECENT_ALERTS {
        alerts.pop_front();
    }
    alerts.push_back(alert);
}

fn select_highest_priority_alert(alerts: &[NetworkAlert]) -> Option<&NetworkAlert> {
    let mut best: Option<&NetworkAlert> = None;
    for candidate in alerts {
        let replace = match best {
            None => true,
            Some(current) => {
                if candidate.severity != current.severity {
                    candidate.severity < current.severity
                } else {
                    candidate.timestamp >= current.timestamp
                }
            }
        };
        if replace {
            best = Some(candidate);
        }
    }
    best
}

async fn validate_eve_path_and_parent(raw_path: &Path) -> Result<PathBuf, DomainError> {
    let file_name = validate_absolute_non_system_file_path(raw_path, "Suricata eve.json")?;
    let normalized_path: PathBuf = raw_path.components().collect();
    reject_forbidden_system_dir(&normalized_path)?;

    let parent = normalized_path.parent().ok_or_else(|| {
        DomainError::InvalidPath(format!(
            "Suricata eve.json path has no parent directory: {}",
            normalized_path.display()
        ))
    })?;
    reject_forbidden_system_dir(parent)?;

    let mut current = PathBuf::from("/");
    for component in parent.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(part) => {
                current.push(part);
                reject_forbidden_system_dir(&current)?;

                let meta = tokio::fs::symlink_metadata(&current)
                    .await
                    .map_err(|err| map_parent_io_err(&current, err))?;

                if meta.file_type().is_symlink() {
                    if let Ok(canonical_target) = tokio::fs::canonicalize(&current).await {
                        reject_forbidden_system_dir(&canonical_target)?;
                    }
                    return Err(DomainError::PathTraversalAttempt(format!(
                        "Symlinks are not permitted in Suricata eve.json ancestor path: {}",
                        current.display()
                    )));
                }

                if !meta.file_type().is_dir() {
                    return Err(DomainError::InvalidPath(format!(
                        "Suricata eve.json ancestor path is not a directory: {}",
                        current.display()
                    )));
                }
            }
            Component::ParentDir => {
                return Err(DomainError::PathTraversalAttempt(format!(
                    "Parent directory traversal ('..') is not allowed in Suricata eve.json path: {}",
                    raw_path.display()
                )));
            }
            Component::Prefix(_) => {
                return Err(DomainError::InvalidPath(format!(
                    "Unsupported path prefix in Suricata eve.json path: {}",
                    raw_path.display()
                )));
            }
        }
    }

    let parent_link_meta = tokio::fs::symlink_metadata(parent)
        .await
        .map_err(|err| map_parent_io_err(parent, err))?;
    let canonical_parent = tokio::fs::canonicalize(parent)
        .await
        .map_err(|err| map_parent_io_err(parent, err))?;
    reject_forbidden_system_dir(&canonical_parent)?;

    if canonical_parent != parent {
        return Err(DomainError::PathTraversalAttempt(format!(
            "Suricata eve.json parent directory changed during canonicalization (TOCTOU): {}",
            parent.display()
        )));
    }

    let canonical_parent_meta = tokio::fs::symlink_metadata(&canonical_parent)
        .await
        .map_err(|err| map_parent_io_err(&canonical_parent, err))?;
    if canonical_parent_meta.file_type().is_symlink() || !canonical_parent_meta.file_type().is_dir()
    {
        return Err(DomainError::InvalidPath(format!(
            "Canonical Suricata eve.json parent is not a regular directory: {}",
            canonical_parent.display()
        )));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if (parent_link_meta.dev(), parent_link_meta.ino())
            != (canonical_parent_meta.dev(), canonical_parent_meta.ino())
        {
            return Err(DomainError::PathTraversalAttempt(format!(
                "Suricata eve.json parent directory identity changed during validation (TOCTOU): {}",
                parent.display()
            )));
        }
    }

    #[cfg(not(unix))]
    let _ = parent_link_meta;

    let canonical_eve_path = canonical_parent.join(file_name);
    reject_forbidden_system_dir(&canonical_eve_path)?;

    Ok(canonical_eve_path)
}

fn map_parent_io_err(path: &Path, err: std::io::Error) -> DomainError {
    match err.kind() {
        ErrorKind::NotFound => DomainError::InvalidPath(format!(
            "Suricata eve.json parent directory does not exist: {}",
            path.display()
        )),
        ErrorKind::NotADirectory => DomainError::InvalidPath(format!(
            "Suricata eve.json path traverses through a non-directory: {}",
            path.display()
        )),
        _ => DomainError::IoError(err),
    }
}

async fn discard_partial_line(
    reader: &mut BufReader<File>,
    eve_path: &Path,
) -> Result<Option<u64>, DomainError> {
    let mut skipped: u64 = 0;

    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(None);
        }

        if let Some(newline_pos) = available.iter().position(|&b| b == b'\n') {
            let consumed = newline_pos + 1;
            let consumed_u64 = usize_to_u64(consumed, eve_path)?;
            reader.consume(consumed);
            skipped = skipped.checked_add(consumed_u64).ok_or_else(|| {
                DomainError::InspectionError(format!(
                    "Skip counter overflowed while tailing {}",
                    eve_path.display()
                ))
            })?;
            return Ok(Some(skipped));
        }

        let len = available.len();
        let len_u64 = usize_to_u64(len, eve_path)?;
        reader.consume(len);
        skipped = skipped.checked_add(len_u64).ok_or_else(|| {
            DomainError::InspectionError(format!(
                "Skip counter overflowed while tailing {}",
                eve_path.display()
            ))
        })?;
    }
}

async fn read_complete_lines(
    reader: &mut BufReader<File>,
    eve_path: &Path,
    start_offset: u64,
    cutoff: DateTime<Utc>,
    recent_alerts: &mut VecDeque<NetworkAlert>,
) -> Result<u64, DomainError> {
    let mut current_offset = start_offset;
    let mut pending_bytes: u64 = 0;
    let mut line_buf: Vec<u8> = Vec::new();
    let mut discarding_oversized = false;

    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            break;
        }

        if let Some(newline_pos) = available.iter().position(|&b| b == b'\n') {
            let segment = &available[..newline_pos];
            let consumed = newline_pos + 1;
            let consumed_u64 = usize_to_u64(consumed, eve_path)?;

            if discarding_oversized || line_buf.len() + segment.len() > MAX_EVE_LINE_BYTES {
                let total_line_bytes = pending_bytes.saturating_add(segment.len() as u64);
                tracing::warn!(
                    eve_path = %eve_path.display(),
                    line_bytes = total_line_bytes,
                    max_bytes = MAX_EVE_LINE_BYTES,
                    "Discarding oversized Suricata eve.json line exceeding 64 KB limit"
                );
                line_buf.clear();
                line_buf.shrink_to(4_096);
                discarding_oversized = false;
            } else {
                let parsed = if line_buf.is_empty() {
                    parse_eve_alert_line(segment)
                } else {
                    append_bounded(&mut line_buf, segment);
                    let res = parse_eve_alert_line(&line_buf);
                    line_buf.clear();
                    res
                };

                if let Some(alert) = parsed
                    && alert.timestamp >= cutoff
                {
                    push_bounded_alert(recent_alerts, alert);
                }
            }

            reader.consume(consumed);
            pending_bytes = pending_bytes.checked_add(consumed_u64).ok_or_else(|| {
                DomainError::InspectionError(format!(
                    "Byte counter overflowed while tailing {}",
                    eve_path.display()
                ))
            })?;
            current_offset = current_offset.checked_add(pending_bytes).ok_or_else(|| {
                DomainError::InspectionError(format!(
                    "File offset overflowed while tailing {}",
                    eve_path.display()
                ))
            })?;
            pending_bytes = 0;
        } else {
            let available_len = available.len();
            let available_u64 = usize_to_u64(available_len, eve_path)?;

            if !discarding_oversized {
                if line_buf.len() + available_len > MAX_EVE_LINE_BYTES {
                    line_buf.clear();
                    line_buf.shrink_to(4_096);
                    discarding_oversized = true;
                } else {
                    append_bounded(&mut line_buf, available);
                }
            }

            reader.consume(available_len);
            pending_bytes = pending_bytes.checked_add(available_u64).ok_or_else(|| {
                DomainError::InspectionError(format!(
                    "Byte counter overflowed while tailing {}",
                    eve_path.display()
                ))
            })?;
        }
    }

    Ok(current_offset)
}

fn append_bounded(line_buf: &mut Vec<u8>, chunk: &[u8]) {
    let needed = line_buf.len() + chunk.len();
    if needed > line_buf.capacity() {
        let target_cap = (line_buf.capacity().saturating_mul(2))
            .max(needed)
            .min(MAX_EVE_LINE_BYTES);
        line_buf.reserve_exact(target_cap - line_buf.len());
    }
    line_buf.extend_from_slice(chunk);
}

fn usize_to_u64(value: usize, eve_path: &Path) -> Result<u64, DomainError> {
    u64::try_from(value).map_err(|err| {
        DomainError::InspectionError(format!(
            "Read byte count exceeds u64 range for {}: {err}",
            eve_path.display()
        ))
    })
}

fn parse_eve_alert_line(raw_line: &[u8]) -> Option<NetworkAlert> {
    let text = match std::str::from_utf8(raw_line) {
        Ok(text) => text.trim(),
        Err(err) => {
            tracing::warn!(error = %err, "Ignoring non-UTF-8 line in Suricata eve.json");
            return None;
        }
    };

    if text.is_empty() {
        return None;
    }

    let event: RawEveEvent = match serde_json::from_str(text) {
        Ok(event) => event,
        Err(err) => {
            tracing::warn!(error = %err, "Ignoring malformed JSON line in Suricata eve.json");
            return None;
        }
    };

    if event.event_type.as_deref() != Some("alert") {
        return None;
    }

    let timestamp_raw = event.timestamp.as_deref().map(str::trim)?;
    let timestamp = parse_eve_timestamp(timestamp_raw)?;
    let src_ip = event
        .src_ip
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())?
        .to_string();
    let dest_ip = event
        .dest_ip
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())?
        .to_string();

    let raw_alert = event.alert?;
    let signature = raw_alert
        .signature
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())?
        .to_string();
    let severity = raw_alert.severity?;

    Some(NetworkAlert {
        timestamp,
        src_ip,
        dest_ip,
        signature,
        severity,
    })
}

fn parse_eve_timestamp(raw: &str) -> Option<DateTime<Utc>> {
    if let Ok(dt) = DateTime::parse_from_rfc3339(raw) {
        return Some(dt.with_timezone(&Utc));
    }

    for fmt in [
        "%Y-%m-%dT%H:%M:%S%.f%#z",
        "%Y-%m-%dT%H:%M:%S%#z",
        "%Y-%m-%dT%H:%M:%S%.f%z",
        "%Y-%m-%dT%H:%M:%S%z",
    ] {
        if let Ok(dt) = DateTime::parse_from_str(raw, fmt) {
            return Some(dt.with_timezone(&Utc));
        }
    }

    tracing::warn!(timestamp = %raw, "Ignoring Suricata alert with unrecognized timestamp format");
    None
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::Write;

    use chrono::Duration as ChronoDuration;
    use tempfile::tempdir;

    use super::*;

    fn test_runtime_config(eve_path: PathBuf) -> Arc<RwLock<RuntimeConfig>> {
        Arc::new(RwLock::new(RuntimeConfig {
            quarantine_dir: PathBuf::from("/var/sentinel/quarantine"),
            approved_dir: PathBuf::from("/var/sentinel/approved"),
            clamd_socket_path: PathBuf::from("/var/run/clamav/clamd.ctl"),
            suricata_eve_path: eve_path,
            updated_at: Utc::now(),
        }))
    }

    fn dummy_artifact(name: &str) -> FileArtifact {
        FileArtifact {
            path: PathBuf::from(format!("/var/sentinel/quarantine/{name}")),
            sanitized_name: name.to_string(),
            extension: FileArtifact::normalize_extension(Path::new(name)),
            size_bytes: 128,
            sha256_hash: "a".repeat(64),
            detected_mime: Some("application/pdf".to_string()),
        }
    }

    fn format_suricata_alert_line(
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

    fn ts_suricata(dt: DateTime<Utc>) -> String {
        dt.format("%Y-%m-%dT%H:%M:%S%.6f+0000").to_string()
    }

    #[tokio::test]
    async fn parses_mixed_ndjson_timestamps_and_resists_malformed_lines() {
        let dir = tempdir().expect("tempdir");
        let eve_path = dir.path().join("eve.json");
        let now = Utc::now();

        let ts_rfc3339 = (now - ChronoDuration::seconds(20)).to_rfc3339();
        let ts_offset_no_colon = ts_suricata(now - ChronoDuration::seconds(10));

        let mut file = File::create(&eve_path).await.expect("create eve.json");
        use tokio::io::AsyncWriteExt;

        let mut payload = Vec::new();
        payload.extend_from_slice(
            format!(
                "{{\"timestamp\":\"{ts_rfc3339}\",\"event_type\":\"dns\",\"src_ip\":\"10.0.0.5\",\"dest_ip\":\"8.8.8.8\"}}\n"
            )
            .as_bytes(),
        );
        payload.extend_from_slice(b"not-valid-json-at-all\n");
        payload.extend_from_slice(b"\xff\xfe\xfd invalid utf8 line\n");
        payload.extend_from_slice(
            format!(
                "{{\"timestamp\":\"{ts_rfc3339}\",\"event_type\":\"flow\",\"src_ip\":\"10.0.0.5\",\"dest_ip\":\"1.1.1.1\"}}\n"
            )
            .as_bytes(),
        );
        payload.extend_from_slice(
            b"{\"timestamp\":\"2026-11-15T00:00:00Z\",\"event_type\":\"stats\",\"uptime\":100}\n",
        );
        // Severity 3 alert (parsed, excluded under default threshold 2)
        payload.extend_from_slice(
            format_suricata_alert_line(
                &ts_rfc3339,
                "192.168.1.99",
                "10.0.0.10",
                "ET INFO Generic Policy",
                3,
            )
            .as_bytes(),
        );
        payload.push(b'\n');
        // Severity 2 alert with RFC3339 timestamp
        payload.extend_from_slice(
            format_suricata_alert_line(
                &ts_rfc3339,
                "203.0.113.10",
                "10.0.0.10",
                "ET MALWARE Suspicious Download",
                2,
            )
            .as_bytes(),
        );
        payload.push(b'\n');
        // Severity 1 alert with Suricata +0000 timestamp
        payload.extend_from_slice(
            format_suricata_alert_line(
                &ts_offset_no_colon,
                "198.51.100.42",
                "10.0.0.10",
                "ET TROJAN Cobalt Strike Beacon",
                1,
            )
            .as_bytes(),
        );
        payload.push(b'\n');

        file.write_all(&payload).await.expect("write payload");
        file.flush().await.expect("flush");
        drop(file);

        let correlator = SuricataCorrelator::new(test_runtime_config(eve_path));
        assert_eq!(correlator.name(), "suricata_eve_correlator");

        let active = correlator.active_alerts().await.expect("active alerts");
        assert_eq!(active.len(), 2);
        assert_eq!(active[0].severity, 2);
        assert_eq!(active[1].severity, 1);

        let verdict = correlator
            .scan(&dummy_artifact("payload.pdf"))
            .await
            .expect("scan");
        assert_eq!(
            verdict,
            SecurityVerdict::SuspiciousNetworkCorrelation {
                alert_signature: "ET TROJAN Cobalt Strike Beacon".to_string(),
                src_ip: "198.51.100.42".to_string(),
            }
        );
    }

    #[tokio::test]
    async fn discards_oversized_line_with_bounded_memory_and_parses_subsequent_alerts() {
        let dir = tempdir().expect("tempdir");
        let eve_path = dir.path().join("eve.json");
        let now = Utc::now();
        let ts = ts_suricata(now);

        let oversized_padding = "A".repeat(MAX_EVE_LINE_BYTES + 8_192);
        let oversized_line = format!(
            "{{\"timestamp\":\"{ts}\",\"event_type\":\"alert\",\"src_ip\":\"10.0.0.1\",\"dest_ip\":\"10.0.0.2\",\"alert\":{{\"signature\":\"{oversized_padding}\",\"severity\":1}}}}\n"
        );
        let valid_after = format!(
            "{}\n",
            format_suricata_alert_line(
                &ts,
                "192.0.2.77",
                "10.0.0.2",
                "ET EXPLOIT Post-Oversized Alert",
                1,
            )
        );

        {
            let mut f = std::fs::File::create(&eve_path).expect("create eve");
            f.write_all(oversized_line.as_bytes())
                .expect("write oversized");
            f.write_all(valid_after.as_bytes()).expect("write valid");
        }

        let correlator = SuricataCorrelator::new(test_runtime_config(eve_path));
        let active = correlator.active_alerts().await.expect("active alerts");
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].signature, "ET EXPLOIT Post-Oversized Alert");
        assert_eq!(active[0].src_ip, "192.0.2.77");

        // Re-syncing does not re-read the discarded oversized line or duplicate the alert.
        let active_again = correlator.active_alerts().await.expect("resync");
        assert_eq!(active_again.len(), 1);
    }

    #[tokio::test]
    async fn handles_incremental_offsets_incomplete_lines_truncation_and_rotation() {
        let dir = tempdir().expect("tempdir");
        let eve_path = dir.path().join("eve.json");
        let rotated_path = dir.path().join("eve.json.1");
        let now = Utc::now();

        let line1 = format!(
            "{}\n",
            format_suricata_alert_line(
                &ts_suricata(now - ChronoDuration::seconds(30)),
                "198.51.100.1",
                "10.0.0.1",
                "Alert One",
                2,
            )
        );
        let partial_line2 = format_suricata_alert_line(
            &ts_suricata(now - ChronoDuration::seconds(20)),
            "198.51.100.2",
            "10.0.0.1",
            "Alert Two",
            1,
        );
        let split_at = partial_line2.len() / 2;
        let first_half = &partial_line2[..split_at];
        let second_half = format!("{}\n", &partial_line2[split_at..]);

        {
            let mut f = std::fs::File::create(&eve_path).expect("create eve");
            f.write_all(line1.as_bytes()).expect("write line1");
            f.write_all(first_half.as_bytes())
                .expect("write partial line2");
        }

        let correlator = SuricataCorrelator::new(test_runtime_config(eve_path.clone()));
        let active1 = correlator.active_alerts().await.expect("sync 1");
        assert_eq!(active1.len(), 1);
        assert_eq!(active1[0].signature, "Alert One");
        assert_eq!(correlator.state.lock().await.offset, line1.len() as u64);

        // Finish writing line2 -> offset advances and Alert Two is parsed cleanly.
        {
            let mut f = OpenOptions::new()
                .append(true)
                .open(&eve_path)
                .expect("open append");
            f.write_all(second_half.as_bytes()).expect("finish line2");
        }
        let active2 = correlator.active_alerts().await.expect("sync 2");
        assert_eq!(active2.len(), 2);
        assert_eq!(active2[1].signature, "Alert Two");

        // Truncate file to a shorter length with a new alert -> offset resets to 0.
        let truncated_alert = format!(
            "{}\n",
            format_suricata_alert_line(
                &ts_suricata(now - ChronoDuration::seconds(10)),
                "198.51.100.3",
                "10.0.0.1",
                "Alert Truncated",
                1,
            )
        );
        {
            let mut f = OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&eve_path)
                .expect("truncate eve");
            f.write_all(truncated_alert.as_bytes())
                .expect("write truncated alert");
        }
        let active3 = correlator.active_alerts().await.expect("sync 3");
        assert!(
            active3.iter().any(|a| a.signature == "Alert Truncated"),
            "truncated file alert must be detected"
        );
        assert_eq!(
            correlator.state.lock().await.offset,
            truncated_alert.len() as u64
        );

        // Simulate log rotation via rename + creating a new inode (even if larger than previous offset!).
        std::fs::rename(&eve_path, &rotated_path).expect("rotate eve.json");
        let rotated_new_alert = format!(
            "{}\n",
            format_suricata_alert_line(
                &ts_suricata(now),
                "198.51.100.4",
                "10.0.0.1",
                "Alert Post Rotation",
                1,
            )
        );
        let padding_dns = format!(
            "{{\"timestamp\":\"{}\",\"event_type\":\"dns\",\"query\":\"example.com\"}}\n",
            ts_suricata(now)
        );
        {
            let mut f = std::fs::File::create(&eve_path).expect("recreate eve");
            for _ in 0..5 {
                f.write_all(padding_dns.as_bytes()).expect("write dns pad");
            }
            f.write_all(rotated_new_alert.as_bytes())
                .expect("write rotated alert");
        }

        let active4 = correlator.active_alerts().await.expect("sync 4");
        assert!(
            active4.iter().any(|a| a.signature == "Alert Post Rotation"),
            "post-rotation alert on new inode must be detected"
        );
    }

    #[tokio::test]
    async fn large_initial_file_seeks_to_last_256kb_and_discards_partial_first_line() {
        let dir = tempdir().expect("tempdir");
        let eve_path = dir.path().join("large_eve.json");
        let now = Utc::now();

        let old_head_alert = format!(
            "{}\n",
            format_suricata_alert_line(
                &ts_suricata(now - ChronoDuration::seconds(5)),
                "203.0.113.200",
                "10.0.0.1",
                "Too Early Before 256KB Tail",
                1,
            )
        );
        let filler_dns = format!(
            "{{\"timestamp\":\"{}\",\"event_type\":\"dns\",\"src_ip\":\"10.0.0.5\",\"rrname\":\"cdn.example.net\",\"padding\":\"{}\"}}\n",
            ts_suricata(now - ChronoDuration::seconds(4)),
            "x".repeat(200)
        );
        let tail_alert = format!(
            "{}\n",
            format_suricata_alert_line(
                &ts_suricata(now),
                "203.0.113.201",
                "10.0.0.1",
                "Alert Within Tail Window",
                1,
            )
        );

        {
            let mut f = std::fs::File::create(&eve_path).expect("create large eve");
            f.write_all(old_head_alert.as_bytes())
                .expect("write early alert");
            let mut written = old_head_alert.len() as u64;
            // Push past INITIAL_TAIL_BYTES + 40 KB so early alert sits strictly before the 256 KB window,
            // and the seek point falls cleanly inside one of the filler_dns lines.
            while written < INITIAL_TAIL_BYTES + 40_960 {
                f.write_all(filler_dns.as_bytes()).expect("write filler");
                written += filler_dns.len() as u64;
            }
            f.write_all(tail_alert.as_bytes())
                .expect("write tail alert");
        }

        let correlator = SuricataCorrelator::new(test_runtime_config(eve_path));
        let active = correlator.active_alerts().await.expect("active alerts");
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].signature, "Alert Within Tail Window");
        assert_eq!(active[0].src_ip, "203.0.113.201");
    }

    #[tokio::test]
    async fn enforces_window_expiration_severity_subnet_priority_and_max_1024_bound() {
        let dir = tempdir().expect("tempdir");
        let eve_path = dir.path().join("policy_eve.json");
        let now = Utc::now();

        {
            let mut f = std::fs::File::create(&eve_path).expect("create policy eve");
            // Expired alert (> 60s old)
            writeln!(
                f,
                "{}",
                format_suricata_alert_line(
                    &ts_suricata(now - ChronoDuration::seconds(120)),
                    "10.20.1.5",
                    "10.20.1.9",
                    "Expired Alert",
                    1,
                )
            )
            .expect("write expired");
            // Non-matching subnet
            writeln!(
                f,
                "{}",
                format_suricata_alert_line(
                    &ts_suricata(now - ChronoDuration::seconds(5)),
                    "172.16.0.10",
                    "172.16.0.20",
                    "Out Of Subnet Alert",
                    1,
                )
            )
            .expect("write other subnet");
            // Severity 3 (excluded when max_severity_threshold == 2)
            writeln!(
                f,
                "{}",
                format_suricata_alert_line(
                    &ts_suricata(now - ChronoDuration::seconds(4)),
                    "10.20.1.6",
                    "10.20.1.9",
                    "Low Severity 3 Alert",
                    3,
                )
            )
            .expect("write sev 3");
            // Severity 2 matching dest_ip subnet
            writeln!(
                f,
                "{}",
                format_suricata_alert_line(
                    &ts_suricata(now - ChronoDuration::seconds(3)),
                    "198.51.100.5",
                    "10.20.5.5",
                    "Medium Severity Dest Match",
                    2,
                )
            )
            .expect("write sev 2");
            // Severity 1 older
            writeln!(
                f,
                "{}",
                format_suricata_alert_line(
                    &ts_suricata(now - ChronoDuration::seconds(2)),
                    "10.20.9.1",
                    "8.8.8.8",
                    "High Severity Older",
                    1,
                )
            )
            .expect("write sev 1 older");
            // Severity 1 newer (must win tie-break!)
            writeln!(
                f,
                "{}",
                format_suricata_alert_line(
                    &ts_suricata(now - ChronoDuration::seconds(1)),
                    "10.20.9.2",
                    "8.8.8.8",
                    "High Severity Newer",
                    1,
                )
            )
            .expect("write sev 1 newer");
        }

        let correlator = SuricataCorrelator::with_policy(
            test_runtime_config(eve_path.clone()),
            Duration::from_secs(60),
            2,
            vec!["10.20.".to_string()],
        );
        let active = correlator.active_alerts().await.expect("active alerts");
        assert_eq!(active.len(), 3);
        let verdict = correlator
            .scan(&dummy_artifact("doc.pdf"))
            .await
            .expect("scan");
        assert_eq!(
            verdict,
            SecurityVerdict::SuspiciousNetworkCorrelation {
                alert_signature: "High Severity Newer".to_string(),
                src_ip: "10.20.9.2".to_string(),
            }
        );

        // Verify strict MAX_RECENT_ALERTS = 1024 cap by writing 1,100 fresh alerts to a second file.
        let flood_path = dir.path().join("flood_eve.json");
        {
            let mut f = std::fs::File::create(&flood_path).expect("create flood eve");
            for idx in 0..1_100usize {
                let ts = ts_suricata(now + ChronoDuration::milliseconds(idx as i64));
                writeln!(
                    f,
                    "{}",
                    format_suricata_alert_line(
                        &ts,
                        "10.30.0.1",
                        "10.30.0.2",
                        &format!("Flood Alert #{idx}"),
                        1,
                    )
                )
                .expect("write flood alert");
            }
        }
        let flood_correlator = SuricataCorrelator::new(test_runtime_config(flood_path));
        let flood_active = flood_correlator
            .active_alerts()
            .await
            .expect("flood active");
        assert_eq!(flood_active.len(), MAX_RECENT_ALERTS);
        assert_eq!(
            flood_active.first().map(|a| a.signature.as_str()),
            Some("Flood Alert #76")
        );
        assert_eq!(
            flood_active.last().map(|a| a.signature.as_str()),
            Some("Flood Alert #1099")
        );
    }

    #[tokio::test]
    async fn enforces_path_security_and_graceful_missing_eve_semantics() {
        let dir = tempdir().expect("tempdir");
        let real_eve = dir.path().join("real_eve.json");
        std::fs::write(&real_eve, b"").expect("write real_eve");

        // 1. Missing eve.json under an existing safe parent succeeds gracefully with Clean verdict.
        let missing_eve = dir.path().join("missing_eve.json");
        let missing_correlator = SuricataCorrelator::new(test_runtime_config(missing_eve));
        missing_correlator
            .sync_alerts()
            .await
            .expect("missing eve.json under safe parent should succeed");
        assert_eq!(
            missing_correlator
                .scan(&dummy_artifact("clean.pdf"))
                .await
                .expect("clean when eve missing"),
            SecurityVerdict::Clean
        );

        // 2. Missing parent directory fails with InvalidPath.
        let missing_parent = dir.path().join("nonexistent_dir/eve.json");
        assert!(matches!(
            SuricataCorrelator::new(test_runtime_config(missing_parent))
                .sync_alerts()
                .await,
            Err(DomainError::InvalidPath(_))
        ));

        // 3. Regular file as parent fails with InvalidPath.
        let file_as_parent = real_eve.join("eve.json");
        assert!(matches!(
            SuricataCorrelator::new(test_runtime_config(file_as_parent))
                .sync_alerts()
                .await,
            Err(DomainError::InvalidPath(_))
        ));

        // 4. Directory as eve.json fails with InvalidPath.
        assert!(matches!(
            SuricataCorrelator::new(test_runtime_config(dir.path().to_path_buf()))
                .sync_alerts()
                .await,
            Err(DomainError::InvalidPath(_))
        ));

        // 5. Relative path, empty path, trailing slash/dot fail with InvalidPath.
        for invalid in [
            PathBuf::new(),
            PathBuf::from("relative/eve.json"),
            PathBuf::from(format!("{}/", real_eve.display())),
            real_eve.join("."),
        ] {
            assert!(
                matches!(
                    SuricataCorrelator::new(test_runtime_config(invalid.clone()))
                        .sync_alerts()
                        .await,
                    Err(DomainError::InvalidPath(_))
                ),
                "expected InvalidPath for {}",
                invalid.display()
            );
        }

        // 6. Traversal '..' and null byte fail with PathTraversalAttempt.
        for traversal in [
            dir.path().join("../eve.json"),
            PathBuf::from("/tmp/eve\0.json"),
        ] {
            assert!(
                matches!(
                    SuricataCorrelator::new(test_runtime_config(traversal.clone()))
                        .sync_alerts()
                        .await,
                    Err(DomainError::PathTraversalAttempt(_))
                ),
                "expected PathTraversalAttempt for {}",
                traversal.display()
            );
        }

        // 7. Forbidden system directories fail with ForbiddenSystemDirectory.
        for forbidden in [
            PathBuf::from("/"),
            PathBuf::from("/eve.json"),
            PathBuf::from("/etc/passwd"),
            PathBuf::from("/etc/suricata/eve.json"),
            PathBuf::from("/proc/1/status"),
        ] {
            assert!(
                matches!(
                    SuricataCorrelator::new(test_runtime_config(forbidden.clone()))
                        .sync_alerts()
                        .await,
                    Err(DomainError::ForbiddenSystemDirectory(_))
                ),
                "expected ForbiddenSystemDirectory for {}",
                forbidden.display()
            );
        }

        #[cfg(unix)]
        {
            // 8. Leaf symlink and dangling leaf symlink fail with PathTraversalAttempt.
            let leaf_symlink = dir.path().join("sym_eve.json");
            std::os::unix::fs::symlink(&real_eve, &leaf_symlink).expect("symlink leaf");
            assert!(matches!(
                SuricataCorrelator::new(test_runtime_config(leaf_symlink))
                    .sync_alerts()
                    .await,
                Err(DomainError::PathTraversalAttempt(_))
            ));

            let dangling_leaf = dir.path().join("dangling_eve.json");
            std::os::unix::fs::symlink(dir.path().join("absent.json"), &dangling_leaf)
                .expect("dangling symlink");
            assert!(matches!(
                SuricataCorrelator::new(test_runtime_config(dangling_leaf))
                    .sync_alerts()
                    .await,
                Err(DomainError::PathTraversalAttempt(_))
            ));

            // 9. Ancestor symlink to safe dir fails with PathTraversalAttempt, and to /etc fails with ForbiddenSystemDirectory.
            let real_sub = dir.path().join("real_sub");
            std::fs::create_dir_all(&real_sub).expect("mkdir real_sub");
            let sym_sub = dir.path().join("sym_sub");
            std::os::unix::fs::symlink(&real_sub, &sym_sub).expect("symlink safe sub");
            assert!(matches!(
                SuricataCorrelator::new(test_runtime_config(sym_sub.join("eve.json")))
                    .sync_alerts()
                    .await,
                Err(DomainError::PathTraversalAttempt(_))
            ));

            let etc_link = dir.path().join("etc_link");
            std::os::unix::fs::symlink("/etc", &etc_link).expect("symlink /etc");
            assert!(matches!(
                SuricataCorrelator::new(test_runtime_config(etc_link.join("eve.json")))
                    .sync_alerts()
                    .await,
                Err(DomainError::ForbiddenSystemDirectory(_))
            ));
        }
    }

    #[tokio::test]
    async fn hot_reloads_suricata_eve_path_and_clears_previous_path_alerts() {
        let dir = tempdir().expect("tempdir");
        let eve_one = dir.path().join("eve_one.json");
        let eve_two = dir.path().join("eve_two.json");
        let now = Utc::now();

        {
            let mut f = std::fs::File::create(&eve_one).expect("create eve_one");
            writeln!(
                f,
                "{}",
                format_suricata_alert_line(
                    &ts_suricata(now),
                    "203.0.113.1",
                    "10.0.0.1",
                    "Old Path Alert",
                    1,
                )
            )
            .expect("write eve_one");
        }
        {
            let mut f = std::fs::File::create(&eve_two).expect("create eve_two");
            writeln!(
                f,
                "{}",
                format_suricata_alert_line(
                    &ts_suricata(now),
                    "203.0.113.2",
                    "10.0.0.2",
                    "New Path Alert",
                    2,
                )
            )
            .expect("write eve_two");
        }

        let runtime_config = test_runtime_config(eve_one);
        let correlator = SuricataCorrelator::new(runtime_config.clone());

        assert_eq!(
            correlator
                .scan(&dummy_artifact("first.pdf"))
                .await
                .expect("scan 1"),
            SecurityVerdict::SuspiciousNetworkCorrelation {
                alert_signature: "Old Path Alert".to_string(),
                src_ip: "203.0.113.1".to_string(),
            }
        );

        // Hot-reload path to eve_two
        {
            let mut guard = runtime_config.write().await;
            guard.suricata_eve_path = eve_two;
        }

        let active_two = correlator.active_alerts().await.expect("active two");
        assert_eq!(active_two.len(), 1);
        assert_eq!(active_two[0].signature, "New Path Alert");
        assert_eq!(
            correlator
                .scan(&dummy_artifact("second.pdf"))
                .await
                .expect("scan 2"),
            SecurityVerdict::SuspiciousNetworkCorrelation {
                alert_signature: "New Path Alert".to_string(),
                src_ip: "203.0.113.2".to_string(),
            }
        );

        // Hot-reload path to missing eve_three under safe parent clears old alerts cleanly.
        {
            let mut guard = runtime_config.write().await;
            guard.suricata_eve_path = dir.path().join("eve_three.json");
        }
        assert_eq!(
            correlator
                .scan(&dummy_artifact("third.pdf"))
                .await
                .expect("scan 3"),
            SecurityVerdict::Clean
        );
    }

    #[tokio::test]
    async fn validate_eve_path_and_parent_returns_canonical_path_and_rejects_suffix_and_control_vectors()
     {
        let dir = tempdir().expect("tempdir");
        let expected_canonical = std::fs::canonicalize(dir.path())
            .expect("canonicalize tempdir")
            .join("eve.json");

        // Redundant '/./' inside a real non-symlink parent still canonicalizes cleanly to the identical parent.
        let with_dot = dir.path().join("./eve.json");
        assert_eq!(
            validate_eve_path_and_parent(&with_dot)
                .await
                .expect("clean parent with dot segment"),
            expected_canonical
        );

        for invalid in [
            PathBuf::from(format!("{}\\.", dir.path().join("eve.json").display())),
            dir.path().join("bad\neve.json"),
        ] {
            assert!(
                matches!(
                    validate_eve_path_and_parent(&invalid).await,
                    Err(DomainError::InvalidPath(_))
                ),
                "expected InvalidPath for {}",
                invalid.display()
            );
        }

        assert!(matches!(
            validate_eve_path_and_parent(&dir.path().join("sub\\eve.json")).await,
            Err(DomainError::PathTraversalAttempt(_))
        ));
    }
}
