//! Asynchronous ClamAV (`clamd`) Unix domain socket adapter using streaming `zINSTREAM` I/O.

use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::sync::RwLock;

use crate::domain::entities::{FileArtifact, RuntimeConfig, SecurityVerdict};
use crate::domain::errors::DomainError;
use crate::domain::path_policy::reject_forbidden_system_dir;
use crate::domain::ports::FileScanner;
use crate::infrastructure::magic_bytes::{STREAM_CHUNK_SIZE, open_regular_file_safely};

/// Default timeout applied to ClamAV socket connection, streaming writes, and response reads.
pub const DEFAULT_CLAMD_TIMEOUT: Duration = Duration::from_secs(30);

/// Upper bound on bytes read from a `clamd` response to prevent unbounded memory allocation.
const MAX_CLAMD_RESPONSE_BYTES: usize = 4_096;

const CLAMD_CMD_INSTREAM: &[u8] = b"zINSTREAM\0";
const CLAMD_CMD_PING: &[u8] = b"zPING\0";

/// Asynchronous ClamAV scanner communicating exclusively over a validated Unix domain socket.
///
/// Reads `clamd_socket_path` from [`RuntimeConfig`] on each invocation so socket path updates
/// take effect immediately without restarting the daemon, and streams file payloads using
/// `zINSTREAM\0` in fixed 64 KB chunks without ever transmitting filesystem paths to `clamd`.
#[derive(Debug, Clone)]
pub struct ClamAvScanner {
    runtime_config: Arc<RwLock<RuntimeConfig>>,
    timeout: Duration,
}

impl ClamAvScanner {
    /// Creates a new [`ClamAvScanner`] with [`DEFAULT_CLAMD_TIMEOUT`].
    pub fn new(runtime_config: Arc<RwLock<RuntimeConfig>>) -> Self {
        Self::with_timeout(runtime_config, DEFAULT_CLAMD_TIMEOUT)
    }

    /// Creates a new [`ClamAvScanner`] with a custom per-operation I/O `timeout`.
    pub fn with_timeout(runtime_config: Arc<RwLock<RuntimeConfig>>, timeout: Duration) -> Self {
        Self {
            runtime_config,
            timeout,
        }
    }

    /// Probes `clamd` availability by sending `zPING\0` and requiring an exact `PONG` response.
    pub async fn ping(&self) -> Result<(), DomainError> {
        #[cfg(not(unix))]
        {
            return Err(DomainError::InspectionError(
                "ClamAV Unix domain socket communication is only supported on Unix platforms"
                    .to_string(),
            ));
        }

        #[cfg(unix)]
        {
            let socket_path = self.current_socket_path().await;
            let validated_socket = validate_socket_path(&socket_path).await?;
            let mut stream = connect_clamd(&validated_socket, self.timeout).await?;

            io_with_timeout(
                "writing zPING to",
                self.timeout,
                stream.write_all(CLAMD_CMD_PING),
            )
            .await
            .map_err(|err| {
                DomainError::InspectionError(format!(
                    "Failed to send zPING command to ClamAV: {err}"
                ))
            })?;
            io_with_timeout("flushing zPING on", self.timeout, stream.flush())
                .await
                .map_err(|err| {
                    DomainError::InspectionError(format!(
                        "Failed to flush zPING command to ClamAV: {err}"
                    ))
                })?;

            let raw_response = read_clamd_response(&mut stream, self.timeout).await?;
            parse_ping_response(&raw_response)
        }
    }

    async fn current_socket_path(&self) -> PathBuf {
        let guard = self.runtime_config.read().await;
        guard.clamd_socket_path.clone()
    }
}

#[async_trait]
impl FileScanner for ClamAvScanner {
    fn name(&self) -> &'static str {
        "clamav_scanner"
    }

    async fn scan(&self, artifact: &FileArtifact) -> Result<SecurityVerdict, DomainError> {
        #[cfg(not(unix))]
        {
            let _ = open_regular_file_safely(&artifact.path).await?;
            return Err(DomainError::InspectionError(
                "ClamAV Unix domain socket communication is only supported on Unix platforms"
                    .to_string(),
            ));
        }

        #[cfg(unix)]
        {
            let mut file = open_regular_file_safely(&artifact.path).await?;
            let socket_path = self.current_socket_path().await;
            let validated_socket = validate_socket_path(&socket_path).await?;
            let mut stream = connect_clamd(&validated_socket, self.timeout).await?;

            if let Err(failure) = stream_file_instream(&mut file, &mut stream, self.timeout).await {
                return Err(resolve_stream_failure(failure, &mut stream, self.timeout).await);
            }

            let raw_response = read_clamd_response(&mut stream, self.timeout).await?;
            let verdict = parse_instream_response(&raw_response)?;

            tracing::debug!(
                scanner = self.name(),
                file_name = %artifact.sanitized_name,
                size_bytes = artifact.size_bytes,
                verdict = ?verdict,
                "ClamAV zINSTREAM scan completed"
            );

            Ok(verdict)
        }
    }
}

/// Validates that `socket_path` is a safe, non-system, non-symlink Unix socket without TOCTOU swaps.
async fn validate_socket_path(socket_path: &Path) -> Result<PathBuf, DomainError> {
    let raw_bytes = socket_path.as_os_str().as_encoded_bytes();
    if raw_bytes.is_empty() {
        return Err(DomainError::InvalidPath(
            "ClamAV socket path must not be empty".to_string(),
        ));
    }

    if raw_bytes.contains(&0) {
        return Err(DomainError::PathTraversalAttempt(
            "ClamAV socket path contains null byte".to_string(),
        ));
    }

    if !socket_path.is_absolute() {
        return Err(DomainError::InvalidPath(format!(
            "ClamAV socket path must be absolute: {}",
            socket_path.display()
        )));
    }

    for component in socket_path.components() {
        if matches!(component, Component::ParentDir) {
            return Err(DomainError::PathTraversalAttempt(format!(
                "Parent directory traversal ('..') is not allowed in ClamAV socket path: {}",
                socket_path.display()
            )));
        }
    }

    if raw_bytes.ends_with(b"/.") {
        return Err(DomainError::InvalidPath(format!(
            "ClamAV socket path must not end with '/.': {}",
            socket_path.display()
        )));
    }

    // Normalize redundant/trailing slashes before lstat so POSIX does not dereference a leaf symlink.
    let normalized_path: PathBuf = socket_path.components().collect();
    reject_forbidden_system_dir(&normalized_path)?;

    let link_meta = match tokio::fs::symlink_metadata(&normalized_path).await {
        Ok(meta) => meta,
        Err(err) => {
            if let Some(parent) = normalized_path.parent()
                && let Ok(canonical_parent) = tokio::fs::canonicalize(parent).await
            {
                reject_forbidden_system_dir(&canonical_parent)?;
            }
            return Err(map_socket_metadata_err(&normalized_path, err));
        }
    };

    let parent = normalized_path.parent().ok_or_else(|| {
        DomainError::InvalidPath(format!(
            "ClamAV socket path has no parent directory: {}",
            normalized_path.display()
        ))
    })?;
    let file_name = normalized_path.file_name().ok_or_else(|| {
        DomainError::InvalidPath(format!(
            "ClamAV socket path has no file name: {}",
            normalized_path.display()
        ))
    })?;

    // Canonicalize parent after capturing link_meta so ancestor symlinks into system dirs or swaps are caught.
    let canonical_parent = tokio::fs::canonicalize(parent)
        .await
        .map_err(|err| map_socket_metadata_err(parent, err))?;
    reject_forbidden_system_dir(&canonical_parent)?;

    ensure_valid_socket_metadata(&normalized_path, &link_meta)?;

    let canonical_socket_path = canonical_parent.join(file_name);
    reject_forbidden_system_dir(&canonical_socket_path)?;

    let canonical_meta = tokio::fs::symlink_metadata(&canonical_socket_path)
        .await
        .map_err(|err| map_socket_metadata_err(&canonical_socket_path, err))?;
    ensure_valid_socket_metadata(&canonical_socket_path, &canonical_meta)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let link_id = (link_meta.dev(), link_meta.ino());
        let canonical_id = (canonical_meta.dev(), canonical_meta.ino());
        if link_id != canonical_id {
            return Err(DomainError::PathTraversalAttempt(format!(
                "ClamAV socket identity changed during validation (TOCTOU): {}",
                normalized_path.display()
            )));
        }
    }

    Ok(canonical_socket_path)
}

fn ensure_valid_socket_metadata(
    path: &Path,
    metadata: &std::fs::Metadata,
) -> Result<(), DomainError> {
    if metadata.file_type().is_symlink() {
        return Err(DomainError::PathTraversalAttempt(format!(
            "Symlinks are not permitted for ClamAV socket path: {}",
            path.display()
        )));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if !metadata.file_type().is_socket() {
            return Err(DomainError::InvalidPath(format!(
                "ClamAV socket path is not a Unix domain socket: {}",
                path.display()
            )));
        }
    }

    Ok(())
}

fn map_socket_metadata_err(path: &Path, err: std::io::Error) -> DomainError {
    match err.kind() {
        ErrorKind::NotFound | ErrorKind::PermissionDenied => DomainError::InspectionError(format!(
            "ClamAV socket unavailable at {}: {err}",
            path.display()
        )),
        _ => DomainError::IoError(err),
    }
}

#[cfg(unix)]
enum StreamFailure {
    LocalFileIo(std::io::Error),
    SocketWrite(std::io::Error),
    Inspection(DomainError),
}

#[cfg(unix)]
async fn connect_clamd(socket_path: &Path, timeout: Duration) -> Result<UnixStream, DomainError> {
    match tokio::time::timeout(timeout, UnixStream::connect(socket_path)).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(err)) => Err(DomainError::InspectionError(format!(
            "Failed to connect to ClamAV socket {}: {err}",
            socket_path.display()
        ))),
        Err(_) => Err(DomainError::InspectionError(format!(
            "Timed out after {}ms connecting to ClamAV socket {}",
            timeout.as_millis(),
            socket_path.display()
        ))),
    }
}

#[cfg(unix)]
async fn stream_file_instream(
    file: &mut File,
    stream: &mut UnixStream,
    timeout: Duration,
) -> Result<(), StreamFailure> {
    io_with_timeout(
        "writing zINSTREAM header to",
        timeout,
        stream.write_all(CLAMD_CMD_INSTREAM),
    )
    .await
    .map_err(StreamFailure::SocketWrite)?;

    let mut buffer = vec![0u8; STREAM_CHUNK_SIZE];
    loop {
        let bytes_read = file
            .read(&mut buffer)
            .await
            .map_err(StreamFailure::LocalFileIo)?;
        if bytes_read == 0 {
            break;
        }

        let chunk_len = u32::try_from(bytes_read).map_err(|err| {
            StreamFailure::Inspection(DomainError::InspectionError(format!(
                "Read chunk length exceeds u32 protocol frame limit: {err}"
            )))
        })?;

        let frame_len = chunk_len.to_be_bytes();
        io_with_timeout(
            "writing chunk header to",
            timeout,
            stream.write_all(&frame_len),
        )
        .await
        .map_err(StreamFailure::SocketWrite)?;
        io_with_timeout(
            "writing chunk payload to",
            timeout,
            stream.write_all(&buffer[..bytes_read]),
        )
        .await
        .map_err(StreamFailure::SocketWrite)?;
    }

    let eof_marker = 0u32.to_be_bytes();
    io_with_timeout(
        "writing EOF marker to",
        timeout,
        stream.write_all(&eof_marker),
    )
    .await
    .map_err(StreamFailure::SocketWrite)?;
    io_with_timeout("flushing zINSTREAM on", timeout, stream.flush())
        .await
        .map_err(StreamFailure::SocketWrite)?;

    Ok(())
}

#[cfg(unix)]
async fn resolve_stream_failure(
    failure: StreamFailure,
    stream: &mut UnixStream,
    timeout: Duration,
) -> DomainError {
    match failure {
        StreamFailure::LocalFileIo(err) => DomainError::IoError(err),
        StreamFailure::Inspection(err) => err,
        StreamFailure::SocketWrite(io_err) => {
            // clamd can close early after emitting an error (e.g., INSTREAM size limit exceeded).
            if matches!(
                io_err.kind(),
                ErrorKind::BrokenPipe | ErrorKind::ConnectionReset
            ) && let Ok(raw) = read_clamd_response(stream, timeout).await
                && let Err(parsed_err) = parse_instream_response(&raw)
            {
                return parsed_err;
            }
            DomainError::InspectionError(format!(
                "Failed while streaming payload to ClamAV socket: {io_err}"
            ))
        }
    }
}

#[cfg(unix)]
async fn io_with_timeout<F>(op: &str, timeout: Duration, fut: F) -> Result<(), std::io::Error>
where
    F: std::future::Future<Output = Result<(), std::io::Error>>,
{
    match tokio::time::timeout(timeout, fut).await {
        Ok(res) => res,
        Err(_) => Err(std::io::Error::new(
            ErrorKind::TimedOut,
            format!(
                "Timed out after {}ms {op} ClamAV socket",
                timeout.as_millis()
            ),
        )),
    }
}

#[cfg(unix)]
async fn read_clamd_response(
    stream: &mut UnixStream,
    timeout: Duration,
) -> Result<Vec<u8>, DomainError> {
    let mut response = Vec::with_capacity(128);
    let max_read = (MAX_CLAMD_RESPONSE_BYTES + 1) as u64;

    let read_result = tokio::time::timeout(timeout, async {
        let mut limited = stream.take(max_read);
        limited.read_to_end(&mut response).await
    })
    .await;

    match read_result {
        Ok(Ok(_)) => {}
        Ok(Err(err)) => {
            return Err(DomainError::InspectionError(format!(
                "Failed to read response from ClamAV socket: {err}"
            )));
        }
        Err(_) => {
            return Err(DomainError::InspectionError(format!(
                "Timed out after {}ms waiting for ClamAV response",
                timeout.as_millis()
            )));
        }
    }

    if response.len() > MAX_CLAMD_RESPONSE_BYTES {
        return Err(DomainError::InspectionError(format!(
            "ClamAV response exceeded maximum allowed size of {MAX_CLAMD_RESPONSE_BYTES} bytes"
        )));
    }

    if response.is_empty() {
        return Err(DomainError::InspectionError(
            "ClamAV closed connection with empty response (EOF)".to_string(),
        ));
    }

    Ok(response)
}

fn trim_clamd_response(raw: &[u8]) -> Result<&str, DomainError> {
    let text = std::str::from_utf8(raw).map_err(|err| {
        DomainError::InspectionError(format!("ClamAV response is not valid UTF-8: {err}"))
    })?;
    let trimmed = text.trim_end_matches(['\0', '\r', '\n']);
    if trimmed.is_empty() {
        return Err(DomainError::InspectionError(
            "ClamAV returned an empty response".to_string(),
        ));
    }
    Ok(trimmed)
}

/// Strictly parses a `clamd` `zINSTREAM` reply (`stream: OK`, `stream: <THREAT> FOUND`, or error).
fn parse_instream_response(raw: &[u8]) -> Result<SecurityVerdict, DomainError> {
    let trimmed = trim_clamd_response(raw)?;
    let payload = trimmed.strip_prefix("stream: ").ok_or_else(|| {
        DomainError::InspectionError(format!(
            "Unexpected ClamAV zINSTREAM response format: {trimmed:?}"
        ))
    })?;

    if payload == "OK" {
        return Ok(SecurityVerdict::Clean);
    }

    if payload == "ERROR" || payload.ends_with(" ERROR") {
        return Err(DomainError::InspectionError(format!(
            "ClamAV daemon reported scan error: {trimmed:?}"
        )));
    }

    if let Some(raw_threat) = payload.strip_suffix(" FOUND") {
        if raw_threat.chars().any(char::is_control) {
            return Err(DomainError::InspectionError(format!(
                "ClamAV threat name contains control characters: {raw_threat:?}"
            )));
        }
        let threat_name = raw_threat.trim();
        if threat_name.is_empty() {
            return Err(DomainError::InspectionError(
                "ClamAV reported FOUND verdict without a threat name".to_string(),
            ));
        }
        return Ok(SecurityVerdict::MaliciousSignature {
            threat_name: threat_name.to_string(),
        });
    }

    Err(DomainError::InspectionError(format!(
        "Unrecognized ClamAV zINSTREAM response: {trimmed:?}"
    )))
}

#[cfg(unix)]
fn parse_ping_response(raw: &[u8]) -> Result<(), DomainError> {
    let trimmed = trim_clamd_response(raw)?;
    if trimmed == "PONG" {
        Ok(())
    } else {
        Err(DomainError::InspectionError(format!(
            "Unexpected ClamAV zPING response: {trimmed:?}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use std::process::Command;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use chrono::Utc;
    use sha2::{Digest, Sha256};
    use tempfile::tempdir;
    use tokio::net::UnixListener;

    use super::*;

    fn test_runtime_config(socket_path: PathBuf) -> Arc<RwLock<RuntimeConfig>> {
        Arc::new(RwLock::new(RuntimeConfig {
            quarantine_dir: PathBuf::from("/var/sentinel/quarantine"),
            approved_dir: PathBuf::from("/var/sentinel/approved"),
            clamd_socket_path: socket_path,
            suricata_eve_path: PathBuf::from("/var/log/suricata/eve.json"),
            updated_at: Utc::now(),
        }))
    }

    fn make_artifact(path: &Path, size_bytes: u64) -> FileArtifact {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("utf8 filename")
            .to_string();
        FileArtifact {
            path: path.to_path_buf(),
            sanitized_name: name,
            extension: FileArtifact::normalize_extension(path),
            size_bytes,
            sha256_hash: "0".repeat(64),
            detected_mime: None,
        }
    }

    async fn read_instream_request(stream: &mut UnixStream) -> Vec<u8> {
        let mut cmd = [0u8; 10];
        stream
            .read_exact(&mut cmd)
            .await
            .expect("read zINSTREAM command");
        assert_eq!(&cmd, CLAMD_CMD_INSTREAM);

        let mut payload = Vec::new();
        loop {
            let mut len_buf = [0u8; 4];
            stream
                .read_exact(&mut len_buf)
                .await
                .expect("read chunk len");
            let chunk_len = u32::from_be_bytes(len_buf) as usize;
            if chunk_len == 0 {
                break;
            }
            assert!(
                chunk_len <= STREAM_CHUNK_SIZE,
                "chunk length {chunk_len} exceeded STREAM_CHUNK_SIZE"
            );
            let mut chunk = vec![0u8; chunk_len];
            stream.read_exact(&mut chunk).await.expect("read chunk");
            payload.extend_from_slice(&chunk);
        }
        payload
    }

    #[test]
    fn parse_instream_response_enforces_strict_clamd_grammar() {
        assert_eq!(
            parse_instream_response(b"stream: OK\0").expect("stream OK null"),
            SecurityVerdict::Clean
        );
        assert_eq!(
            parse_instream_response(b"stream: OK\r\n").expect("stream OK crlf"),
            SecurityVerdict::Clean
        );
        assert_eq!(
            parse_instream_response(b"stream: OK").expect("stream OK bare"),
            SecurityVerdict::Clean
        );

        assert_eq!(
            parse_instream_response(b"stream: Win.Test.EICAR_HDB-1 FOUND\0").expect("stream FOUND"),
            SecurityVerdict::MaliciousSignature {
                threat_name: "Win.Test.EICAR_HDB-1".to_string(),
            }
        );
        assert_eq!(
            parse_instream_response(b"stream: Eicar-Signature FOUND\n").expect("stream FOUND lf"),
            SecurityVerdict::MaliciousSignature {
                threat_name: "Eicar-Signature".to_string(),
            }
        );

        let invalid_responses: &[&[u8]] = &[
            b"",
            b"\0\r\n",
            b"\xff\xfe\0",
            b"OK\0",
            b"/tmp/file.bin: OK\0",
            b"stream: OK\0extra",
            b"stream: FOUND\0",
            b"stream:    FOUND\0",
            b"stream: Evil\x1b[31m FOUND\0",
            b"stream: Evil\0Name FOUND\0",
            b"stream: Evil\nName FOUND\0",
            b"stream: Evil\tName FOUND\0",
            b"stream: INSTREAM size limit exceeded. ERROR\0",
            b"stream: ERROR\0",
            b"UNKNOWN COMMAND\0",
            b"stream: UNKNOWN\0",
        ];

        for raw in invalid_responses {
            let err = parse_instream_response(raw)
                .expect_err(&format!("expected InspectionError for {raw:?}"));
            assert!(
                matches!(err, DomainError::InspectionError(_)),
                "expected InspectionError for {raw:?}, got {err:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn parse_ping_response_requires_exact_pong() {
        assert!(parse_ping_response(b"PONG\0").is_ok());
        assert!(parse_ping_response(b"PONG\r\n").is_ok());
        assert!(parse_ping_response(b"PONG").is_ok());

        for bad in [
            b"".as_slice(),
            b"\0\n",
            b"PING\0",
            b"PONG\0extra",
            b"PONG!",
            b"\xff\xfe",
        ] {
            assert!(matches!(
                parse_ping_response(bad),
                Err(DomainError::InspectionError(_))
            ));
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn validate_socket_path_rejects_unsafe_paths_and_accepts_canonical_socket() {
        let dir = tempdir().expect("tempdir");

        assert!(matches!(
            validate_socket_path(Path::new("")).await,
            Err(DomainError::InvalidPath(_))
        ));
        assert!(matches!(
            validate_socket_path(Path::new("/tmp/clam\0.ctl")).await,
            Err(DomainError::PathTraversalAttempt(_))
        ));
        assert!(matches!(
            validate_socket_path(Path::new("relative/clamd.ctl")).await,
            Err(DomainError::InvalidPath(_))
        ));
        assert!(matches!(
            validate_socket_path(&dir.path().join("../clamd.ctl")).await,
            Err(DomainError::PathTraversalAttempt(_))
        ));
        assert!(matches!(
            validate_socket_path(Path::new("/tmp/clamd.ctl/.")).await,
            Err(DomainError::InvalidPath(_))
        ));

        for forbidden in ["/", "/etc/clamav/clamd.ctl", "/dev/log", "/proc/1/fd/0"] {
            assert!(
                matches!(
                    validate_socket_path(Path::new(forbidden)).await,
                    Err(DomainError::ForbiddenSystemDirectory(_))
                ),
                "expected ForbiddenSystemDirectory for {forbidden}"
            );
        }

        // Missing socket maps to InspectionError
        assert!(matches!(
            validate_socket_path(&dir.path().join("missing.ctl")).await,
            Err(DomainError::InspectionError(_))
        ));

        // Regular file, directory, and FIFO must return InvalidPath
        let regular_file = dir.path().join("regular.ctl");
        std::fs::write(&regular_file, b"not a socket").expect("write regular");
        assert!(matches!(
            validate_socket_path(&regular_file).await,
            Err(DomainError::InvalidPath(_))
        ));

        let sub_dir = dir.path().join("subdir");
        std::fs::create_dir_all(&sub_dir).expect("mkdir");
        assert!(matches!(
            validate_socket_path(&sub_dir).await,
            Err(DomainError::InvalidPath(_))
        ));

        let fifo_path = dir.path().join("pipe.ctl");
        let mkfifo_status = Command::new("mkfifo")
            .arg(&fifo_path)
            .status()
            .expect("invoke mkfifo");
        assert!(mkfifo_status.success(), "mkfifo must succeed");
        assert!(matches!(
            validate_socket_path(&fifo_path).await,
            Err(DomainError::InvalidPath(_))
        ));

        // Real socket + symlink rejections + trailing slash normalization + safe parent symlink
        let real_dir = dir.path().join("real_run");
        std::fs::create_dir_all(&real_dir).expect("mkdir real_run");
        let socket_path = real_dir.join("clamd.ctl");
        let _listener = UnixListener::bind(&socket_path).expect("bind unix socket");

        let socket_symlink = dir.path().join("link.ctl");
        std::os::unix::fs::symlink(&socket_path, &socket_symlink).expect("symlink socket");
        assert!(matches!(
            validate_socket_path(&socket_symlink).await,
            Err(DomainError::PathTraversalAttempt(_))
        ));

        let dangling_symlink = dir.path().join("dangling.ctl");
        std::os::unix::fs::symlink(dir.path().join("absent.ctl"), &dangling_symlink)
            .expect("dangling symlink");
        assert!(matches!(
            validate_socket_path(&dangling_symlink).await,
            Err(DomainError::PathTraversalAttempt(_))
        ));

        let etc_link = dir.path().join("etc_link");
        std::os::unix::fs::symlink("/etc", &etc_link).expect("symlink /etc");
        assert!(matches!(
            validate_socket_path(&etc_link.join("clamd.ctl")).await,
            Err(DomainError::ForbiddenSystemDirectory(_))
        ));
        if Path::new("/etc/passwd").exists() {
            assert!(matches!(
                validate_socket_path(&etc_link.join("passwd")).await,
                Err(DomainError::ForbiddenSystemDirectory(_))
            ));
        }

        // Trailing slash should be stripped so leaf socket validation still succeeds
        let trailing_slash = PathBuf::from(format!("{}/", socket_path.display()));
        let expected_canonical = tokio::fs::canonicalize(&real_dir)
            .await
            .expect("canonicalize real_dir")
            .join("clamd.ctl");
        assert_eq!(
            validate_socket_path(&trailing_slash)
                .await
                .expect("trailing slash socket"),
            expected_canonical
        );

        // Safe ancestor symlink (similar to /var/run -> /run) resolves cleanly to canonical parent
        let safe_parent_alias = dir.path().join("var_run");
        std::os::unix::fs::symlink(&real_dir, &safe_parent_alias).expect("symlink safe parent");
        assert_eq!(
            validate_socket_path(&safe_parent_alias.join("clamd.ctl"))
                .await
                .expect("safe parent alias socket"),
            expected_canonical
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn scanner_streams_empty_eicar_and_multi_chunk_files_without_sending_paths() {
        let dir = tempdir().expect("tempdir");
        let socket_path = dir.path().join("clamd.ctl");
        let listener = UnixListener::bind(&socket_path).expect("bind mock clamd");

        let eicar_payload =
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*".to_vec();
        let multi_chunk_payload: Vec<u8> = (0..(STREAM_CHUNK_SIZE * 2 + 1_337))
            .map(|i| ((i.wrapping_mul(31) ^ (i >> 6)) % 251) as u8)
            .collect();
        let expected_multi_digest = Sha256::digest(&multi_chunk_payload).to_vec();

        let empty_file = dir.path().join("empty.txt");
        let eicar_file = dir.path().join("eicar_secret_path.txt");
        let multi_file = dir.path().join("large_clean.bin");
        std::fs::write(&empty_file, b"").expect("write empty");
        std::fs::write(&eicar_file, &eicar_payload).expect("write eicar");
        std::fs::write(&multi_file, &multi_chunk_payload).expect("write multi chunk");

        let server_task = tokio::spawn(async move {
            // 1. Empty file
            {
                let (mut s1, _) = listener.accept().await.expect("accept 1");
                let data1 = read_instream_request(&mut s1).await;
                assert!(data1.is_empty());
                s1.write_all(b"stream: OK\0").await.expect("reply 1");
            }

            // 2. EICAR file
            {
                let (mut s2, _) = listener.accept().await.expect("accept 2");
                let data2 = read_instream_request(&mut s2).await;
                assert_eq!(data2, eicar_payload);
                s2.write_all(b"stream: Win.Test.EICAR_HDB-1 FOUND\0")
                    .await
                    .expect("reply 2");
            }

            // 3. Multi-chunk file (> 2 * 64 KB)
            {
                let (mut s3, _) = listener.accept().await.expect("accept 3");
                let data3 = read_instream_request(&mut s3).await;
                assert_eq!(
                    Sha256::digest(&data3).as_slice(),
                    expected_multi_digest.as_slice()
                );
                s3.write_all(b"stream: OK\0").await.expect("reply 3");
            }
        });

        let concrete_scanner = ClamAvScanner::new(test_runtime_config(socket_path));
        assert_eq!(concrete_scanner.timeout, DEFAULT_CLAMD_TIMEOUT);
        let scanner: Arc<dyn FileScanner> = Arc::new(concrete_scanner);
        assert_eq!(scanner.name(), "clamav_scanner");

        let v1 = scanner
            .scan(&make_artifact(&empty_file, 0))
            .await
            .expect("scan empty");
        assert_eq!(v1, SecurityVerdict::Clean);

        let v2 = scanner
            .scan(&make_artifact(&eicar_file, 68))
            .await
            .expect("scan eicar");
        assert_eq!(
            v2,
            SecurityVerdict::MaliciousSignature {
                threat_name: "Win.Test.EICAR_HDB-1".to_string(),
            }
        );

        let v3 = scanner
            .scan(&make_artifact(
                &multi_file,
                multi_chunk_payload.len() as u64,
            ))
            .await
            .expect("scan multi chunk");
        assert_eq!(v3, SecurityVerdict::Clean);

        server_task.await.expect("mock server task");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn scanner_ping_and_dynamic_socket_reload_work_at_runtime() {
        let dir = tempdir().expect("tempdir");
        let socket_one = dir.path().join("clamd_one.ctl");
        let socket_two = dir.path().join("clamd_two.ctl");

        let listener_one = UnixListener::bind(&socket_one).expect("bind one");
        let listener_two = UnixListener::bind(&socket_two).expect("bind two");

        let server_one = tokio::spawn(async move {
            let (mut stream, _) = listener_one.accept().await.expect("accept one");
            let mut cmd = [0u8; 6];
            stream.read_exact(&mut cmd).await.expect("read ping one");
            assert_eq!(&cmd, CLAMD_CMD_PING);
            stream.write_all(b"PONG\0").await.expect("write pong one");
        });

        let server_two = tokio::spawn(async move {
            let (mut stream, _) = listener_two.accept().await.expect("accept two");
            let mut cmd = [0u8; 6];
            stream.read_exact(&mut cmd).await.expect("read ping two");
            assert_eq!(&cmd, CLAMD_CMD_PING);
            stream.write_all(b"PONG\n").await.expect("write pong two");
        });

        let runtime_config = test_runtime_config(socket_one);
        let scanner = ClamAvScanner::new(runtime_config.clone());

        scanner.ping().await.expect("ping first socket");
        server_one.await.expect("server one finished");

        {
            let mut guard = runtime_config.write().await;
            guard.clamd_socket_path = socket_two;
        }

        scanner
            .ping()
            .await
            .expect("ping dynamically reloaded socket");
        server_two.await.expect("server two finished");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn scanner_handles_timeouts_oversized_replies_eof_and_early_error_close() {
        let dir = tempdir().expect("tempdir");
        let socket_path = dir.path().join("clamd_faults.ctl");
        let listener = UnixListener::bind(&socket_path).expect("bind fault server");

        let sample_file = dir.path().join("sample.pdf");
        std::fs::write(&sample_file, b"%PDF-1.5\nsample\n").expect("write sample");

        let scenario_counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = Arc::clone(&scenario_counter);

        let server_task = tokio::spawn(async move {
            for _ in 0..4 {
                let (mut stream, _) = listener.accept().await.expect("accept fault case");
                let idx = counter_clone.fetch_add(1, Ordering::SeqCst);
                match idx {
                    // 0: Timeout (hangs after receiving request)
                    0 => {
                        let _ = read_instream_request(&mut stream).await;
                        tokio::time::sleep(Duration::from_millis(250)).await;
                    }
                    // 1: Oversized response (> MAX_CLAMD_RESPONSE_BYTES)
                    1 => {
                        let _ = read_instream_request(&mut stream).await;
                        let oversized = vec![b'A'; MAX_CLAMD_RESPONSE_BYTES + 256];
                        let _ = stream.write_all(&oversized).await;
                    }
                    // 2: Empty EOF
                    2 => {
                        let _ = read_instream_request(&mut stream).await;
                        drop(stream);
                    }
                    // 3: clamd reports stream size error
                    3 => {
                        let _ = read_instream_request(&mut stream).await;
                        let _ = stream
                            .write_all(b"stream: INSTREAM size limit exceeded. ERROR\0")
                            .await;
                    }
                    _ => unreachable!(),
                }
            }
        });

        let scanner = ClamAvScanner::with_timeout(
            test_runtime_config(socket_path),
            Duration::from_millis(50),
        );
        let artifact = make_artifact(&sample_file, 16);

        for case in ["timeout", "oversized", "empty_eof", "clamd_error"] {
            let err = scanner
                .scan(&artifact)
                .await
                .expect_err(&format!("case {case} must fail"));
            assert!(
                matches!(err, DomainError::InspectionError(_)),
                "expected InspectionError for {case}, got {err:?}"
            );
        }

        server_task.await.expect("fault server finished");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn scanner_reuses_safe_file_validation_for_symlinks_traversal_and_system_dirs() {
        let dir = tempdir().expect("tempdir");
        let scanner = ClamAvScanner::new(test_runtime_config(dir.path().join("unused.ctl")));

        let target = dir.path().join("real.txt");
        std::fs::write(&target, b"hello").expect("write target");
        let symlink_file = dir.path().join("sym.txt");
        std::os::unix::fs::symlink(&target, &symlink_file).expect("symlink");

        assert!(matches!(
            scanner.scan(&make_artifact(&symlink_file, 5)).await,
            Err(DomainError::PathTraversalAttempt(_))
        ));

        let traversal = dir.path().join("sub/../real.txt");
        assert!(matches!(
            scanner.scan(&make_artifact(&traversal, 5)).await,
            Err(DomainError::PathTraversalAttempt(_))
        ));

        if Path::new("/etc/passwd").exists() {
            assert!(matches!(
                scanner
                    .scan(&make_artifact(Path::new("/etc/passwd"), 10))
                    .await,
                Err(DomainError::ForbiddenSystemDirectory(_))
            ));
        }

        assert!(matches!(
            scanner.scan(&make_artifact(dir.path(), 0)).await,
            Err(DomainError::InvalidPath(_))
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn scanner_captures_error_reply_when_clamd_closes_mid_stream_and_rejects_bad_ping() {
        let dir = tempdir().expect("tempdir");
        let socket_path = dir.path().join("clamd_midstream.ctl");
        let listener = UnixListener::bind(&socket_path).expect("bind midstream");

        // Create a 2 MB file to exceed socket buffer when server rejects after reading header/first chunk.
        let big_file = dir.path().join("too_big.bin");
        let payload = vec![0x42u8; STREAM_CHUNK_SIZE * 32];
        std::fs::write(&big_file, &payload).expect("write big file");

        let server_task = tokio::spawn(async move {
            // 1. Mid-stream size-limit abort
            let (mut s1, _) = listener.accept().await.expect("accept midstream");
            let mut cmd = [0u8; 10];
            s1.read_exact(&mut cmd).await.expect("read zINSTREAM");
            let _ = s1
                .write_all(b"stream: INSTREAM size limit exceeded. ERROR\0")
                .await;
            drop(s1);

            // 2. Bad ping response ("PING\0" instead of "PONG\0")
            let (mut s2, _) = listener.accept().await.expect("accept bad ping");
            let mut ping_cmd = [0u8; 6];
            s2.read_exact(&mut ping_cmd).await.expect("read zPING");
            let _ = s2.write_all(b"PING\0").await;
        });

        let scanner =
            ClamAvScanner::with_timeout(test_runtime_config(socket_path), Duration::from_secs(2));
        let err = scanner
            .scan(&make_artifact(&big_file, payload.len() as u64))
            .await
            .expect_err("mid-stream size limit error must fail");
        assert!(
            matches!(err, DomainError::InspectionError(ref msg) if msg.contains("INSTREAM size limit exceeded") || msg.contains("Failed while streaming")),
            "unexpected error for mid-stream close: {err:?}"
        );

        let ping_err = scanner
            .ping()
            .await
            .expect_err("unexpected ping reply must fail");
        assert!(matches!(ping_err, DomainError::InspectionError(_)));

        server_task.await.expect("midstream server finished");
    }
}
