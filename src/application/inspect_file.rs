//! Use case orchestrating the streaming zero-trust file inspection pipeline.

use std::path::Path;
use std::sync::Arc;

use chrono::Utc;
use tokio::sync::RwLock;

use crate::domain::entities::{FileArtifact, InspectionReport, RuntimeConfig, SecurityVerdict};
use crate::domain::errors::DomainError;
use crate::domain::path_policy::reject_forbidden_system_dir;
pub use crate::domain::path_policy::sanitize_file_name;
use crate::domain::ports::{
    FileScanner, HashCalculator, MimeValidator, QuarantineMover, QuarantineRepo,
};

/// Orchestrates permission hardening, streaming hashing, MIME detection, scanning, disposition, and persistence.
pub struct InspectFileUseCase {
    hash_calculator: Arc<dyn HashCalculator>,
    mime_validator: Arc<dyn MimeValidator>,
    scanners: Vec<Arc<dyn FileScanner>>,
    quarantine_mover: Arc<dyn QuarantineMover>,
    quarantine_repo: Arc<dyn QuarantineRepo>,
    runtime_config: Arc<RwLock<RuntimeConfig>>,
}

impl InspectFileUseCase {
    /// Creates a new [`InspectFileUseCase`] with injected domain ports and shared runtime configuration.
    pub fn new(
        hash_calculator: Arc<dyn HashCalculator>,
        mime_validator: Arc<dyn MimeValidator>,
        scanners: Vec<Arc<dyn FileScanner>>,
        quarantine_mover: Arc<dyn QuarantineMover>,
        quarantine_repo: Arc<dyn QuarantineRepo>,
        runtime_config: Arc<RwLock<RuntimeConfig>>,
    ) -> Self {
        Self {
            hash_calculator,
            mime_validator,
            scanners,
            quarantine_mover,
            quarantine_repo,
            runtime_config,
        }
    }

    /// Executes the full inspection pipeline for `source_path` and persists an [`InspectionReport`].
    pub async fn execute(&self, source_path: &Path) -> Result<InspectionReport, DomainError> {
        let sanitized_name = sanitize_file_name(source_path)?;
        let extension = FileArtifact::normalize_extension(Path::new(&sanitized_name));

        let config = self.runtime_config.read().await.clone();

        reject_forbidden_system_dir(source_path)?;
        if !source_path.starts_with(&config.quarantine_dir) || source_path == config.quarantine_dir
        {
            return Err(DomainError::PathTraversalAttempt(format!(
                "Source path '{}' is outside configured quarantine directory '{}'",
                source_path.display(),
                config.quarantine_dir.display()
            )));
        }

        self.quarantine_mover
            .harden_permissions(source_path, false)
            .await?;

        let (sha256_hash, size_bytes) = self.hash_calculator.calculate_sha256(source_path).await?;
        let detected_mime = self.mime_validator.detect_mime(source_path).await?;

        let artifact = FileArtifact {
            path: source_path.to_path_buf(),
            sanitized_name,
            extension,
            size_bytes,
            sha256_hash,
            detected_mime,
        };

        let verdict = self.run_scanners(&artifact).await?;

        let destination_path = match &verdict {
            SecurityVerdict::Clean => {
                self.quarantine_mover
                    .move_to_approved(source_path, &config.approved_dir)
                    .await?
            }
            _ => {
                self.quarantine_mover
                    .isolate_rejected(source_path, &config.quarantine_dir)
                    .await?
            }
        };

        let mut report = InspectionReport {
            id: None,
            artifact,
            verdict,
            destination_path: Some(destination_path),
            inspected_at: Utc::now(),
        };

        let report_id = self.quarantine_repo.save_report(&report).await?;
        report.id = Some(report_id);

        tracing::info!(
            report_id,
            file_name = %report.artifact.sanitized_name,
            size_bytes = report.artifact.size_bytes,
            sha256_hash = %report.artifact.sha256_hash,
            detected_mime = report.artifact.detected_mime.as_deref().unwrap_or("none"),
            verdict = ?report.verdict,
            "File inspection completed"
        );

        Ok(report)
    }

    async fn run_scanners(&self, artifact: &FileArtifact) -> Result<SecurityVerdict, DomainError> {
        for scanner in &self.scanners {
            let verdict = scanner.scan(artifact).await?;
            if verdict != SecurityVerdict::Clean {
                tracing::warn!(
                    scanner = scanner.name(),
                    file_name = %artifact.sanitized_name,
                    verdict = ?verdict,
                    "Scanner reported non-clean verdict; halting pipeline"
                );
                return Ok(verdict);
            }
        }
        Ok(SecurityVerdict::Clean)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    use async_trait::async_trait;

    use super::*;

    struct MockHasher {
        result: Result<(String, u64), String>,
        events: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl HashCalculator for MockHasher {
        async fn calculate_sha256(&self, path: &Path) -> Result<(String, u64), DomainError> {
            self.events
                .lock()
                .expect("events mutex")
                .push(format!("hash:{}", path.display()));
            self.result.clone().map_err(DomainError::InspectionError)
        }
    }

    struct MockMimeValidator {
        mime: Result<Option<String>, String>,
        events: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl MimeValidator for MockMimeValidator {
        async fn detect_mime(&self, path: &Path) -> Result<Option<String>, DomainError> {
            self.events
                .lock()
                .expect("events mutex")
                .push(format!("mime:{}", path.display()));
            self.mime.clone().map_err(DomainError::InspectionError)
        }
    }

    struct MockScanner {
        scanner_name: &'static str,
        verdict: SecurityVerdict,
        called: Arc<AtomicBool>,
        events: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl FileScanner for MockScanner {
        fn name(&self) -> &'static str {
            self.scanner_name
        }

        async fn scan(&self, artifact: &FileArtifact) -> Result<SecurityVerdict, DomainError> {
            self.called.store(true, Ordering::SeqCst);
            self.events.lock().expect("events mutex").push(format!(
                "scan:{}:{}",
                self.scanner_name, artifact.sanitized_name
            ));
            Ok(self.verdict.clone())
        }
    }

    struct FailingScanner;

    #[async_trait]
    impl FileScanner for FailingScanner {
        fn name(&self) -> &'static str {
            "failing_scanner"
        }

        async fn scan(&self, _artifact: &FileArtifact) -> Result<SecurityVerdict, DomainError> {
            Err(DomainError::InspectionError(
                "scanner backend unavailable".to_string(),
            ))
        }
    }

    struct MockQuarantineMover {
        fail_harden: bool,
        fail_move_approved: bool,
        fail_isolate: bool,
        approved_calls: Mutex<Vec<(PathBuf, PathBuf)>>,
        isolated_calls: Mutex<Vec<(PathBuf, PathBuf)>>,
        events: Arc<Mutex<Vec<String>>>,
    }

    impl MockQuarantineMover {
        fn new(events: Arc<Mutex<Vec<String>>>) -> Self {
            Self {
                fail_harden: false,
                fail_move_approved: false,
                fail_isolate: false,
                approved_calls: Mutex::new(Vec::new()),
                isolated_calls: Mutex::new(Vec::new()),
                events,
            }
        }
    }

    #[async_trait]
    impl QuarantineMover for MockQuarantineMover {
        async fn harden_permissions(&self, path: &Path, isolated: bool) -> Result<(), DomainError> {
            self.events
                .lock()
                .expect("events mutex")
                .push(format!("harden:{isolated}:{}", path.display()));
            if self.fail_harden {
                return Err(DomainError::QuarantineError(
                    "chmod failed in mock".to_string(),
                ));
            }
            Ok(())
        }

        async fn move_to_approved(
            &self,
            source: &Path,
            approved_dir: &Path,
        ) -> Result<PathBuf, DomainError> {
            self.events
                .lock()
                .expect("events mutex")
                .push(format!("move_approved:{}", approved_dir.display()));
            if self.fail_move_approved {
                return Err(DomainError::QuarantineError(
                    "move_to_approved failed in mock".to_string(),
                ));
            }
            self.approved_calls
                .lock()
                .expect("approved mutex")
                .push((source.to_path_buf(), approved_dir.to_path_buf()));
            let file_name = source.file_name().expect("file name");
            Ok(approved_dir.join(file_name))
        }

        async fn isolate_rejected(
            &self,
            source: &Path,
            quarantine_dir: &Path,
        ) -> Result<PathBuf, DomainError> {
            self.events
                .lock()
                .expect("events mutex")
                .push(format!("isolate_rejected:{}", quarantine_dir.display()));
            if self.fail_isolate {
                return Err(DomainError::QuarantineError(
                    "isolate_rejected failed in mock".to_string(),
                ));
            }
            self.isolated_calls
                .lock()
                .expect("isolated mutex")
                .push((source.to_path_buf(), quarantine_dir.to_path_buf()));
            let file_name = source.file_name().expect("file name");
            Ok(quarantine_dir.join("isolated").join(file_name))
        }
    }

    struct MockQuarantineRepo {
        saved: Mutex<Vec<InspectionReport>>,
        next_id: i64,
        fail_save: bool,
        events: Arc<Mutex<Vec<String>>>,
    }

    impl MockQuarantineRepo {
        fn new(next_id: i64, events: Arc<Mutex<Vec<String>>>) -> Self {
            Self {
                saved: Mutex::new(Vec::new()),
                next_id,
                fail_save: false,
                events,
            }
        }
    }

    #[async_trait]
    impl QuarantineRepo for MockQuarantineRepo {
        async fn save_report(&self, report: &InspectionReport) -> Result<i64, DomainError> {
            self.events
                .lock()
                .expect("events mutex")
                .push(format!("save_report:{}", report.artifact.sanitized_name));
            if self.fail_save {
                return Err(DomainError::StorageError(
                    "save_report failed in mock".to_string(),
                ));
            }
            self.saved.lock().expect("saved mutex").push(report.clone());
            Ok(self.next_id)
        }

        async fn list_recent_reports(
            &self,
            _limit: u32,
        ) -> Result<Vec<InspectionReport>, DomainError> {
            Ok(self.saved.lock().expect("saved mutex").clone())
        }
    }

    fn test_runtime_config() -> Arc<RwLock<RuntimeConfig>> {
        Arc::new(RwLock::new(RuntimeConfig {
            quarantine_dir: PathBuf::from("/var/sentinel/quarantine"),
            approved_dir: PathBuf::from("/var/sentinel/approved"),
            clamd_socket_path: PathBuf::from("/var/run/clamav/clamd.ctl"),
            suricata_eve_path: PathBuf::from("/var/log/suricata/eve.json"),
            updated_at: Utc::now(),
        }))
    }

    #[test]
    fn sanitize_file_name_validates_safe_names_and_rejects_traversal_vectors() {
        assert_eq!(
            sanitize_file_name(Path::new("/quarantine/Invoice.2026.PDF"))
                .expect("valid path should sanitize"),
            "Invoice.2026.PDF"
        );
        assert_eq!(
            FileArtifact::normalize_extension(Path::new("Invoice.2026.PDF")).as_deref(),
            Some("pdf")
        );
        assert_eq!(
            sanitize_file_name(Path::new("/quarantine/Relatorio Mensal 2026.pdf"))
                .expect("spaces in filename should be allowed"),
            "Relatorio Mensal 2026.pdf"
        );
        assert_eq!(
            sanitize_file_name(Path::new("/quarantine/aula.01.final.pdf"))
                .expect("multiple dots in filename should be allowed"),
            "aula.01.final.pdf"
        );
        assert_eq!(
            FileArtifact::normalize_extension(Path::new("aula.01.final.pdf")).as_deref(),
            Some("pdf")
        );
        assert_eq!(
            sanitize_file_name(Path::new(
                "/quarantine/ação_relatório_último_número_ñ_ç.pdf"
            ))
            .expect("accented Unicode characters should be allowed"),
            "ação_relatório_último_número_ñ_ç.pdf"
        );
        assert_eq!(
            sanitize_file_name(Path::new("/quarantine/Aula 01 - Ação Final.PDF"))
                .expect("spaces plus accented Unicode characters should be allowed"),
            "Aula 01 - Ação Final.PDF"
        );
        assert_eq!(
            FileArtifact::normalize_extension(Path::new("Aula 01 - Ação Final.PDF")).as_deref(),
            Some("pdf")
        );
        assert_eq!(FileArtifact::normalize_extension(Path::new("README")), None);
        assert_eq!(
            FileArtifact::normalize_extension(Path::new("trailing.")),
            None
        );

        let traversal_cases = [
            PathBuf::from(".."),
            PathBuf::from("/quarantine/.."),
            PathBuf::from("/quarantine/../etc/passwd"),
            PathBuf::from("sub/../payload.bin"),
            PathBuf::from("/quarantine/bad\0name.txt"),
            PathBuf::from("\0"),
            PathBuf::from("/quarantine/win\\..\\evil.exe"),
            PathBuf::from("/quarantine/sub\\evil.exe"),
            PathBuf::from("sub\\evil.txt"),
        ];
        for path in traversal_cases {
            let err = sanitize_file_name(&path).expect_err("traversal vector must be rejected");
            assert!(
                matches!(err, DomainError::PathTraversalAttempt(_)),
                "expected PathTraversalAttempt for {}, got {err:?}",
                path.display()
            );
        }

        let invalid_cases = [
            PathBuf::new(),
            PathBuf::from("/"),
            PathBuf::from("."),
            PathBuf::from("./"),
            PathBuf::from("/quarantine/."),
            PathBuf::from("/quarantine/sub/."),
            PathBuf::from("/quarantine/dir/"),
            PathBuf::from("\\"),
            PathBuf::from("/quarantine/trailing\\"),
            PathBuf::from("/quarantine/line\nbreak.txt"),
            PathBuf::from("/quarantine/carriage\rreturn.txt"),
            PathBuf::from("/quarantine/tab\tchar.txt"),
            PathBuf::from("/quarantine/del\x7fchar.txt"),
            PathBuf::from("/quarantine/ansi\x1b[31m.txt"),
        ];
        for path in invalid_cases {
            let err = sanitize_file_name(&path).expect_err("invalid path must be rejected");
            assert!(
                matches!(err, DomainError::InvalidPath(_)),
                "expected InvalidPath for {}, got {err:?}",
                path.display()
            );
        }

        #[cfg(unix)]
        {
            use std::ffi::OsStr;
            use std::os::unix::ffi::OsStrExt;
            let non_utf8 = Path::new(OsStr::from_bytes(b"/quarantine/\xff\xfe.bin"));
            let err = sanitize_file_name(non_utf8).expect_err("non-UTF8 name must be rejected");
            assert!(matches!(err, DomainError::InvalidPath(_)));
        }
    }

    #[tokio::test]
    async fn execute_clean_pipeline_runs_in_order_moves_to_approved_and_persists() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let scanner_called = Arc::new(AtomicBool::new(false));
        let hasher = Arc::new(MockHasher {
            result: Ok(("a".repeat(64), 4_096)),
            events: events.clone(),
        });
        let mime_validator = Arc::new(MockMimeValidator {
            mime: Ok(Some("application/pdf".to_string())),
            events: events.clone(),
        });
        let scanner: Arc<dyn FileScanner> = Arc::new(MockScanner {
            scanner_name: "magic_bytes_inspector",
            verdict: SecurityVerdict::Clean,
            called: scanner_called.clone(),
            events: events.clone(),
        });
        let mover = Arc::new(MockQuarantineMover::new(events.clone()));
        let repo = Arc::new(MockQuarantineRepo::new(42, events.clone()));
        let config = test_runtime_config();

        let use_case = InspectFileUseCase::new(
            hasher,
            mime_validator,
            vec![scanner],
            mover.clone(),
            repo.clone(),
            config,
        );

        let source = PathBuf::from("/var/sentinel/quarantine/Document.PDF");
        let report = use_case
            .execute(&source)
            .await
            .expect("clean inspection should succeed");

        assert!(scanner_called.load(Ordering::SeqCst));
        assert_eq!(report.id, Some(42));
        assert_eq!(report.artifact.sanitized_name, "Document.PDF");
        assert_eq!(report.artifact.extension.as_deref(), Some("pdf"));
        assert_eq!(report.artifact.size_bytes, 4_096);
        assert_eq!(report.artifact.sha256_hash, "a".repeat(64));
        assert_eq!(
            report.artifact.detected_mime.as_deref(),
            Some("application/pdf")
        );
        assert_eq!(report.verdict, SecurityVerdict::Clean);
        assert_eq!(
            report.destination_path,
            Some(PathBuf::from("/var/sentinel/approved/Document.PDF"))
        );

        assert_eq!(mover.approved_calls.lock().expect("lock").len(), 1);
        assert!(mover.isolated_calls.lock().expect("lock").is_empty());
        let saved = repo.saved.lock().expect("lock");
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].id, None);
        assert_eq!(saved[0].verdict, SecurityVerdict::Clean);

        let recorded = events.lock().expect("lock").clone();
        assert_eq!(
            recorded,
            vec![
                "harden:false:/var/sentinel/quarantine/Document.PDF",
                "hash:/var/sentinel/quarantine/Document.PDF",
                "mime:/var/sentinel/quarantine/Document.PDF",
                "scan:magic_bytes_inspector:Document.PDF",
                "move_approved:/var/sentinel/approved",
                "save_report:Document.PDF",
            ]
        );
    }

    #[tokio::test]
    async fn execute_short_circuits_on_first_malicious_verdict_and_isolates() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let first_called = Arc::new(AtomicBool::new(false));
        let second_called = Arc::new(AtomicBool::new(false));

        let expected_verdict = SecurityVerdict::MaliciousSpoofing {
            expected_ext: "jpg".to_string(),
            actual_mime: "application/x-executable".to_string(),
        };

        let scanner1: Arc<dyn FileScanner> = Arc::new(MockScanner {
            scanner_name: "magic_bytes_inspector",
            verdict: expected_verdict.clone(),
            called: first_called.clone(),
            events: events.clone(),
        });
        let scanner2: Arc<dyn FileScanner> = Arc::new(MockScanner {
            scanner_name: "clamav_scanner",
            verdict: SecurityVerdict::Clean,
            called: second_called.clone(),
            events: events.clone(),
        });

        let mover = Arc::new(MockQuarantineMover::new(events.clone()));
        let repo = Arc::new(MockQuarantineRepo::new(99, events.clone()));
        let config = test_runtime_config();

        // Mutate runtime config dynamically to verify snapshot usage.
        {
            let mut guard = config.write().await;
            guard.quarantine_dir = PathBuf::from("/mnt/dynamic_quarantine");
            guard.approved_dir = PathBuf::from("/mnt/dynamic_approved");
        }

        let use_case = InspectFileUseCase::new(
            Arc::new(MockHasher {
                result: Ok(("b".repeat(64), 128)),
                events: events.clone(),
            }),
            Arc::new(MockMimeValidator {
                mime: Ok(Some("application/x-executable".to_string())),
                events: events.clone(),
            }),
            vec![scanner1, scanner2],
            mover.clone(),
            repo.clone(),
            config,
        );

        let source = PathBuf::from("/mnt/dynamic_quarantine/vacation.jpg");
        let report = use_case
            .execute(&source)
            .await
            .expect("spoofed file should produce isolated report");

        assert!(first_called.load(Ordering::SeqCst));
        assert!(
            !second_called.load(Ordering::SeqCst),
            "second scanner must not execute after first non-clean verdict"
        );
        assert_eq!(report.id, Some(99));
        assert_eq!(report.verdict, expected_verdict);
        assert_eq!(
            report.destination_path,
            Some(PathBuf::from(
                "/mnt/dynamic_quarantine/isolated/vacation.jpg"
            ))
        );
        assert!(mover.approved_calls.lock().expect("lock").is_empty());
        assert_eq!(mover.isolated_calls.lock().expect("lock").len(), 1);
        let saved = repo.saved.lock().expect("lock");
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].verdict, expected_verdict);

        let recorded = events.lock().expect("lock").clone();
        assert_eq!(
            recorded,
            vec![
                "harden:false:/mnt/dynamic_quarantine/vacation.jpg",
                "hash:/mnt/dynamic_quarantine/vacation.jpg",
                "mime:/mnt/dynamic_quarantine/vacation.jpg",
                "scan:magic_bytes_inspector:vacation.jpg",
                "isolate_rejected:/mnt/dynamic_quarantine",
                "save_report:vacation.jpg",
            ]
        );
    }

    #[tokio::test]
    async fn execute_ocp_multiple_scanners_isolates_when_second_scanner_flags_signature() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let first_called = Arc::new(AtomicBool::new(false));
        let second_called = Arc::new(AtomicBool::new(false));
        let third_called = Arc::new(AtomicBool::new(false));

        let signature_verdict = SecurityVerdict::MaliciousSignature {
            threat_name: "Win.Test.EICAR_HDB-1".to_string(),
        };

        let scanner1: Arc<dyn FileScanner> = Arc::new(MockScanner {
            scanner_name: "magic_bytes_inspector",
            verdict: SecurityVerdict::Clean,
            called: first_called.clone(),
            events: events.clone(),
        });
        let scanner2: Arc<dyn FileScanner> = Arc::new(MockScanner {
            scanner_name: "clamav_scanner",
            verdict: signature_verdict.clone(),
            called: second_called.clone(),
            events: events.clone(),
        });
        let scanner3: Arc<dyn FileScanner> = Arc::new(MockScanner {
            scanner_name: "suricata_correlator",
            verdict: SecurityVerdict::Clean,
            called: third_called.clone(),
            events: events.clone(),
        });

        let mover = Arc::new(MockQuarantineMover::new(events.clone()));
        let repo = Arc::new(MockQuarantineRepo::new(105, events.clone()));

        let use_case = InspectFileUseCase::new(
            Arc::new(MockHasher {
                result: Ok(("d".repeat(64), 2_048)),
                events: events.clone(),
            }),
            Arc::new(MockMimeValidator {
                mime: Ok(Some("application/pdf".to_string())),
                events: events.clone(),
            }),
            vec![scanner1, scanner2, scanner3],
            mover.clone(),
            repo.clone(),
            test_runtime_config(),
        );

        let source = PathBuf::from("/var/sentinel/quarantine/aula.01.final.pdf");
        let report = use_case
            .execute(&source)
            .await
            .expect("malicious signature should isolate artifact and persist report");

        assert!(first_called.load(Ordering::SeqCst));
        assert!(second_called.load(Ordering::SeqCst));
        assert!(
            !third_called.load(Ordering::SeqCst),
            "third scanner must not execute after second scanner reports MaliciousSignature"
        );
        assert_eq!(report.id, Some(105));
        assert_eq!(report.artifact.sanitized_name, "aula.01.final.pdf");
        assert_eq!(report.artifact.extension.as_deref(), Some("pdf"));
        assert_eq!(report.verdict, signature_verdict);
        assert_eq!(
            report.destination_path,
            Some(PathBuf::from(
                "/var/sentinel/quarantine/isolated/aula.01.final.pdf"
            ))
        );
        assert!(mover.approved_calls.lock().expect("lock").is_empty());
        assert_eq!(mover.isolated_calls.lock().expect("lock").len(), 1);
        let saved = repo.saved.lock().expect("lock");
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].verdict, signature_verdict);

        let recorded = events.lock().expect("lock").clone();
        assert_eq!(
            recorded,
            vec![
                "harden:false:/var/sentinel/quarantine/aula.01.final.pdf",
                "hash:/var/sentinel/quarantine/aula.01.final.pdf",
                "mime:/var/sentinel/quarantine/aula.01.final.pdf",
                "scan:magic_bytes_inspector:aula.01.final.pdf",
                "scan:clamav_scanner:aula.01.final.pdf",
                "isolate_rejected:/var/sentinel/quarantine",
                "save_report:aula.01.final.pdf",
            ]
        );
    }

    #[tokio::test]
    async fn execute_runs_all_clean_scanners_in_order_before_approving() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let first_called = Arc::new(AtomicBool::new(false));
        let second_called = Arc::new(AtomicBool::new(false));

        let scanner1: Arc<dyn FileScanner> = Arc::new(MockScanner {
            scanner_name: "magic_bytes_inspector",
            verdict: SecurityVerdict::Clean,
            called: first_called.clone(),
            events: events.clone(),
        });
        let scanner2: Arc<dyn FileScanner> = Arc::new(MockScanner {
            scanner_name: "clamav_scanner",
            verdict: SecurityVerdict::Clean,
            called: second_called.clone(),
            events: events.clone(),
        });

        let mover = Arc::new(MockQuarantineMover::new(events.clone()));
        let repo = Arc::new(MockQuarantineRepo::new(7, events.clone()));

        let use_case = InspectFileUseCase::new(
            Arc::new(MockHasher {
                result: Ok(("e".repeat(64), 512)),
                events: events.clone(),
            }),
            Arc::new(MockMimeValidator {
                mime: Ok(None),
                events: events.clone(),
            }),
            vec![scanner1, scanner2],
            mover.clone(),
            repo.clone(),
            test_runtime_config(),
        );

        let source = PathBuf::from("/var/sentinel/quarantine/Relatório Final 2026.txt");
        let report = use_case
            .execute(&source)
            .await
            .expect("all-clean multi-scanner run should approve file");

        assert!(first_called.load(Ordering::SeqCst));
        assert!(second_called.load(Ordering::SeqCst));
        assert_eq!(report.id, Some(7));
        assert_eq!(report.verdict, SecurityVerdict::Clean);
        assert_eq!(
            report.destination_path,
            Some(PathBuf::from(
                "/var/sentinel/approved/Relatório Final 2026.txt"
            ))
        );
        assert_eq!(mover.approved_calls.lock().expect("lock").len(), 1);
        assert!(mover.isolated_calls.lock().expect("lock").is_empty());

        let recorded = events.lock().expect("lock").clone();
        assert_eq!(
            recorded,
            vec![
                "harden:false:/var/sentinel/quarantine/Relatório Final 2026.txt",
                "hash:/var/sentinel/quarantine/Relatório Final 2026.txt",
                "mime:/var/sentinel/quarantine/Relatório Final 2026.txt",
                "scan:magic_bytes_inspector:Relatório Final 2026.txt",
                "scan:clamav_scanner:Relatório Final 2026.txt",
                "move_approved:/var/sentinel/approved",
                "save_report:Relatório Final 2026.txt",
            ]
        );
    }

    #[tokio::test]
    async fn execute_rejects_unsafe_paths_before_invoking_any_port() {
        for unsafe_path in [
            Path::new("/var/sentinel/quarantine/../etc/passwd"),
            Path::new("/var/sentinel/quarantine/."),
            Path::new(""),
            Path::new("/var/sentinel/quarantine/bad\rname.pdf"),
            Path::new("/var/sentinel/quarantine/sub\\evil.pdf"),
            Path::new("/var/sentinel/quarantine/null\0byte.pdf"),
        ] {
            let events = Arc::new(Mutex::new(Vec::new()));
            let mover = Arc::new(MockQuarantineMover::new(events.clone()));
            let repo = Arc::new(MockQuarantineRepo::new(1, events.clone()));
            let use_case = InspectFileUseCase::new(
                Arc::new(MockHasher {
                    result: Ok(("f".repeat(64), 64)),
                    events: events.clone(),
                }),
                Arc::new(MockMimeValidator {
                    mime: Ok(None),
                    events: events.clone(),
                }),
                vec![],
                mover.clone(),
                repo.clone(),
                test_runtime_config(),
            );

            let err = use_case
                .execute(unsafe_path)
                .await
                .expect_err("unsafe path must be rejected before pipeline starts");
            assert!(
                matches!(
                    err,
                    DomainError::PathTraversalAttempt(_) | DomainError::InvalidPath(_)
                ),
                "unexpected error for {}: {err:?}",
                unsafe_path.display()
            );
            assert!(
                events.lock().expect("lock").is_empty(),
                "no port should run for unsafe path {}",
                unsafe_path.display()
            );
            assert!(mover.approved_calls.lock().expect("lock").is_empty());
            assert!(mover.isolated_calls.lock().expect("lock").is_empty());
            assert!(repo.saved.lock().expect("lock").is_empty());
        }
    }

    #[tokio::test]
    async fn execute_rejects_forbidden_system_dirs_and_outside_quarantine_paths_before_ports() {
        for forbidden_path in [
            Path::new("/etc/passwd"),
            Path::new("/usr/bin/env"),
            Path::new("/bin/sh"),
            Path::new("/root/.ssh/id_rsa"),
        ] {
            let events = Arc::new(Mutex::new(Vec::new()));
            let mover = Arc::new(MockQuarantineMover::new(events.clone()));
            let repo = Arc::new(MockQuarantineRepo::new(1, events.clone()));
            let use_case = InspectFileUseCase::new(
                Arc::new(MockHasher {
                    result: Ok(("f".repeat(64), 64)),
                    events: events.clone(),
                }),
                Arc::new(MockMimeValidator {
                    mime: Ok(None),
                    events: events.clone(),
                }),
                vec![],
                mover.clone(),
                repo.clone(),
                test_runtime_config(),
            );

            let err = use_case
                .execute(forbidden_path)
                .await
                .expect_err("forbidden system path must be rejected");
            assert!(
                matches!(err, DomainError::ForbiddenSystemDirectory(_)),
                "expected ForbiddenSystemDirectory for {}, got {err:?}",
                forbidden_path.display()
            );
            assert!(events.lock().expect("lock").is_empty());
            assert!(mover.approved_calls.lock().expect("lock").is_empty());
            assert!(mover.isolated_calls.lock().expect("lock").is_empty());
            assert!(repo.saved.lock().expect("lock").is_empty());
        }

        for outside_path in [
            Path::new("/tmp/outside/doc.pdf"),
            Path::new("/tmp/outside/report.pdf"),
            Path::new("/var/sentinel/quarantine_other/report.pdf"),
            Path::new("/var/sentinel/approved/report.pdf"),
            Path::new("/var/sentinel/quarantine"),
            Path::new("relative_only.pdf"),
        ] {
            let events = Arc::new(Mutex::new(Vec::new()));
            let mover = Arc::new(MockQuarantineMover::new(events.clone()));
            let repo = Arc::new(MockQuarantineRepo::new(1, events.clone()));
            let use_case = InspectFileUseCase::new(
                Arc::new(MockHasher {
                    result: Ok(("f".repeat(64), 64)),
                    events: events.clone(),
                }),
                Arc::new(MockMimeValidator {
                    mime: Ok(None),
                    events: events.clone(),
                }),
                vec![],
                mover.clone(),
                repo.clone(),
                test_runtime_config(),
            );

            let err = use_case
                .execute(outside_path)
                .await
                .expect_err("outside quarantine path must be rejected");
            assert!(
                matches!(err, DomainError::PathTraversalAttempt(_)),
                "expected PathTraversalAttempt for {}, got {err:?}",
                outside_path.display()
            );
            assert!(events.lock().expect("lock").is_empty());
            assert!(mover.approved_calls.lock().expect("lock").is_empty());
            assert!(mover.isolated_calls.lock().expect("lock").is_empty());
            assert!(repo.saved.lock().expect("lock").is_empty());
        }
    }

    #[tokio::test]
    async fn execute_propagates_errors_without_moving_or_saving() {
        let source = Path::new("/var/sentinel/quarantine/notes.txt");

        // 1. harden_permissions failure halts before hashing
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut failing_mover = MockQuarantineMover::new(events.clone());
        failing_mover.fail_harden = true;
        let mover = Arc::new(failing_mover);
        let repo = Arc::new(MockQuarantineRepo::new(1, events.clone()));
        let harden_uc = InspectFileUseCase::new(
            Arc::new(MockHasher {
                result: Ok(("c".repeat(64), 10)),
                events: events.clone(),
            }),
            Arc::new(MockMimeValidator {
                mime: Ok(None),
                events: events.clone(),
            }),
            vec![],
            mover.clone(),
            repo.clone(),
            test_runtime_config(),
        );
        let err = harden_uc
            .execute(source)
            .await
            .expect_err("harden failure must propagate");
        assert!(matches!(err, DomainError::QuarantineError(_)));
        assert_eq!(
            *events.lock().expect("lock"),
            vec!["harden:false:/var/sentinel/quarantine/notes.txt"]
        );
        assert!(repo.saved.lock().expect("lock").is_empty());

        // 2. hash_calculator failure halts before mime detection
        let events = Arc::new(Mutex::new(Vec::new()));
        let mover = Arc::new(MockQuarantineMover::new(events.clone()));
        let repo = Arc::new(MockQuarantineRepo::new(1, events.clone()));
        let hash_uc = InspectFileUseCase::new(
            Arc::new(MockHasher {
                result: Err("hash read error".to_string()),
                events: events.clone(),
            }),
            Arc::new(MockMimeValidator {
                mime: Ok(None),
                events: events.clone(),
            }),
            vec![],
            mover.clone(),
            repo.clone(),
            test_runtime_config(),
        );
        let err = hash_uc
            .execute(source)
            .await
            .expect_err("hash failure must propagate");
        assert!(matches!(err, DomainError::InspectionError(_)));
        assert_eq!(
            *events.lock().expect("lock"),
            vec![
                "harden:false:/var/sentinel/quarantine/notes.txt",
                "hash:/var/sentinel/quarantine/notes.txt",
            ]
        );
        assert!(repo.saved.lock().expect("lock").is_empty());

        // 3. mime_validator failure halts before scanning
        let events = Arc::new(Mutex::new(Vec::new()));
        let mover = Arc::new(MockQuarantineMover::new(events.clone()));
        let repo = Arc::new(MockQuarantineRepo::new(1, events.clone()));
        let mime_uc = InspectFileUseCase::new(
            Arc::new(MockHasher {
                result: Ok(("c".repeat(64), 10)),
                events: events.clone(),
            }),
            Arc::new(MockMimeValidator {
                mime: Err("mime read error".to_string()),
                events: events.clone(),
            }),
            vec![Arc::new(FailingScanner)],
            mover.clone(),
            repo.clone(),
            test_runtime_config(),
        );
        let err = mime_uc
            .execute(source)
            .await
            .expect_err("mime failure must propagate");
        assert!(matches!(err, DomainError::InspectionError(_)));
        assert_eq!(
            *events.lock().expect("lock"),
            vec![
                "harden:false:/var/sentinel/quarantine/notes.txt",
                "hash:/var/sentinel/quarantine/notes.txt",
                "mime:/var/sentinel/quarantine/notes.txt",
            ]
        );
        assert!(repo.saved.lock().expect("lock").is_empty());

        // 4. scanner failure halts before moving and persisting
        let events = Arc::new(Mutex::new(Vec::new()));
        let mover = Arc::new(MockQuarantineMover::new(events.clone()));
        let repo = Arc::new(MockQuarantineRepo::new(1, events.clone()));
        let use_case = InspectFileUseCase::new(
            Arc::new(MockHasher {
                result: Ok(("c".repeat(64), 10)),
                events: events.clone(),
            }),
            Arc::new(MockMimeValidator {
                mime: Ok(None),
                events: events.clone(),
            }),
            vec![Arc::new(FailingScanner)],
            mover.clone(),
            repo.clone(),
            test_runtime_config(),
        );

        let err = use_case
            .execute(source)
            .await
            .expect_err("scanner error must propagate");
        assert!(matches!(err, DomainError::InspectionError(_)));
        assert!(mover.approved_calls.lock().expect("lock").is_empty());
        assert!(mover.isolated_calls.lock().expect("lock").is_empty());
        assert!(repo.saved.lock().expect("lock").is_empty());

        // 5. move_to_approved failure halts before persisting
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut fail_approve_mover = MockQuarantineMover::new(events.clone());
        fail_approve_mover.fail_move_approved = true;
        let mover = Arc::new(fail_approve_mover);
        let repo = Arc::new(MockQuarantineRepo::new(1, events.clone()));
        let approve_err_uc = InspectFileUseCase::new(
            Arc::new(MockHasher {
                result: Ok(("c".repeat(64), 10)),
                events: events.clone(),
            }),
            Arc::new(MockMimeValidator {
                mime: Ok(None),
                events: events.clone(),
            }),
            vec![],
            mover.clone(),
            repo.clone(),
            test_runtime_config(),
        );
        let err = approve_err_uc
            .execute(source)
            .await
            .expect_err("move_to_approved failure must propagate");
        assert!(matches!(err, DomainError::QuarantineError(_)));
        assert!(repo.saved.lock().expect("lock").is_empty());

        // 6. isolate_rejected failure halts before persisting
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut fail_isolate_mover = MockQuarantineMover::new(events.clone());
        fail_isolate_mover.fail_isolate = true;
        let mover = Arc::new(fail_isolate_mover);
        let repo = Arc::new(MockQuarantineRepo::new(1, events.clone()));
        let isolate_err_uc = InspectFileUseCase::new(
            Arc::new(MockHasher {
                result: Ok(("c".repeat(64), 10)),
                events: events.clone(),
            }),
            Arc::new(MockMimeValidator {
                mime: Ok(None),
                events: events.clone(),
            }),
            vec![Arc::new(MockScanner {
                scanner_name: "spoof",
                verdict: SecurityVerdict::CorruptedOrUnreadable {
                    reason: "corrupted".to_string(),
                },
                called: Arc::new(AtomicBool::new(false)),
                events: events.clone(),
            })],
            mover.clone(),
            repo.clone(),
            test_runtime_config(),
        );
        let err = isolate_err_uc
            .execute(source)
            .await
            .expect_err("isolate_rejected failure must propagate");
        assert!(matches!(err, DomainError::QuarantineError(_)));
        assert!(repo.saved.lock().expect("lock").is_empty());

        // 7. save_report failure propagates cleanly
        let events = Arc::new(Mutex::new(Vec::new()));
        let mover = Arc::new(MockQuarantineMover::new(events.clone()));
        let mut failing_repo = MockQuarantineRepo::new(1, events.clone());
        failing_repo.fail_save = true;
        let repo = Arc::new(failing_repo);
        let save_err_uc = InspectFileUseCase::new(
            Arc::new(MockHasher {
                result: Ok(("c".repeat(64), 10)),
                events: events.clone(),
            }),
            Arc::new(MockMimeValidator {
                mime: Ok(None),
                events: events.clone(),
            }),
            vec![],
            mover,
            repo,
            test_runtime_config(),
        );
        let err = save_err_uc
            .execute(source)
            .await
            .expect_err("save_report failure must propagate");
        assert!(matches!(err, DomainError::StorageError(_)));
    }
}
