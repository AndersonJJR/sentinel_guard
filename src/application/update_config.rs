//! Use case for validating, persisting, and hot-reloading runtime directory configuration.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock, watch};

use crate::domain::entities::RuntimeConfig;
use crate::domain::errors::DomainError;
use crate::domain::path_policy::{ensure_distinct_non_nested_dirs, reject_forbidden_system_dir};
use crate::domain::ports::ConfigStore;

const MAX_SYMLINK_HOPS: usize = 40;

static PROBE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Input payload for updating monitored and output directories at runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateConfigRequest {
    /// New quarantine directory to watch for incoming files.
    pub quarantine_dir: PathBuf,
    /// New destination directory for verified clean files.
    pub approved_dir: PathBuf,
    /// Optional override for ClamAV daemon Unix socket path.
    pub clamd_socket_path: Option<PathBuf>,
    /// Optional override for Suricata `eve.json` telemetry path.
    pub suricata_eve_path: Option<PathBuf>,
}

/// Validates directory permissions and safety, persists new config, and notifies the watcher.
pub struct UpdateConfigUseCase {
    config_store: Arc<dyn ConfigStore>,
    runtime_config: Arc<RwLock<RuntimeConfig>>,
    watcher_tx: watch::Sender<PathBuf>,
    update_lock: Mutex<()>,
}

struct ValidatedPaths {
    quarantine_dir: PathBuf,
    approved_dir: PathBuf,
    clamd_socket_path: Option<PathBuf>,
    suricata_eve_path: Option<PathBuf>,
}

enum LexicalComponent {
    ParentDir,
    Normal(OsString),
}

impl UpdateConfigUseCase {
    /// Creates a new [`UpdateConfigUseCase`] instance with injected ports and shared state.
    pub fn new(
        config_store: Arc<dyn ConfigStore>,
        runtime_config: Arc<RwLock<RuntimeConfig>>,
        watcher_tx: watch::Sender<PathBuf>,
    ) -> Self {
        Self {
            config_store,
            runtime_config,
            watcher_tx,
            update_lock: Mutex::new(()),
        }
    }

    /// Validates paths, persists updated configuration, refreshes memory state, and notifies watchers.
    pub async fn execute(&self, req: UpdateConfigRequest) -> Result<RuntimeConfig, DomainError> {
        let _update_guard = self.update_lock.lock().await;

        let validated =
            tokio::task::spawn_blocking(move || -> Result<ValidatedPaths, DomainError> {
                let quarantine_dir =
                    validate_operational_dir(&req.quarantine_dir, "quarantine_dir")?;
                let approved_dir = validate_operational_dir(&req.approved_dir, "approved_dir")?;

                ensure_distinct_non_nested_dirs(&quarantine_dir, &approved_dir)?;

                let clamd_socket_path = req
                    .clamd_socket_path
                    .as_deref()
                    .map(|path| validate_auxiliary_path(path, "clamd_socket_path"))
                    .transpose()?;

                let suricata_eve_path = req
                    .suricata_eve_path
                    .as_deref()
                    .map(|path| validate_auxiliary_path(path, "suricata_eve_path"))
                    .transpose()?;

                Ok(ValidatedPaths {
                    quarantine_dir,
                    approved_dir,
                    clamd_socket_path,
                    suricata_eve_path,
                })
            })
            .await
            .map_err(|err| {
                DomainError::ConfigError(format!("Path validation task failed: {err}"))
            })??;

        let (current_clamd, current_suricata) = {
            let guard = self.runtime_config.read().await;
            (
                guard.clamd_socket_path.clone(),
                guard.suricata_eve_path.clone(),
            )
        };

        let new_config = RuntimeConfig {
            quarantine_dir: validated.quarantine_dir.clone(),
            approved_dir: validated.approved_dir,
            clamd_socket_path: validated.clamd_socket_path.unwrap_or(current_clamd),
            suricata_eve_path: validated.suricata_eve_path.unwrap_or(current_suricata),
            updated_at: Utc::now(),
        };

        self.config_store.save_config(&new_config).await?;

        {
            let mut guard = self.runtime_config.write().await;
            *guard = new_config.clone();
        }

        // Ignore SendError when no watcher receiver is currently subscribed.
        let _ = self.watcher_tx.send(validated.quarantine_dir);

        Ok(new_config)
    }
}

fn validate_operational_dir(raw_path: &Path, label: &str) -> Result<PathBuf, DomainError> {
    let resolved = validate_and_resolve_path(raw_path, label)?;

    let canonical =
        std::fs::canonicalize(&resolved).map_err(|err| map_path_io_error(raw_path, label, err))?;

    reject_forbidden_system_dir(&canonical)?;

    let metadata = std::fs::metadata(&canonical)?;
    if !metadata.is_dir() {
        return Err(DomainError::InvalidPath(format!(
            "{label} path is not a directory: {}",
            canonical.display()
        )));
    }

    if metadata.permissions().readonly() {
        return Err(DomainError::InvalidPath(format!(
            "{label} directory is read-only: {}",
            canonical.display()
        )));
    }

    // Confirm read/traverse access and effective write capability without leaving probe artifacts.
    let _ = std::fs::read_dir(&canonical)?;
    verify_directory_writable(&canonical)?;

    Ok(canonical)
}

fn validate_auxiliary_path(raw_path: &Path, label: &str) -> Result<PathBuf, DomainError> {
    validate_and_resolve_path(raw_path, label)
}

fn validate_and_resolve_path(raw_path: &Path, label: &str) -> Result<PathBuf, DomainError> {
    reject_empty_and_null_bytes(raw_path, label)?;
    reject_parent_traversal(raw_path)?;
    require_absolute_path(raw_path, label)?;
    reject_forbidden_system_dir(raw_path)?;

    let resolved = resolve_symlinks_and_normalize(raw_path, label)?;
    reject_forbidden_system_dir(&resolved)?;

    let canonicalized = canonicalize_deepest_existing_ancestor(&resolved)?;
    reject_forbidden_system_dir(&canonicalized)?;

    Ok(canonicalized)
}

fn reject_empty_and_null_bytes(path: &Path, label: &str) -> Result<(), DomainError> {
    if path.as_os_str().is_empty() {
        return Err(DomainError::InvalidPath(format!(
            "{label} path must not be empty"
        )));
    }

    if path.as_os_str().as_encoded_bytes().contains(&0) {
        return Err(DomainError::PathTraversalAttempt(format!(
            "{label} path contains null byte"
        )));
    }

    Ok(())
}

fn reject_parent_traversal(path: &Path) -> Result<(), DomainError> {
    for component in path.components() {
        if matches!(component, Component::ParentDir) {
            return Err(DomainError::PathTraversalAttempt(format!(
                "Parent directory traversal ('..') is not allowed: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn require_absolute_path(path: &Path, label: &str) -> Result<(), DomainError> {
    if !path.is_absolute() {
        return Err(DomainError::InvalidPath(format!(
            "{label} path must be absolute: {}",
            path.display()
        )));
    }
    Ok(())
}

fn normalize_lexical(path: &Path) -> PathBuf {
    let mut stack: Vec<OsString> = Vec::new();
    let mut has_root = false;

    for component in path.components() {
        match component {
            Component::Prefix(prefix) => stack.push(prefix.as_os_str().to_os_string()),
            Component::RootDir => has_root = true,
            Component::CurDir => {}
            Component::ParentDir => {
                stack.pop();
            }
            Component::Normal(part) => stack.push(part.to_os_string()),
        }
    }

    let mut normalized = PathBuf::new();
    if has_root {
        normalized.push("/");
    }
    for part in stack {
        normalized.push(part);
    }
    normalized
}

fn push_components_front(queue: &mut VecDeque<LexicalComponent>, path: &Path) {
    let mut collected = Vec::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::CurDir => {}
            Component::ParentDir => collected.push(LexicalComponent::ParentDir),
            Component::Normal(part) => {
                collected.push(LexicalComponent::Normal(part.to_os_string()))
            }
        }
    }
    for item in collected.into_iter().rev() {
        queue.push_front(item);
    }
}

fn resolve_symlinks_and_normalize(raw_path: &Path, label: &str) -> Result<PathBuf, DomainError> {
    let mut pending = VecDeque::new();
    push_components_front(&mut pending, raw_path);

    let mut current = PathBuf::from("/");
    let mut hops: usize = 0;

    while let Some(component) = pending.pop_front() {
        match component {
            LexicalComponent::ParentDir => {
                current.pop();
            }
            LexicalComponent::Normal(part) => {
                current.push(&part);
                reject_forbidden_system_dir(&current)?;

                match std::fs::symlink_metadata(&current) {
                    Ok(meta) if meta.file_type().is_symlink() => {
                        hops += 1;
                        if hops > MAX_SYMLINK_HOPS {
                            return Err(DomainError::InvalidPath(format!(
                                "{label} exceeded maximum symlink depth ({MAX_SYMLINK_HOPS}): {}",
                                raw_path.display()
                            )));
                        }

                        let target = std::fs::read_link(&current)?;
                        reject_empty_and_null_bytes(&target, label)?;

                        if target.is_absolute() {
                            current = PathBuf::from("/");
                        } else {
                            current.pop();
                        }

                        let lexical_target = if target.is_absolute() {
                            normalize_lexical(&target)
                        } else {
                            normalize_lexical(&current.join(&target))
                        };
                        reject_forbidden_system_dir(&lexical_target)?;

                        push_components_front(&mut pending, &target);
                    }
                    Ok(_) => {}
                    Err(err) if err.kind() == ErrorKind::NotFound => {}
                    Err(err) if err.kind() == ErrorKind::NotADirectory => {
                        return Err(DomainError::InvalidPath(format!(
                            "{label} path traverses through a non-directory component: {}",
                            current.display()
                        )));
                    }
                    Err(err) => return Err(DomainError::IoError(err)),
                }
            }
        }
    }

    reject_forbidden_system_dir(&current)?;
    Ok(current)
}

fn canonicalize_deepest_existing_ancestor(resolved: &Path) -> Result<PathBuf, DomainError> {
    let mut existing = resolved.to_path_buf();
    let mut suffix_parts: Vec<OsString> = Vec::new();

    loop {
        match std::fs::canonicalize(&existing) {
            Ok(canonical) => {
                reject_forbidden_system_dir(&canonical)?;
                let mut result = canonical;
                for part in suffix_parts.into_iter().rev() {
                    result.push(part);
                }
                return Ok(result);
            }
            Err(err) if err.kind() == ErrorKind::NotFound => match existing.file_name() {
                Some(name) => {
                    suffix_parts.push(name.to_os_string());
                    if !existing.pop() {
                        return Err(DomainError::InvalidPath(format!(
                            "No existing ancestor found for path: {}",
                            resolved.display()
                        )));
                    }
                }
                None => {
                    return Err(DomainError::InvalidPath(format!(
                        "No existing ancestor found for path: {}",
                        resolved.display()
                    )));
                }
            },
            Err(err) if err.kind() == ErrorKind::NotADirectory => {
                return Err(DomainError::InvalidPath(format!(
                    "Path traverses through a non-directory component: {}",
                    existing.display()
                )));
            }
            Err(err) => return Err(DomainError::IoError(err)),
        }
    }
}

fn map_path_io_error(path: &Path, label: &str, err: std::io::Error) -> DomainError {
    match err.kind() {
        ErrorKind::NotFound => DomainError::InvalidPath(format!(
            "{label} directory does not exist: {}",
            path.display()
        )),
        ErrorKind::NotADirectory => DomainError::InvalidPath(format!(
            "{label} path is not a directory: {}",
            path.display()
        )),
        _ => DomainError::IoError(err),
    }
}

struct ProbeCleanupGuard {
    path: Option<PathBuf>,
}

impl Drop for ProbeCleanupGuard {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn verify_directory_writable(dir: &Path) -> Result<(), DomainError> {
    let seq = PROBE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let probe_path = dir.join(format!(
        ".sentinel_guard_write_probe_{}_{}",
        std::process::id(),
        seq
    ));

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let file = options.open(&probe_path)?;

    let mut guard = ProbeCleanupGuard {
        path: Some(probe_path.clone()),
    };
    drop(file);
    std::fs::remove_file(&probe_path)?;
    guard.path = None;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use tempfile::tempdir;

    use crate::domain::path_policy::FORBIDDEN_SYSTEM_DIRS;

    use super::*;

    struct InMemoryConfigStore {
        saved: Mutex<Option<RuntimeConfig>>,
        fail_on_save: bool,
    }

    impl InMemoryConfigStore {
        fn new() -> Self {
            Self {
                saved: Mutex::new(None),
                fail_on_save: false,
            }
        }

        fn failing() -> Self {
            Self {
                saved: Mutex::new(None),
                fail_on_save: true,
            }
        }
    }

    #[async_trait]
    impl ConfigStore for InMemoryConfigStore {
        async fn load_or_seed(
            &self,
            defaults: &RuntimeConfig,
        ) -> Result<RuntimeConfig, DomainError> {
            let guard = self.saved.lock().expect("test mutex poisoned");
            Ok(guard.clone().unwrap_or_else(|| defaults.clone()))
        }

        async fn save_config(&self, config: &RuntimeConfig) -> Result<(), DomainError> {
            if self.fail_on_save {
                return Err(DomainError::StorageError(
                    "Simulated database write failure".to_string(),
                ));
            }
            let mut guard = self.saved.lock().expect("test mutex poisoned");
            *guard = Some(config.clone());
            Ok(())
        }
    }

    fn setup_use_case_with_store(
        store: Arc<InMemoryConfigStore>,
        initial_q: PathBuf,
        initial_a: PathBuf,
    ) -> (
        UpdateConfigUseCase,
        Arc<RwLock<RuntimeConfig>>,
        watch::Receiver<PathBuf>,
    ) {
        let initial = RuntimeConfig {
            quarantine_dir: initial_q.clone(),
            approved_dir: initial_a,
            clamd_socket_path: PathBuf::from("/var/run/clamav/clamd.ctl"),
            suricata_eve_path: PathBuf::from("/var/log/suricata/eve.json"),
            updated_at: Utc::now(),
        };
        let state = Arc::new(RwLock::new(initial));
        let (tx, rx) = watch::channel(initial_q);
        let use_case = UpdateConfigUseCase::new(store, state.clone(), tx);
        (use_case, state, rx)
    }

    fn setup_use_case(
        initial_q: PathBuf,
        initial_a: PathBuf,
    ) -> (
        UpdateConfigUseCase,
        Arc<InMemoryConfigStore>,
        Arc<RwLock<RuntimeConfig>>,
        watch::Receiver<PathBuf>,
    ) {
        let store = Arc::new(InMemoryConfigStore::new());
        let (use_case, state, rx) = setup_use_case_with_store(store.clone(), initial_q, initial_a);
        (use_case, store, state, rx)
    }

    fn basic_req(quarantine_dir: PathBuf, approved_dir: PathBuf) -> UpdateConfigRequest {
        UpdateConfigRequest {
            quarantine_dir,
            approved_dir,
            clamd_socket_path: None,
            suricata_eve_path: None,
        }
    }

    #[tokio::test]
    async fn execute_updates_valid_directories_persists_and_notifies_watcher() {
        let root = tempdir().expect("tempdir");
        let old_q = root.path().join("old_q");
        let old_a = root.path().join("old_a");
        let new_q = root.path().join("new_q");
        let new_a = root.path().join("new_a");
        std::fs::create_dir_all(&old_q).expect("create old_q");
        std::fs::create_dir_all(&old_a).expect("create old_a");
        std::fs::create_dir_all(&new_q).expect("create new_q");
        std::fs::create_dir_all(&new_a).expect("create new_a");

        let (use_case, store, state, mut rx) = setup_use_case(old_q, old_a);

        let updated = use_case
            .execute(basic_req(new_q.clone(), new_a.clone()))
            .await
            .expect("valid directory update should succeed");

        let expected_q = std::fs::canonicalize(&new_q).expect("canonical new_q");
        let expected_a = std::fs::canonicalize(&new_a).expect("canonical new_a");

        assert_eq!(updated.quarantine_dir, expected_q);
        assert_eq!(updated.approved_dir, expected_a);
        assert_eq!(state.read().await.quarantine_dir, expected_q);
        assert_eq!(state.read().await.approved_dir, expected_a);
        assert_eq!(
            store
                .saved
                .lock()
                .expect("lock")
                .as_ref()
                .map(|c| (&c.quarantine_dir, &c.approved_dir)),
            Some((&expected_q, &expected_a))
        );
        assert!(rx.has_changed().expect("watch channel open"));
        assert_eq!(*rx.borrow_and_update(), expected_q);

        // Probe files must be cleaned up.
        assert_eq!(std::fs::read_dir(&expected_q).expect("read_dir").count(), 0);
        assert_eq!(std::fs::read_dir(&expected_a).expect("read_dir").count(), 0);
    }

    #[tokio::test]
    async fn execute_canonicalizes_dot_segments_and_safe_symlinks_and_allows_non_system_etc_name() {
        let root = tempdir().expect("tempdir");
        let real_q = root.path().join("etc");
        let real_a = root.path().join("approved_target");
        std::fs::create_dir_all(&real_q).expect("create safe dir named etc");
        std::fs::create_dir_all(&real_a).expect("create approved_target");

        let q_link = root.path().join("q_link");
        std::os::unix::fs::symlink(&real_q, &q_link).expect("create safe symlink");

        let (use_case, _, state, mut rx) =
            setup_use_case(root.path().to_path_buf(), root.path().to_path_buf());

        let updated = use_case
            .execute(basic_req(q_link, real_a.join(".")))
            .await
            .expect("safe symlink and non-root etc directory should be allowed");

        let canonical_q = std::fs::canonicalize(&real_q).expect("canonical real_q");
        let canonical_a = std::fs::canonicalize(&real_a).expect("canonical real_a");

        assert_eq!(updated.quarantine_dir, canonical_q);
        assert_eq!(updated.approved_dir, canonical_a);
        assert_eq!(state.read().await.quarantine_dir, canonical_q);
        assert_eq!(*rx.borrow_and_update(), canonical_q);
    }

    #[tokio::test]
    async fn execute_rejects_traversal_null_bytes_and_forbidden_system_dirs() {
        let root = tempdir().expect("tempdir");
        let valid_q = root.path().join("quarantine");
        let valid_a = root.path().join("approved");
        std::fs::create_dir_all(&valid_q).expect("create quarantine");
        std::fs::create_dir_all(&valid_a).expect("create approved");
        let (use_case, store, state, rx) = setup_use_case(valid_q.clone(), valid_a.clone());

        let traversal_cases = [
            (
                "quarantine_parent_dir",
                root.path().join("../escape"),
                valid_a.clone(),
            ),
            (
                "approved_parent_dir",
                valid_q.clone(),
                root.path().join("sub/../escape"),
            ),
            (
                "quarantine_null_byte",
                PathBuf::from("/tmp/quarantine\0evil"),
                valid_a.clone(),
            ),
            (
                "approved_null_byte",
                valid_q.clone(),
                PathBuf::from("/tmp/approved\0evil"),
            ),
        ];

        for (label, q, a) in traversal_cases {
            let err = use_case
                .execute(basic_req(q, a))
                .await
                .expect_err("traversal / null byte must be rejected");
            assert!(
                matches!(err, DomainError::PathTraversalAttempt(_)),
                "expected PathTraversalAttempt for {label}, got {err:?}"
            );
        }

        let mut forbidden_paths: Vec<PathBuf> =
            FORBIDDEN_SYSTEM_DIRS.iter().map(PathBuf::from).collect();
        forbidden_paths.push(PathBuf::from("/"));
        forbidden_paths.push(PathBuf::from("/etc/sentinel_sub"));
        forbidden_paths.push(PathBuf::from("/usr/local/bin"));
        forbidden_paths.push(PathBuf::from("/root/.ssh"));

        for forbidden in &forbidden_paths {
            let err_q = use_case
                .execute(basic_req(forbidden.clone(), valid_a.clone()))
                .await
                .expect_err("system directory in quarantine_dir must be rejected");
            assert!(
                matches!(err_q, DomainError::ForbiddenSystemDirectory(_)),
                "expected ForbiddenSystemDirectory for quarantine_dir={}, got {err_q:?}",
                forbidden.display()
            );

            let err_a = use_case
                .execute(basic_req(valid_q.clone(), forbidden.clone()))
                .await
                .expect_err("system directory in approved_dir must be rejected");
            assert!(
                matches!(err_a, DomainError::ForbiddenSystemDirectory(_)),
                "expected ForbiddenSystemDirectory for approved_dir={}, got {err_a:?}",
                forbidden.display()
            );
        }

        // Absolute and relative symlinks pointing to a forbidden directory must also be caught.
        let abs_link = root.path().join("abs_etc_link");
        std::os::unix::fs::symlink("/etc", &abs_link).expect("create abs symlink");
        let abs_err = use_case
            .execute(basic_req(abs_link, valid_a.clone()))
            .await
            .expect_err("absolute symlink into /etc must be rejected");
        assert!(matches!(abs_err, DomainError::ForbiddenSystemDirectory(_)));

        let rel_link = root.path().join("rel_etc_link");
        std::os::unix::fs::symlink("../../../../../../etc", &rel_link).expect("create rel symlink");
        let rel_err = use_case
            .execute(basic_req(valid_q.clone(), rel_link))
            .await
            .expect_err("relative symlink into /etc must be rejected");
        assert!(matches!(rel_err, DomainError::ForbiddenSystemDirectory(_)));

        // None of the rejected requests should have persisted, updated state, or notified watcher.
        assert!(store.saved.lock().expect("lock").is_none());
        assert_eq!(state.read().await.quarantine_dir, valid_q);
        assert_eq!(state.read().await.approved_dir, valid_a);
        assert!(!rx.has_changed().expect("watch channel open"));
    }

    #[tokio::test]
    async fn execute_rejects_same_nested_nonexistent_file_empty_and_readonly_dirs() {
        let root = tempdir().expect("tempdir");
        let dir_a = root.path().join("dir_a");
        let dir_b = root.path().join("dir_b");
        let nested = dir_a.join("nested");
        let deeply_nested = nested.join("deep");
        let file_path = root.path().join("regular_file.txt");
        let readonly_dir = root.path().join("readonly");

        std::fs::create_dir_all(&deeply_nested).expect("create deeply_nested");
        std::fs::create_dir_all(&dir_b).expect("create dir_b");
        std::fs::write(&file_path, b"hello").expect("create file");
        std::fs::create_dir_all(&readonly_dir).expect("create readonly");
        std::fs::set_permissions(&readonly_dir, std::fs::Permissions::from_mode(0o555))
            .expect("chmod 0555");

        let alias_to_dir_a = root.path().join("dir_a_alias");
        std::os::unix::fs::symlink(&dir_a, &alias_to_dir_a).expect("create alias symlink");
        let alias_to_nested = root.path().join("nested_alias");
        std::os::unix::fs::symlink(&nested, &alias_to_nested).expect("create nested alias");

        let (use_case, store, state, rx) = setup_use_case(dir_a.clone(), dir_b.clone());

        let cases = [
            ("same_dir", dir_a.clone(), dir_a.clone()),
            ("same_dir_via_symlink", alias_to_dir_a, dir_a.clone()),
            ("approved_inside_quarantine", dir_a.clone(), nested.clone()),
            (
                "approved_deeply_inside_quarantine",
                dir_a.clone(),
                deeply_nested,
            ),
            ("quarantine_inside_approved", nested, dir_a.clone()),
            (
                "quarantine_inside_approved_via_symlink",
                alias_to_nested,
                dir_a.clone(),
            ),
            (
                "nonexistent_quarantine",
                root.path().join("missing_q"),
                dir_a.clone(),
            ),
            (
                "nonexistent_approved",
                dir_a.clone(),
                root.path().join("missing_a"),
            ),
            ("regular_file_quarantine", file_path.clone(), dir_a.clone()),
            ("regular_file_approved", dir_a.clone(), file_path.clone()),
            (
                "path_through_regular_file",
                file_path.join("subdir"),
                dir_a.clone(),
            ),
            ("empty_quarantine", PathBuf::new(), dir_a.clone()),
            ("empty_approved", dir_a.clone(), PathBuf::new()),
            ("readonly_quarantine", readonly_dir.clone(), dir_a),
        ];

        for (name, q, a) in cases {
            let err = use_case
                .execute(basic_req(q, a))
                .await
                .expect_err("invalid directory configuration should fail");
            assert!(
                matches!(err, DomainError::InvalidPath(_)),
                "case '{name}' expected DomainError::InvalidPath, got {err:?}"
            );
        }

        // Restore permissions so tempdir cleanup succeeds cleanly.
        let _ = std::fs::set_permissions(&readonly_dir, std::fs::Permissions::from_mode(0o755));

        assert!(store.saved.lock().expect("lock").is_none());
        assert_eq!(state.read().await.quarantine_dir, root.path().join("dir_a"));
        assert_eq!(state.read().await.approved_dir, dir_b);
        assert!(!rx.has_changed().expect("watch channel open"));
    }

    #[tokio::test]
    async fn execute_validates_auxiliary_paths_and_succeeds_without_active_watcher() {
        let root = tempdir().expect("tempdir");
        let old_q = root.path().join("old_q");
        let old_a = root.path().join("old_a");
        let new_q = root.path().join("new_q");
        let new_a = root.path().join("new_a");
        std::fs::create_dir_all(&old_q).expect("create old_q");
        std::fs::create_dir_all(&old_a).expect("create old_a");
        std::fs::create_dir_all(&new_q).expect("create new_q");
        std::fs::create_dir_all(&new_a).expect("create new_a");

        let etc_link = root.path().join("etc_link");
        std::os::unix::fs::symlink("/etc", &etc_link).expect("create etc symlink");

        let (use_case, _, state, rx) = setup_use_case(old_q.clone(), old_a);
        drop(rx);

        // Rejects forbidden system directory in auxiliary socket path without mutating state.
        let bad_aux = use_case
            .execute(UpdateConfigRequest {
                quarantine_dir: new_q.clone(),
                approved_dir: new_a.clone(),
                clamd_socket_path: Some(PathBuf::from("/etc/clamav/clamd.ctl")),
                suricata_eve_path: None,
            })
            .await
            .expect_err("forbidden auxiliary path must fail");
        assert!(matches!(bad_aux, DomainError::ForbiddenSystemDirectory(_)));
        assert_eq!(state.read().await.quarantine_dir, old_q);

        // Rejects symlink ancestor into /etc and '..' traversal in auxiliary paths.
        let bad_sym_aux = use_case
            .execute(UpdateConfigRequest {
                quarantine_dir: new_q.clone(),
                approved_dir: new_a.clone(),
                clamd_socket_path: None,
                suricata_eve_path: Some(etc_link.join("eve.json")),
            })
            .await
            .expect_err("auxiliary path with symlink ancestor into /etc must fail");
        assert!(matches!(
            bad_sym_aux,
            DomainError::ForbiddenSystemDirectory(_)
        ));

        let bad_trav_aux = use_case
            .execute(UpdateConfigRequest {
                quarantine_dir: new_q.clone(),
                approved_dir: new_a.clone(),
                clamd_socket_path: Some(root.path().join("../clamd.ctl")),
                suricata_eve_path: None,
            })
            .await
            .expect_err("auxiliary path traversal must fail");
        assert!(matches!(bad_trav_aux, DomainError::PathTraversalAttempt(_)));

        let empty_aux = use_case
            .execute(UpdateConfigRequest {
                quarantine_dir: new_q.clone(),
                approved_dir: new_a.clone(),
                clamd_socket_path: Some(PathBuf::new()),
                suricata_eve_path: None,
            })
            .await
            .expect_err("empty auxiliary path must fail");
        assert!(matches!(empty_aux, DomainError::InvalidPath(_)));

        // Succeeds even with dropped watch receiver and valid auxiliary paths.
        let custom_clamd = root.path().join("clamd.ctl");
        let custom_eve = root.path().join("eve.json");
        let updated = use_case
            .execute(UpdateConfigRequest {
                quarantine_dir: new_q,
                approved_dir: new_a,
                clamd_socket_path: Some(custom_clamd.clone()),
                suricata_eve_path: Some(custom_eve.clone()),
            })
            .await
            .expect("update should succeed even when watcher receiver is dropped");
        assert_eq!(updated.clamd_socket_path, custom_clamd);
        assert_eq!(updated.suricata_eve_path, custom_eve);
    }

    #[tokio::test]
    async fn execute_does_not_mutate_memory_or_notify_watcher_when_store_fails() {
        let root = tempdir().expect("tempdir");
        let old_q = root.path().join("old_q");
        let old_a = root.path().join("old_a");
        let new_q = root.path().join("new_q");
        let new_a = root.path().join("new_a");
        std::fs::create_dir_all(&old_q).expect("create old_q");
        std::fs::create_dir_all(&old_a).expect("create old_a");
        std::fs::create_dir_all(&new_q).expect("create new_q");
        std::fs::create_dir_all(&new_a).expect("create new_a");

        let failing_store = Arc::new(InMemoryConfigStore::failing());
        let (use_case, state, rx) =
            setup_use_case_with_store(failing_store, old_q.clone(), old_a.clone());

        let err = use_case
            .execute(basic_req(new_q, new_a))
            .await
            .expect_err("store error must propagate");
        assert!(matches!(err, DomainError::StorageError(_)));

        let guard = state.read().await;
        assert_eq!(guard.quarantine_dir, old_q);
        assert_eq!(guard.approved_dir, old_a);
        assert!(!rx.has_changed().expect("watch channel open"));
    }

    #[tokio::test]
    async fn execute_rejects_relative_paths_dangling_forbidden_symlinks_and_symlink_loops() {
        let root = tempdir().expect("tempdir");
        let valid_q = root.path().join("valid_q");
        let valid_a = root.path().join("valid_a");
        std::fs::create_dir_all(&valid_q).expect("create valid_q");
        std::fs::create_dir_all(&valid_a).expect("create valid_a");

        let (use_case, store, state, rx) = setup_use_case(valid_q.clone(), valid_a.clone());

        // Relative operational paths must be rejected with InvalidPath.
        let rel_q_err = use_case
            .execute(basic_req(PathBuf::from("relative_q"), valid_a.clone()))
            .await
            .expect_err("relative quarantine_dir must fail");
        assert!(matches!(rel_q_err, DomainError::InvalidPath(_)));

        // Relative auxiliary paths must be rejected with InvalidPath.
        let rel_aux_err = use_case
            .execute(UpdateConfigRequest {
                quarantine_dir: valid_q.clone(),
                approved_dir: valid_a.clone(),
                clamd_socket_path: Some(PathBuf::from("clamd.ctl")),
                suricata_eve_path: None,
            })
            .await
            .expect_err("relative auxiliary path must fail");
        assert!(matches!(rel_aux_err, DomainError::InvalidPath(_)));

        // Dangling symlink pointing to /etc/nonexistent_ctl must return ForbiddenSystemDirectory.
        let dangling_abs = root.path().join("dangling_abs_etc");
        std::os::unix::fs::symlink("/etc/nonexistent_sentinel_target", &dangling_abs)
            .expect("create dangling abs symlink");
        let dangling_abs_err = use_case
            .execute(UpdateConfigRequest {
                quarantine_dir: valid_q.clone(),
                approved_dir: valid_a.clone(),
                clamd_socket_path: Some(dangling_abs),
                suricata_eve_path: None,
            })
            .await
            .expect_err("dangling symlink into /etc must fail");
        assert!(matches!(
            dangling_abs_err,
            DomainError::ForbiddenSystemDirectory(_)
        ));

        // Dangling relative symlink escaping into /etc must return ForbiddenSystemDirectory.
        let dangling_rel = root.path().join("dangling_rel_etc");
        std::os::unix::fs::symlink("../../../../../../etc/nonexistent_eve.json", &dangling_rel)
            .expect("create dangling rel symlink");
        let dangling_rel_err = use_case
            .execute(UpdateConfigRequest {
                quarantine_dir: valid_q.clone(),
                approved_dir: valid_a.clone(),
                clamd_socket_path: None,
                suricata_eve_path: Some(dangling_rel),
            })
            .await
            .expect_err("dangling relative symlink into /etc must fail");
        assert!(matches!(
            dangling_rel_err,
            DomainError::ForbiddenSystemDirectory(_)
        ));

        // Dangling relative symlink to root '/' must return ForbiddenSystemDirectory.
        let dangling_root = root.path().join("dangling_root");
        std::os::unix::fs::symlink("../../../../../../..", &dangling_root)
            .expect("create root symlink");
        let dangling_root_err = use_case
            .execute(UpdateConfigRequest {
                quarantine_dir: valid_q.clone(),
                approved_dir: valid_a.clone(),
                clamd_socket_path: Some(dangling_root),
                suricata_eve_path: None,
            })
            .await
            .expect_err("symlink resolving to '/' must fail");
        assert!(matches!(
            dangling_root_err,
            DomainError::ForbiddenSystemDirectory(_)
        ));

        // Symlink loop (a -> b, b -> a) must terminate cleanly with InvalidPath.
        let loop_a = root.path().join("loop_a");
        let loop_b = root.path().join("loop_b");
        std::os::unix::fs::symlink(&loop_b, &loop_a).expect("create loop_a");
        std::os::unix::fs::symlink(&loop_a, &loop_b).expect("create loop_b");
        let loop_err = use_case
            .execute(UpdateConfigRequest {
                quarantine_dir: valid_q.clone(),
                approved_dir: valid_a.clone(),
                clamd_socket_path: Some(loop_a),
                suricata_eve_path: None,
            })
            .await
            .expect_err("symlink loop must fail");
        assert!(matches!(loop_err, DomainError::InvalidPath(_)));

        // Valid dangling auxiliary symlink to safe sibling resolves to canonical ancestor + suffix.
        let sub_dir = root.path().join("sub");
        std::fs::create_dir_all(&sub_dir).expect("create sub");
        let safe_dangling = sub_dir.join("safe_dangling");
        std::os::unix::fs::symlink("../future_dir/clamd.ctl", &safe_dangling)
            .expect("create safe dangling symlink");
        let updated = use_case
            .execute(UpdateConfigRequest {
                quarantine_dir: valid_q.clone(),
                approved_dir: valid_a.clone(),
                clamd_socket_path: Some(safe_dangling),
                suricata_eve_path: None,
            })
            .await
            .expect("safe dangling auxiliary symlink should resolve cleanly");
        let expected_canonical = std::fs::canonicalize(root.path())
            .expect("canonical root")
            .join("future_dir/clamd.ctl");
        assert_eq!(updated.clamd_socket_path, expected_canonical);

        // First rejections kept store clean until the final valid call.
        assert!(store.saved.lock().expect("lock").is_some());
        assert_eq!(state.read().await.clamd_socket_path, expected_canonical);
        assert!(rx.has_changed().expect("watch channel open"));
    }

    #[tokio::test]
    async fn execute_serializes_concurrent_updates_cleanly() {
        let root = tempdir().expect("tempdir");
        let q1 = root.path().join("q1");
        let a1 = root.path().join("a1");
        let q2 = root.path().join("q2");
        let a2 = root.path().join("a2");
        for d in [&q1, &a1, &q2, &a2] {
            std::fs::create_dir_all(d).expect("create dir");
        }

        let (use_case, store, state, _rx) = setup_use_case(q1.clone(), a1.clone());
        let uc = Arc::new(use_case);

        let uc1 = uc.clone();
        let uc2 = uc.clone();
        let h1 = tokio::spawn(async move { uc1.execute(basic_req(q1, a1)).await });
        let h2 = tokio::spawn(async move { uc2.execute(basic_req(q2, a2)).await });

        let r1 = h1.await.expect("join 1").expect("update 1");
        let r2 = h2.await.expect("join 2").expect("update 2");

        let in_mem = state.read().await.clone();
        let persisted = store
            .saved
            .lock()
            .expect("lock")
            .clone()
            .expect("saved config");

        // Memory state and persisted store must never diverge after concurrent updates.
        assert_eq!(in_mem, persisted);
        assert!(in_mem == r1 || in_mem == r2);
    }
}
