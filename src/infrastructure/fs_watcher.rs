//! Linux `inotify` directory watcher and atomic/streaming quarantine file mover.

use std::io::{ErrorKind, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock as StdRwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use notify::event::{AccessKind, AccessMode};
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::{mpsc, watch};

use crate::domain::errors::DomainError;
use crate::domain::path_policy::{reject_forbidden_system_dir, sanitize_file_name};
use crate::domain::ports::QuarantineMover;
use crate::infrastructure::magic_bytes::STREAM_CHUNK_SIZE;

const WRITE_PROBE_PREFIX: &str = ".sentinel_guard_write_probe_";
const ISOLATED_SUBDIR_NAME: &str = ".isolated";
const MODE_ISOLATED_FILE: u32 = 0o600;
const MODE_APPROVED_FILE: u32 = 0o640;
#[cfg(unix)]
const MODE_ISOLATED_DIR: u32 = 0o700;
const MAX_COLLISION_ATTEMPTS: usize = 128;

static COLLISION_SEQ: AtomicU64 = AtomicU64::new(0);

/// Non-recursive filesystem watcher emitting `IN_CLOSE_WRITE` file paths for the active quarantine directory.
pub struct InotifyWatcher {
    watcher: RecommendedWatcher,
    current_dir: PathBuf,
    shared_current_dir: Arc<StdRwLock<PathBuf>>,
    dir_rx: watch::Receiver<PathBuf>,
}

impl InotifyWatcher {
    /// Validates `initial_dir`, initializes `RecommendedWatcher`, and immediately registers a non-recursive watch.
    pub fn new(
        initial_dir: PathBuf,
        dir_rx: watch::Receiver<PathBuf>,
        event_tx: mpsc::Sender<PathBuf>,
    ) -> Result<Self, DomainError> {
        let canonical_dir = validate_watch_dir(&initial_dir)?;
        let shared_current_dir = Arc::new(StdRwLock::new(canonical_dir.clone()));
        let callback_dir = Arc::clone(&shared_current_dir);

        let mut watcher = RecommendedWatcher::new(
            move |res: notify::Result<Event>| {
                handle_notify_event(res, &callback_dir, &event_tx);
            },
            Config::default(),
        )
        .map_err(map_notify_error)?;

        watcher
            .watch(&canonical_dir, RecursiveMode::NonRecursive)
            .map_err(map_notify_error)?;

        tracing::info!(
            quarantine_dir = %canonical_dir.display(),
            "Registered non-recursive inotify watcher"
        );

        Ok(Self {
            watcher,
            current_dir: canonical_dir,
            shared_current_dir,
            dir_rx,
        })
    }

    /// Returns the canonical directory currently being monitored.
    pub fn current_dir(&self) -> &Path {
        &self.current_dir
    }

    /// Runs the watcher control loop for dynamic directory hot-reloading and graceful shutdown.
    pub async fn run(mut self, mut shutdown_rx: watch::Receiver<bool>) -> Result<(), DomainError> {
        if *shutdown_rx.borrow_and_update() {
            self.unwatch_current();
            return Ok(());
        }

        let mut dir_updates_open = true;

        loop {
            tokio::select! {
                shutdown_changed = shutdown_rx.changed() => {
                    match shutdown_changed {
                        Ok(()) => {
                            if *shutdown_rx.borrow_and_update() {
                                tracing::info!("Shutdown requested; stopping inotify watcher");
                                self.unwatch_current();
                                return Ok(());
                            }
                        }
                        Err(_) => {
                            tracing::info!("Shutdown channel closed; stopping inotify watcher");
                            self.unwatch_current();
                            return Ok(());
                        }
                    }
                }
                dir_changed = self.dir_rx.changed(), if dir_updates_open => {
                    match dir_changed {
                        Ok(()) => {
                            let candidate_dir = self.dir_rx.borrow_and_update().clone();
                            self.reload_watched_dir(candidate_dir).await;
                        }
                        Err(_) => {
                            tracing::debug!(
                                "Directory update watch channel closed; keeping active watch"
                            );
                            dir_updates_open = false;
                        }
                    }
                }
            }
        }
    }

    async fn reload_watched_dir(&mut self, candidate_dir: PathBuf) {
        let candidate_for_task = candidate_dir.clone();
        let validation =
            tokio::task::spawn_blocking(move || validate_watch_dir(&candidate_for_task)).await;

        let canonical_new = match validation {
            Ok(Ok(dir)) => dir,
            Ok(Err(err)) => {
                tracing::warn!(
                    path = %candidate_dir.display(),
                    error = %err,
                    "Ignoring invalid quarantine directory reload; preserving active watch"
                );
                return;
            }
            Err(join_err) => {
                tracing::warn!(
                    path = %candidate_dir.display(),
                    error = %join_err,
                    "Quarantine directory validation task failed; preserving active watch"
                );
                return;
            }
        };

        if canonical_new == self.current_dir {
            tracing::debug!(
                quarantine_dir = %self.current_dir.display(),
                "Updated quarantine directory matches active watch; skipping reload"
            );
            return;
        }

        // Update shared filter before adding the new watch so immediate events are not dropped,
        // and restore it if registering the new watch fails.
        let previous_dir = self.current_dir.clone();
        set_shared_dir(&self.shared_current_dir, canonical_new.clone());

        if let Err(err) = self
            .watcher
            .watch(&canonical_new, RecursiveMode::NonRecursive)
        {
            set_shared_dir(&self.shared_current_dir, previous_dir);
            tracing::warn!(
                new_dir = %canonical_new.display(),
                error = %err,
                "Failed to register inotify watch on updated directory; keeping current watch"
            );
            return;
        }

        self.current_dir = canonical_new;

        if let Err(err) = self.watcher.unwatch(&previous_dir) {
            tracing::warn!(
                old_dir = %previous_dir.display(),
                error = %err,
                "Failed to unwatch previous quarantine directory after reload"
            );
        }

        tracing::info!(
            old_dir = %previous_dir.display(),
            new_dir = %self.current_dir.display(),
            "Hot-reloaded inotify watch directory"
        );
    }

    fn unwatch_current(&mut self) {
        if let Err(err) = self.watcher.unwatch(&self.current_dir) {
            tracing::debug!(
                quarantine_dir = %self.current_dir.display(),
                error = %err,
                "Failed to unwatch quarantine directory during shutdown"
            );
        }
    }
}

/// Hardens file permissions and performs collision-free atomic/streaming file disposition.
#[derive(Debug, Default, Clone, Copy)]
pub struct FsQuarantineMover;

impl FsQuarantineMover {
    /// Creates a new [`FsQuarantineMover`] instance.
    pub fn new() -> Self {
        Self
    }

    async fn safe_move_file(
        &self,
        source: &Path,
        dest_base_dir: &Path,
        isolated: bool,
    ) -> Result<PathBuf, DomainError> {
        let target_mode = mode_for_isolated(isolated);
        let source_owned = source.to_path_buf();
        let dest_base_owned = dest_base_dir.to_path_buf();

        tokio::task::spawn_blocking(move || {
            let validated_source = validate_source_file(&source_owned)?;
            apply_permissions_safely(&validated_source, target_mode)?;

            let dir_label = if isolated {
                "quarantine_dir"
            } else {
                "approved_dir"
            };
            let canonical_base = validate_dest_dir(&dest_base_owned, dir_label)?;
            let target_dir = if isolated {
                ensure_isolated_dir(&canonical_base.canonical_path)?
            } else {
                canonical_base
            };

            let revalidated = validate_source_file(&validated_source.canonical_path)?;
            #[cfg(unix)]
            if revalidated.dev_ino != validated_source.dev_ino {
                return Err(DomainError::PathTraversalAttempt(format!(
                    "Source file identity changed before disposition (TOCTOU): {}",
                    validated_source.canonical_path.display()
                )));
            }

            move_validated_file_blocking(&revalidated, &target_dir, target_mode)
        })
        .await
        .map_err(|err| {
            DomainError::QuarantineError(format!("File disposition task failed: {err}"))
        })?
    }
}

#[async_trait]
impl QuarantineMover for FsQuarantineMover {
    async fn harden_permissions(&self, path: &Path, isolated: bool) -> Result<(), DomainError> {
        let path_owned = path.to_path_buf();
        let mode = mode_for_isolated(isolated);

        tokio::task::spawn_blocking(move || {
            let validated = validate_source_file(&path_owned)?;
            apply_permissions_safely(&validated, mode)
        })
        .await
        .map_err(|err| {
            DomainError::QuarantineError(format!("Permission hardening task failed: {err}"))
        })?
    }

    async fn move_to_approved(
        &self,
        source: &Path,
        approved_dir: &Path,
    ) -> Result<PathBuf, DomainError> {
        self.safe_move_file(source, approved_dir, false).await
    }

    async fn isolate_rejected(
        &self,
        source: &Path,
        quarantine_dir: &Path,
    ) -> Result<PathBuf, DomainError> {
        self.safe_move_file(source, quarantine_dir, true).await
    }
}

struct ValidatedSourceFile {
    sanitized_name: String,
    canonical_path: PathBuf,
    #[cfg(unix)]
    dev_ino: (u64, u64),
}

struct ValidatedTargetDir {
    canonical_path: PathBuf,
    #[cfg(unix)]
    dev_ino: (u64, u64),
}

/// Validates that `dir` is an existing non-symlink directory outside forbidden system paths and returns its canonical path.
pub fn validate_real_directory(dir: &Path, label: &str) -> Result<PathBuf, DomainError> {
    validate_dest_dir(dir, label).map(|validated| validated.canonical_path)
}

struct PartialFileCleanupGuard {
    path: Option<PathBuf>,
}

impl Drop for PartialFileCleanupGuard {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

enum StreamingMoveOutcome {
    Moved,
    DestAlreadyExists,
}

fn mode_for_isolated(isolated: bool) -> u32 {
    if isolated {
        MODE_ISOLATED_FILE
    } else {
        MODE_APPROVED_FILE
    }
}

fn set_shared_dir(shared: &StdRwLock<PathBuf>, new_dir: PathBuf) {
    match shared.write() {
        Ok(mut guard) => *guard = new_dir,
        Err(poisoned) => *poisoned.into_inner() = new_dir,
    }
}

fn handle_notify_event(
    res: notify::Result<Event>,
    shared_current_dir: &StdRwLock<PathBuf>,
    event_tx: &mpsc::Sender<PathBuf>,
) {
    let event = match res {
        Ok(event) => event,
        Err(err) => {
            tracing::warn!(error = %err, "Filesystem watcher received error notification");
            return;
        }
    };

    if event.kind != EventKind::Access(AccessKind::Close(AccessMode::Write)) {
        return;
    }

    let current_dir = match shared_current_dir.read() {
        Ok(guard) => guard.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    };

    for path in event.paths {
        if should_ignore_entry(&path) {
            continue;
        }
        if path.parent() != Some(current_dir.as_path()) {
            tracing::debug!(
                path = %path.display(),
                watched_dir = %current_dir.display(),
                "Ignoring IN_CLOSE_WRITE event outside currently watched directory"
            );
            continue;
        }
        if event_tx.blocking_send(path).is_err() {
            break;
        }
    }
}

fn should_ignore_entry(path: &Path) -> bool {
    let Some(file_name) = path.file_name() else {
        return true;
    };
    if let Some(name) = file_name.to_str() {
        return name.starts_with(WRITE_PROBE_PREFIX) || name == ISOLATED_SUBDIR_NAME;
    }
    false
}

fn map_notify_error(err: notify::Error) -> DomainError {
    DomainError::QuarantineError(format!("Filesystem watcher error: {err}"))
}

fn check_basic_dir_path(path: &Path, label: &str) -> Result<(), DomainError> {
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
    for component in path.components() {
        if matches!(component, Component::ParentDir) {
            return Err(DomainError::PathTraversalAttempt(format!(
                "Parent directory traversal ('..') is not allowed in {label}: {}",
                path.display()
            )));
        }
    }
    reject_forbidden_system_dir(path)
}

fn map_dir_io_error(path: &Path, label: &str, err: std::io::Error) -> DomainError {
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

fn validate_watch_dir(dir: &Path) -> Result<PathBuf, DomainError> {
    check_basic_dir_path(dir, "watch_dir")?;

    let canonical =
        std::fs::canonicalize(dir).map_err(|err| map_dir_io_error(dir, "watch_dir", err))?;
    reject_forbidden_system_dir(&canonical)?;

    let metadata = std::fs::metadata(&canonical)?;
    if !metadata.is_dir() {
        return Err(DomainError::InvalidPath(format!(
            "watch_dir path is not a directory: {}",
            canonical.display()
        )));
    }

    Ok(canonical)
}

fn validate_source_file(source: &Path) -> Result<ValidatedSourceFile, DomainError> {
    let sanitized_name = sanitize_file_name(source)?;
    reject_forbidden_system_dir(source)?;

    let link_meta = std::fs::symlink_metadata(source)?;
    if link_meta.file_type().is_symlink() {
        return Err(DomainError::PathTraversalAttempt(format!(
            "Symlinks are not permitted: {}",
            source.display()
        )));
    }
    if !link_meta.file_type().is_file() {
        return Err(DomainError::InvalidPath(format!(
            "Source path is not a regular file: {}",
            source.display()
        )));
    }

    let canonical_path = std::fs::canonicalize(source)?;
    reject_forbidden_system_dir(&canonical_path)?;

    let canonical_meta = std::fs::symlink_metadata(&canonical_path)?;
    if canonical_meta.file_type().is_symlink() {
        return Err(DomainError::PathTraversalAttempt(format!(
            "Canonical source path must not be a symlink: {}",
            canonical_path.display()
        )));
    }
    if !canonical_meta.file_type().is_file() {
        return Err(DomainError::InvalidPath(format!(
            "Canonical source path is not a regular file: {}",
            canonical_path.display()
        )));
    }

    #[cfg(unix)]
    let dev_ino = {
        use std::os::unix::fs::MetadataExt;
        let link_id = (link_meta.dev(), link_meta.ino());
        let canonical_id = (canonical_meta.dev(), canonical_meta.ino());
        if link_id != canonical_id {
            return Err(DomainError::PathTraversalAttempt(format!(
                "Source file identity changed during validation (TOCTOU): {}",
                source.display()
            )));
        }
        link_id
    };

    Ok(ValidatedSourceFile {
        sanitized_name,
        canonical_path,
        #[cfg(unix)]
        dev_ino,
    })
}

fn validate_dest_dir(dest_dir: &Path, label: &str) -> Result<ValidatedTargetDir, DomainError> {
    check_basic_dir_path(dest_dir, label)?;

    // Strip any trailing slash before lstat so POSIX does not follow a leaf symlink.
    let normalized_dest: PathBuf = dest_dir.components().collect();
    reject_forbidden_system_dir(&normalized_dest)?;

    let link_meta = std::fs::symlink_metadata(&normalized_dest)
        .map_err(|err| map_dir_io_error(&normalized_dest, label, err))?;
    if link_meta.file_type().is_symlink() {
        return Err(DomainError::PathTraversalAttempt(format!(
            "{label} must not be a symlink: {}",
            normalized_dest.display()
        )));
    }
    if !link_meta.file_type().is_dir() {
        return Err(DomainError::InvalidPath(format!(
            "{label} is not a directory: {}",
            normalized_dest.display()
        )));
    }

    let canonical_dest = std::fs::canonicalize(&normalized_dest)
        .map_err(|err| map_dir_io_error(&normalized_dest, label, err))?;
    reject_forbidden_system_dir(&canonical_dest)?;

    let canonical_meta = std::fs::symlink_metadata(&canonical_dest)?;
    if canonical_meta.file_type().is_symlink() {
        return Err(DomainError::PathTraversalAttempt(format!(
            "Canonical {label} must not be a symlink: {}",
            canonical_dest.display()
        )));
    }
    if !canonical_meta.file_type().is_dir() {
        return Err(DomainError::InvalidPath(format!(
            "Canonical {label} is not a directory: {}",
            canonical_dest.display()
        )));
    }

    #[cfg(unix)]
    let dev_ino = {
        use std::os::unix::fs::MetadataExt;
        let link_id = (link_meta.dev(), link_meta.ino());
        let canonical_id = (canonical_meta.dev(), canonical_meta.ino());
        if link_id != canonical_id {
            return Err(DomainError::PathTraversalAttempt(format!(
                "{label} identity changed during validation (TOCTOU): {}",
                dest_dir.display()
            )));
        }
        canonical_id
    };

    Ok(ValidatedTargetDir {
        canonical_path: canonical_dest,
        #[cfg(unix)]
        dev_ino,
    })
}

fn ensure_isolated_dir(canonical_quarantine: &Path) -> Result<ValidatedTargetDir, DomainError> {
    let isolated_dir = canonical_quarantine.join(ISOLATED_SUBDIR_NAME);
    let mut created_now = false;

    let link_meta = match std::fs::symlink_metadata(&isolated_dir) {
        Ok(meta) => meta,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(MODE_ISOLATED_DIR);
            }
            match builder.create(&isolated_dir) {
                Ok(()) => {
                    created_now = true;
                    std::fs::symlink_metadata(&isolated_dir)?
                }
                Err(create_err) if create_err.kind() == ErrorKind::AlreadyExists => {
                    std::fs::symlink_metadata(&isolated_dir)?
                }
                Err(create_err) => return Err(DomainError::IoError(create_err)),
            }
        }
        Err(err) => return Err(DomainError::IoError(err)),
    };

    if link_meta.file_type().is_symlink() {
        return Err(DomainError::PathTraversalAttempt(format!(
            "Isolated directory must not be a symlink: {}",
            isolated_dir.display()
        )));
    }
    if !link_meta.file_type().is_dir() {
        return Err(DomainError::InvalidPath(format!(
            "Isolated path exists and is not a directory: {}",
            isolated_dir.display()
        )));
    }

    let canonical_isolated = std::fs::canonicalize(&isolated_dir)?;
    reject_forbidden_system_dir(&canonical_isolated)?;

    let canonical_meta = std::fs::symlink_metadata(&canonical_isolated)?;
    if canonical_meta.file_type().is_symlink() || !canonical_meta.file_type().is_dir() {
        return Err(DomainError::InvalidPath(format!(
            "Canonical isolated path is not a regular directory: {}",
            canonical_isolated.display()
        )));
    }

    #[cfg(unix)]
    let dev_ino = {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let link_id = (link_meta.dev(), link_meta.ino());
        let canonical_id = (canonical_meta.dev(), canonical_meta.ino());
        if link_id != canonical_id {
            return Err(DomainError::PathTraversalAttempt(format!(
                "Isolated directory identity changed during validation (TOCTOU): {}",
                isolated_dir.display()
            )));
        }
        if created_now || (canonical_meta.permissions().mode() & 0o777) != MODE_ISOLATED_DIR {
            std::fs::set_permissions(
                &canonical_isolated,
                std::fs::Permissions::from_mode(MODE_ISOLATED_DIR),
            )?;
        }
        canonical_id
    };

    #[cfg(not(unix))]
    let _ = created_now;

    Ok(ValidatedTargetDir {
        canonical_path: canonical_isolated,
        #[cfg(unix)]
        dev_ino,
    })
}

fn verify_target_dir_identity(target_dir: &ValidatedTargetDir) -> Result<(), DomainError> {
    reject_forbidden_system_dir(&target_dir.canonical_path)?;

    let meta = std::fs::symlink_metadata(&target_dir.canonical_path)?;
    if meta.file_type().is_symlink() {
        return Err(DomainError::PathTraversalAttempt(format!(
            "Destination directory became a symlink (TOCTOU): {}",
            target_dir.canonical_path.display()
        )));
    }
    if !meta.file_type().is_dir() {
        return Err(DomainError::InvalidPath(format!(
            "Destination path is no longer a regular directory: {}",
            target_dir.canonical_path.display()
        )));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if (meta.dev(), meta.ino()) != target_dir.dev_ino {
            return Err(DomainError::PathTraversalAttempt(format!(
                "Destination directory identity changed before disposition (TOCTOU): {}",
                target_dir.canonical_path.display()
            )));
        }
    }

    Ok(())
}

#[cfg(unix)]
fn apply_permissions_safely(validated: &ValidatedSourceFile, mode: u32) -> Result<(), DomainError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);

    match opts.open(&validated.canonical_path) {
        Ok(file) => {
            let meta = file.metadata()?;
            if !meta.file_type().is_file() {
                return Err(DomainError::InvalidPath(format!(
                    "Opened handle is not a regular file: {}",
                    validated.canonical_path.display()
                )));
            }
            if (meta.dev(), meta.ino()) != validated.dev_ino {
                return Err(DomainError::PathTraversalAttempt(format!(
                    "File identity changed before hardening permissions (TOCTOU): {}",
                    validated.canonical_path.display()
                )));
            }
            file.set_permissions(std::fs::Permissions::from_mode(mode))?;
            Ok(())
        }
        Err(err) if err.kind() == ErrorKind::PermissionDenied => {
            // An incoming file may be write-only or 0o000 before quarantine hardening.
            let pre_meta = std::fs::symlink_metadata(&validated.canonical_path)?;
            if pre_meta.file_type().is_symlink() || !pre_meta.file_type().is_file() {
                return Err(DomainError::PathTraversalAttempt(format!(
                    "File became symlink or non-regular before chmod: {}",
                    validated.canonical_path.display()
                )));
            }
            if (pre_meta.dev(), pre_meta.ino()) != validated.dev_ino {
                return Err(DomainError::PathTraversalAttempt(format!(
                    "File identity changed before chmod (TOCTOU): {}",
                    validated.canonical_path.display()
                )));
            }
            std::fs::set_permissions(
                &validated.canonical_path,
                std::fs::Permissions::from_mode(mode),
            )?;
            let post_meta = std::fs::symlink_metadata(&validated.canonical_path)?;
            if (post_meta.dev(), post_meta.ino()) != validated.dev_ino {
                return Err(DomainError::PathTraversalAttempt(format!(
                    "File identity changed during chmod (TOCTOU): {}",
                    validated.canonical_path.display()
                )));
            }
            Ok(())
        }
        Err(err) => Err(DomainError::IoError(err)),
    }
}

#[cfg(not(unix))]
fn apply_permissions_safely(
    validated: &ValidatedSourceFile,
    _mode: u32,
) -> Result<(), DomainError> {
    let mut perms = std::fs::metadata(&validated.canonical_path)?.permissions();
    perms.set_readonly(false);
    std::fs::set_permissions(&validated.canonical_path, perms)?;
    Ok(())
}

fn build_collision_file_name(sanitized_name: &str, attempt: usize) -> String {
    if attempt == 0 {
        return sanitized_name.to_string();
    }

    let unix_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let seq = COLLISION_SEQ.fetch_add(1, Ordering::Relaxed);

    let path = Path::new(sanitized_name);
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(sanitized_name);
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty());

    match ext {
        Some(ext_str) => format!("{stem}_{unix_nanos}_{pid}_{seq}.{ext_str}"),
        None => format!("{stem}_{unix_nanos}_{pid}_{seq}"),
    }
}

fn is_cross_device_error(err: &std::io::Error) -> bool {
    if err.kind() == ErrorKind::CrossesDevices {
        return true;
    }
    #[cfg(unix)]
    if err.raw_os_error() == Some(libc::EXDEV) {
        return true;
    }
    false
}

fn move_validated_file_blocking(
    validated_source: &ValidatedSourceFile,
    target_dir: &ValidatedTargetDir,
    target_mode: u32,
) -> Result<PathBuf, DomainError> {
    verify_target_dir_identity(target_dir)?;
    move_validated_file_with_linker(validated_source, target_dir, target_mode, |src, dst| {
        std::fs::hard_link(src, dst)
    })
}

fn move_validated_file_with_linker<F>(
    validated_source: &ValidatedSourceFile,
    target_dir: &ValidatedTargetDir,
    target_mode: u32,
    mut hard_linker: F,
) -> Result<PathBuf, DomainError>
where
    F: FnMut(&Path, &Path) -> std::io::Result<()>,
{
    for attempt in 0..MAX_COLLISION_ATTEMPTS {
        verify_target_dir_identity(target_dir)?;

        let candidate_name = build_collision_file_name(&validated_source.sanitized_name, attempt);
        let dest_path = target_dir.canonical_path.join(&candidate_name);

        match std::fs::symlink_metadata(&dest_path) {
            Ok(_) => continue,
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            Err(err) => return Err(DomainError::IoError(err)),
        }

        match hard_linker(&validated_source.canonical_path, &dest_path) {
            Ok(()) => {
                let dest_meta = match std::fs::symlink_metadata(&dest_path) {
                    Ok(meta) => meta,
                    Err(err) => {
                        let _ = std::fs::remove_file(&dest_path);
                        return Err(DomainError::IoError(err));
                    }
                };
                if dest_meta.file_type().is_symlink() || !dest_meta.file_type().is_file() {
                    let _ = std::fs::remove_file(&dest_path);
                    return Err(DomainError::PathTraversalAttempt(format!(
                        "Hard-linked destination is not a regular file: {}",
                        dest_path.display()
                    )));
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    if (dest_meta.dev(), dest_meta.ino()) != validated_source.dev_ino {
                        let _ = std::fs::remove_file(&dest_path);
                        return Err(DomainError::PathTraversalAttempt(format!(
                            "Source file identity changed before hard-link (TOCTOU): {}",
                            validated_source.canonical_path.display()
                        )));
                    }
                }

                let dest_validated = ValidatedSourceFile {
                    sanitized_name: candidate_name,
                    canonical_path: dest_path.clone(),
                    #[cfg(unix)]
                    dev_ino: validated_source.dev_ino,
                };
                if let Err(err) = apply_permissions_safely(&dest_validated, target_mode) {
                    let _ = std::fs::remove_file(&dest_path);
                    return Err(err);
                }

                if let Err(err) = std::fs::remove_file(&validated_source.canonical_path) {
                    let _ = std::fs::remove_file(&dest_path);
                    return Err(DomainError::IoError(err));
                }

                return Ok(dest_path);
            }
            Err(err) if err.kind() == ErrorKind::AlreadyExists => continue,
            Err(err) if is_cross_device_error(&err) => {
                match stream_copy_and_remove_source(validated_source, &dest_path, target_mode)? {
                    StreamingMoveOutcome::Moved => return Ok(dest_path),
                    StreamingMoveOutcome::DestAlreadyExists => continue,
                }
            }
            Err(err) => return Err(DomainError::IoError(err)),
        }
    }

    Err(DomainError::QuarantineError(format!(
        "Failed to find collision-free destination name after {MAX_COLLISION_ATTEMPTS} attempts in {}",
        target_dir.canonical_path.display()
    )))
}

fn stream_copy_and_remove_source(
    validated_source: &ValidatedSourceFile,
    dest_path: &Path,
    target_mode: u32,
) -> Result<StreamingMoveOutcome, DomainError> {
    let mut src_opts = std::fs::OpenOptions::new();
    src_opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        src_opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }

    let mut src_file = src_opts.open(&validated_source.canonical_path)?;
    let src_meta = src_file.metadata()?;
    if !src_meta.file_type().is_file() {
        return Err(DomainError::InvalidPath(format!(
            "Opened source handle is not a regular file: {}",
            validated_source.canonical_path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if (src_meta.dev(), src_meta.ino()) != validated_source.dev_ino {
            return Err(DomainError::PathTraversalAttempt(format!(
                "Source file identity changed before streaming copy (TOCTOU): {}",
                validated_source.canonical_path.display()
            )));
        }
    }

    let mut dst_opts = std::fs::OpenOptions::new();
    dst_opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        dst_opts.mode(target_mode);
    }

    let mut dst_file = match dst_opts.open(dest_path) {
        Ok(file) => file,
        Err(err) if err.kind() == ErrorKind::AlreadyExists => {
            return Ok(StreamingMoveOutcome::DestAlreadyExists);
        }
        Err(err) => return Err(DomainError::IoError(err)),
    };

    let mut cleanup_guard = PartialFileCleanupGuard {
        path: Some(dest_path.to_path_buf()),
    };

    let mut buffer = vec![0u8; STREAM_CHUNK_SIZE];
    loop {
        let bytes_read = match src_file.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) => return Err(DomainError::IoError(err)),
        };
        dst_file.write_all(&buffer[..bytes_read])?;
    }

    dst_file.sync_all()?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        dst_file.set_permissions(std::fs::Permissions::from_mode(target_mode))?;
    }
    #[cfg(not(unix))]
    let _ = target_mode;

    drop(dst_file);
    drop(src_file);

    let current_src_meta = std::fs::symlink_metadata(&validated_source.canonical_path)?;
    if current_src_meta.file_type().is_symlink() || !current_src_meta.file_type().is_file() {
        return Err(DomainError::PathTraversalAttempt(format!(
            "Source path became symlink or non-regular before removal: {}",
            validated_source.canonical_path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if (current_src_meta.dev(), current_src_meta.ino()) != validated_source.dev_ino {
            return Err(DomainError::PathTraversalAttempt(format!(
                "Source file identity changed before removal (TOCTOU): {}",
                validated_source.canonical_path.display()
            )));
        }
    }

    std::fs::remove_file(&validated_source.canonical_path)?;
    cleanup_guard.path = None;

    Ok(StreamingMoveOutcome::Moved)
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;

    use tempfile::tempdir;

    use crate::domain::path_policy::FORBIDDEN_SYSTEM_DIRS;

    use super::*;

    #[tokio::test]
    async fn inotify_watcher_emits_close_write_and_filters_probes_isolated_and_subdirs() {
        let root = tempdir().expect("tempdir");
        let quarantine = root.path().join("quarantine");
        let nested_sub = quarantine.join("nested");
        let isolated_dir = quarantine.join(".isolated");
        std::fs::create_dir_all(&nested_sub).expect("create nested");
        std::fs::create_dir_all(&isolated_dir).expect("create .isolated");

        let (_dir_tx, dir_rx) = watch::channel(quarantine.clone());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (event_tx, mut event_rx) = mpsc::channel(32);

        let watcher = InotifyWatcher::new(quarantine.clone(), dir_rx, event_tx)
            .expect("watcher initialization should succeed");
        let canonical_q = watcher.current_dir().to_path_buf();
        let watcher_handle = tokio::spawn(async move { watcher.run(shutdown_rx).await });

        // Give inotify task a moment to enter select loop.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Ignored entries: probe file, .isolated entry, and file in subdirectory.
        {
            let probe = canonical_q.join(".sentinel_guard_write_probe_999_0");
            std::fs::write(&probe, b"probe").expect("write probe");
            let _ = std::fs::remove_file(&probe);
        }
        {
            let sub_file = nested_sub.join("inside_subdir.txt");
            std::fs::write(&sub_file, b"ignored").expect("write sub file");
        }
        {
            let iso_file = isolated_dir.join("already_isolated.bin");
            std::fs::write(&iso_file, b"ignored").expect("write isolated file");
        }

        // Valid upload directly in watched quarantine directory.
        let valid_file = canonical_q.join("report_2026.pdf");
        {
            let mut file = std::fs::File::create(&valid_file).expect("create valid file");
            file.write_all(b"%PDF-1.5\ncontent")
                .expect("write valid file");
            file.sync_all().expect("sync valid file");
        }

        let received = tokio::time::timeout(Duration::from_secs(3), event_rx.recv())
            .await
            .expect("timeout waiting for IN_CLOSE_WRITE event")
            .expect("event channel should stay open");
        assert_eq!(received, valid_file);

        // Ensure no spurious ignored events arrived.
        let extra = tokio::time::timeout(Duration::from_millis(150), event_rx.recv()).await;
        assert!(extra.is_err(), "expected no extra events, got {extra:?}");

        shutdown_tx.send(true).expect("send shutdown");
        watcher_handle
            .await
            .expect("watcher task join")
            .expect("watcher clean exit");
    }

    #[tokio::test]
    async fn inotify_watcher_hot_reloads_and_preserves_watch_on_invalid_reload() {
        let root = tempdir().expect("tempdir");
        let dir_a = root.path().join("q_a");
        let dir_b = root.path().join("q_b");
        std::fs::create_dir_all(&dir_a).expect("create dir_a");
        std::fs::create_dir_all(&dir_b).expect("create dir_b");

        let (dir_tx, dir_rx) = watch::channel(dir_a.clone());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (event_tx, mut event_rx) = mpsc::channel(32);

        let watcher = InotifyWatcher::new(dir_a.clone(), dir_rx, event_tx)
            .expect("watcher initialization should succeed");
        let canonical_a = watcher.current_dir().to_path_buf();
        let canonical_b = std::fs::canonicalize(&dir_b).expect("canonical dir_b");
        let watcher_handle = tokio::spawn(async move { watcher.run(shutdown_rx).await });

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Invalid reloads (/etc and nonexistent path) must NOT crash or drop dir_a watch.
        dir_tx.send(PathBuf::from("/etc")).expect("send /etc");
        tokio::time::sleep(Duration::from_millis(60)).await;
        dir_tx
            .send(root.path().join("missing_dir"))
            .expect("send missing");
        tokio::time::sleep(Duration::from_millis(60)).await;

        let file_a = canonical_a.join("still_watched.txt");
        std::fs::write(&file_a, b"hello a").expect("write file_a");
        let got_a = tokio::time::timeout(Duration::from_secs(3), event_rx.recv())
            .await
            .expect("timeout waiting for file_a")
            .expect("channel open");
        assert_eq!(got_a, file_a);

        // Reload to dir_b.
        dir_tx.send(dir_b.clone()).expect("send dir_b");
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Old directory must no longer trigger events; new directory must trigger events.
        let ignored_a = canonical_a.join("after_reload_a.txt");
        std::fs::write(&ignored_a, b"ignored").expect("write ignored_a");

        let file_b = canonical_b.join("arrived_b.txt");
        std::fs::write(&file_b, b"hello b").expect("write file_b");

        let got_b = tokio::time::timeout(Duration::from_secs(3), event_rx.recv())
            .await
            .expect("timeout waiting for file_b")
            .expect("channel open");
        assert_eq!(got_b, file_b);

        // Re-sending the exact same dir_b must be a no-op and keep dir_b watched.
        dir_tx.send(canonical_b.clone()).expect("send same dir_b");
        tokio::time::sleep(Duration::from_millis(80)).await;

        let file_b2 = canonical_b.join("second_b.txt");
        std::fs::write(&file_b2, b"hello b2").expect("write file_b2");
        let got_b2 = tokio::time::timeout(Duration::from_secs(3), event_rx.recv())
            .await
            .expect("timeout waiting for file_b2")
            .expect("channel open");
        assert_eq!(got_b2, file_b2);

        shutdown_tx.send(true).expect("send shutdown");
        watcher_handle
            .await
            .expect("join watcher")
            .expect("clean watcher exit");
    }

    #[test]
    fn inotify_watcher_new_rejects_forbidden_missing_non_dir_and_symlinks_to_system() {
        let root = tempdir().expect("tempdir");
        let file_path = root.path().join("regular.txt");
        std::fs::write(&file_path, b"not a dir").expect("write file");
        let etc_link = root.path().join("etc_link");
        std::os::unix::fs::symlink("/etc", &etc_link).expect("symlink /etc");

        for forbidden in FORBIDDEN_SYSTEM_DIRS {
            let (_dtx, drx) = watch::channel(PathBuf::from(forbidden));
            let (etx, _erx) = mpsc::channel(4);
            let err = InotifyWatcher::new(PathBuf::from(forbidden), drx, etx)
                .err()
                .expect("forbidden system dir must fail");
            assert!(matches!(err, DomainError::ForbiddenSystemDirectory(_)));
        }

        let (_dtx, drx) = watch::channel(etc_link.clone());
        let (etx, _erx) = mpsc::channel(4);
        let err = InotifyWatcher::new(etc_link, drx, etx)
            .err()
            .expect("symlink to /etc must fail");
        assert!(matches!(err, DomainError::ForbiddenSystemDirectory(_)));

        let (_dtx, drx) = watch::channel(file_path.clone());
        let (etx, _erx) = mpsc::channel(4);
        let err = InotifyWatcher::new(file_path, drx, etx)
            .err()
            .expect("regular file must fail");
        assert!(matches!(err, DomainError::InvalidPath(_)));

        let missing = root.path().join("does_not_exist");
        let (_dtx, drx) = watch::channel(missing.clone());
        let (etx, _erx) = mpsc::channel(4);
        let err = InotifyWatcher::new(missing, drx, etx)
            .err()
            .expect("missing dir must fail");
        assert!(matches!(err, DomainError::InvalidPath(_)));
    }

    #[tokio::test]
    async fn fs_quarantine_mover_harden_permissions_strips_exec_and_rejects_symlinks() {
        let root = tempdir().expect("tempdir");
        let mover = FsQuarantineMover::new();

        let file_path = root.path().join("script.sh");
        std::fs::write(&file_path, b"#!/bin/sh\necho hi\n").expect("write file");
        std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o755))
            .expect("chmod 0755");

        mover
            .harden_permissions(&file_path, false)
            .await
            .expect("harden 0640");
        let mode_640 = std::fs::metadata(&file_path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode_640, 0o640);

        mover
            .harden_permissions(&file_path, true)
            .await
            .expect("harden 0600");
        let mode_600 = std::fs::metadata(&file_path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode_600, 0o600);

        // Even 0o000 file owned by user can be hardened to 0o640.
        let locked_file = root.path().join("locked.pdf");
        std::fs::write(&locked_file, b"%PDF-1.5").expect("write locked");
        std::fs::set_permissions(&locked_file, std::fs::Permissions::from_mode(0o000))
            .expect("chmod 0000");
        mover
            .harden_permissions(&locked_file, false)
            .await
            .expect("harden 0000 -> 0640");
        let recovered_mode = std::fs::metadata(&locked_file)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(recovered_mode, 0o640);

        // Reject symlinks and directories.
        let symlink_path = root.path().join("link.txt");
        std::os::unix::fs::symlink(&file_path, &symlink_path).expect("symlink");
        let err = mover
            .harden_permissions(&symlink_path, false)
            .await
            .expect_err("symlink must be rejected");
        assert!(matches!(err, DomainError::PathTraversalAttempt(_)));

        let dir_err = mover
            .harden_permissions(root.path(), false)
            .await
            .expect_err("dir must be rejected");
        assert!(matches!(dir_err, DomainError::InvalidPath(_)));
    }

    #[tokio::test]
    async fn fs_quarantine_mover_moves_approved_and_isolated_without_overwriting_collisions() {
        let root = tempdir().expect("tempdir");
        let quarantine = root.path().join("quarantine");
        let approved = root.path().join("approved");
        std::fs::create_dir_all(&quarantine).expect("create quarantine");
        std::fs::create_dir_all(&approved).expect("create approved");
        let mover = FsQuarantineMover::new();

        // 1. Move clean file to approved -> 0o640, source removed.
        let clean_src = quarantine.join("invoice.pdf");
        std::fs::write(&clean_src, b"%PDF-1.5\nfirst").expect("write clean");
        std::fs::set_permissions(&clean_src, std::fs::Permissions::from_mode(0o755))
            .expect("chmod 0755");
        let approved_dest = mover
            .move_to_approved(&clean_src, &approved)
            .await
            .expect("move_to_approved");
        assert_eq!(approved_dest, approved.join("invoice.pdf"));
        assert!(!clean_src.exists());
        assert_eq!(
            std::fs::read(&approved_dest).expect("read dest"),
            b"%PDF-1.5\nfirst"
        );
        assert_eq!(
            std::fs::metadata(&approved_dest)
                .expect("meta")
                .permissions()
                .mode()
                & 0o777,
            0o640
        );

        // 2. Collision with existing file in approved_dir -> unique suffixed name, original intact.
        let clean_dup = quarantine.join("invoice.pdf");
        std::fs::write(&clean_dup, b"%PDF-1.5\nsecond").expect("write clean dup");
        let dup_dest = mover
            .move_to_approved(&clean_dup, &approved)
            .await
            .expect("move collision");
        assert_ne!(dup_dest, approved_dest);
        assert_eq!(dup_dest.extension().and_then(|e| e.to_str()), Some("pdf"));
        assert_eq!(
            std::fs::read(&approved_dest).expect("original intact"),
            b"%PDF-1.5\nfirst"
        );
        assert_eq!(
            std::fs::read(&dup_dest).expect("new dest"),
            b"%PDF-1.5\nsecond"
        );

        // 3. Collision with dangling symlink in approved_dir -> dangling symlink NOT overwritten!
        let dangling_name = "dangling_target";
        let dangling_link = approved.join(dangling_name);
        std::os::unix::fs::symlink(root.path().join("nonexistent"), &dangling_link)
            .expect("dangling symlink");
        let no_ext_src = quarantine.join(dangling_name);
        std::fs::write(&no_ext_src, b"plain readme").expect("write no_ext_src");
        let no_ext_dest = mover
            .move_to_approved(&no_ext_src, &approved)
            .await
            .expect("dangling symlink collision avoided");
        assert_ne!(no_ext_dest, dangling_link);
        assert!(
            std::fs::symlink_metadata(&dangling_link)
                .expect("dangling link still exists")
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            std::fs::read(&no_ext_dest).expect("read no_ext_dest"),
            b"plain readme"
        );

        // 4. Isolate malicious file -> creates .isolated (0o700) and moves file with 0o600.
        let evil_src = quarantine.join("payload.exe");
        std::fs::write(&evil_src, b"\x7fELFmalicious").expect("write evil");
        std::fs::set_permissions(&evil_src, std::fs::Permissions::from_mode(0o777))
            .expect("chmod 0777");
        let isolated_dest = mover
            .isolate_rejected(&evil_src, &quarantine)
            .await
            .expect("isolate_rejected");
        let isolated_dir = quarantine.join(".isolated");
        assert_eq!(isolated_dest, isolated_dir.join("payload.exe"));
        assert!(!evil_src.exists());
        assert_eq!(
            std::fs::metadata(&isolated_dir)
                .expect("isolated dir meta")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&isolated_dest)
                .expect("isolated file meta")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[tokio::test]
    async fn fs_quarantine_mover_rejects_malicious_symlink_dest_and_system_dirs() {
        let root = tempdir().expect("tempdir");
        let quarantine = root.path().join("quarantine");
        let approved = root.path().join("approved");
        std::fs::create_dir_all(&quarantine).expect("create quarantine");
        std::fs::create_dir_all(&approved).expect("create approved");
        let mover = FsQuarantineMover::new();

        let src = quarantine.join("sample.txt");
        std::fs::write(&src, b"hello").expect("write src");

        // Destination directory is a symlink -> rejected.
        let approved_symlink = root.path().join("approved_link");
        std::os::unix::fs::symlink(&approved, &approved_symlink).expect("symlink approved");
        let err = mover
            .move_to_approved(&src, &approved_symlink)
            .await
            .expect_err("symlink dest_dir must be rejected");
        assert!(matches!(err, DomainError::PathTraversalAttempt(_)));
        assert!(src.exists());

        // .isolated is a symlink -> rejected.
        let isolated_symlink = quarantine.join(".isolated");
        std::os::unix::fs::symlink(&approved, &isolated_symlink).expect("symlink .isolated");
        let err = mover
            .isolate_rejected(&src, &quarantine)
            .await
            .expect_err("symlink .isolated must be rejected");
        assert!(matches!(err, DomainError::PathTraversalAttempt(_)));
        assert!(src.exists());

        // Forbidden system dir destination -> rejected.
        let sys_err = mover
            .move_to_approved(&src, Path::new("/etc"))
            .await
            .expect_err("/etc destination must be rejected");
        assert!(matches!(sys_err, DomainError::ForbiddenSystemDirectory(_)));
    }

    #[tokio::test]
    async fn fs_quarantine_mover_hardens_preexisting_permissive_isolated_dir_to_0700() {
        let root = tempdir().expect("tempdir");
        let quarantine = root.path().join("quarantine");
        let isolated_dir = quarantine.join(".isolated");
        std::fs::create_dir_all(&isolated_dir).expect("create .isolated");
        std::fs::set_permissions(&isolated_dir, std::fs::Permissions::from_mode(0o755))
            .expect("chmod 0755 on .isolated");

        let mover = FsQuarantineMover::new();
        let evil_src = quarantine.join("preexisting_isolated.exe");
        std::fs::write(&evil_src, b"\x7fELFmalicious").expect("write evil");
        std::fs::set_permissions(&evil_src, std::fs::Permissions::from_mode(0o755))
            .expect("chmod 0755");

        let isolated_dest = mover
            .isolate_rejected(&evil_src, &quarantine)
            .await
            .expect("isolate_rejected should harden preexisting .isolated");

        assert!(!evil_src.exists());
        assert_eq!(isolated_dest, isolated_dir.join("preexisting_isolated.exe"));
        assert_eq!(
            std::fs::metadata(&isolated_dir)
                .expect("isolated dir metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&isolated_dest)
                .expect("isolated file metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn cross_device_exdev_fallback_copies_in_64kb_chunks_with_exact_permissions() {
        let root = tempdir().expect("tempdir");
        let src_dir = root.path().join("src");
        let dst_dir = root.path().join("dst");
        std::fs::create_dir_all(&src_dir).expect("create src_dir");
        std::fs::create_dir_all(&dst_dir).expect("create dst_dir");

        let total_len = STREAM_CHUNK_SIZE * 3 + 777;
        let payload: Vec<u8> = (0..total_len)
            .map(|i| ((i.wrapping_mul(31) ^ (i >> 7)) % 251) as u8)
            .collect();

        let src_path = src_dir.join("large_archive.tar.gz");
        std::fs::write(&src_path, &payload).expect("write large payload");

        // Pre-populate collision file at destination to test collision retry under EXDEV as well.
        std::fs::write(dst_dir.join("large_archive.tar.gz"), b"existing").expect("write collision");

        let validated = validate_source_file(&src_path).expect("validate source");
        let validated_dst = validate_dest_dir(&dst_dir, "dst_dir").expect("validate dst_dir");
        let dest_path = move_validated_file_with_linker(
            &validated,
            &validated_dst,
            MODE_ISOLATED_FILE,
            |_src, _dst| Err(std::io::Error::from_raw_os_error(libc::EXDEV)),
        )
        .expect("EXDEV streaming fallback should succeed");

        assert!(
            !src_path.exists(),
            "source must be removed after EXDEV copy"
        );
        assert_ne!(dest_path, dst_dir.join("large_archive.tar.gz"));
        assert_eq!(dest_path.extension().and_then(|e| e.to_str()), Some("gz"));
        assert_eq!(
            std::fs::read(&dest_path).expect("read copied file"),
            payload
        );
        assert_eq!(
            std::fs::metadata(&dest_path)
                .expect("dest meta")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}
