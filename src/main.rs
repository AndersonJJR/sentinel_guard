//! Composition root and daemon entrypoint for Sentinel Guard.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::{RwLock, mpsc, watch};
use tracing_subscriber::EnvFilter;

use sentinel_guard::application::inspect_file::InspectFileUseCase;
use sentinel_guard::application::update_config::UpdateConfigUseCase;
use sentinel_guard::domain::entities::RuntimeConfig;
use sentinel_guard::domain::errors::DomainError;
use sentinel_guard::domain::path_policy::ensure_distinct_non_nested_dirs;
use sentinel_guard::domain::ports::{ConfigStore, FileScanner};
use sentinel_guard::infrastructure::config_env::BootstrapConfig;
use sentinel_guard::infrastructure::fs_watcher::{
    FsQuarantineMover, InotifyWatcher, validate_real_directory,
};
use sentinel_guard::infrastructure::magic_bytes::{MagicBytesInspector, StreamingHasher};
use sentinel_guard::infrastructure::sqlite_repo::SqliteStore;

const WATCHER_EVENT_CHANNEL_CAPACITY: usize = 256;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing()?;

    let bootstrap = BootstrapConfig::from_env()?;
    let store = Arc::new(SqliteStore::connect_and_migrate(&bootstrap.database_url).await?);

    let default_runtime_config = bootstrap.to_default_runtime_config();
    let mut initial_config = store.load_or_seed(&default_runtime_config).await?;

    let (dir_tx, dir_rx) = watch::channel(initial_config.quarantine_dir.clone());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (event_tx, mut event_rx) = mpsc::channel::<PathBuf>(WATCHER_EVENT_CHANNEL_CAPACITY);

    let watcher =
        validate_startup_config_and_watcher(&mut initial_config, dir_rx, event_tx).await?;

    let runtime_config = Arc::new(RwLock::new(initial_config));

    let hasher = Arc::new(StreamingHasher::new());
    let magic_inspector = Arc::new(MagicBytesInspector::new());
    let scanners: Vec<Arc<dyn FileScanner>> = vec![magic_inspector.clone()];
    let quarantine_mover = Arc::new(FsQuarantineMover::new());

    let inspect_use_case = Arc::new(InspectFileUseCase::new(
        hasher,
        magic_inspector,
        scanners,
        quarantine_mover,
        store.clone(),
        runtime_config.clone(),
    ));

    let _update_config_use_case = Arc::new(UpdateConfigUseCase::new(
        store,
        runtime_config.clone(),
        dir_tx,
    ));

    {
        let cfg = runtime_config.read().await;
        tracing::info!(
            app_env = %bootstrap.app_env,
            bind_address = %bootstrap.bind_address,
            quarantine_dir = %cfg.quarantine_dir.display(),
            approved_dir = %cfg.approved_dir.display(),
            "Sentinel Guard daemon initialized"
        );
    }

    let mut watcher_handle = tokio::spawn(async move { watcher.run(shutdown_rx).await });

    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    let mut watcher_result: Option<Result<Result<(), DomainError>, tokio::task::JoinError>> = None;

    loop {
        tokio::select! {
            signal_result = &mut ctrl_c => {
                match signal_result {
                    Ok(()) => tracing::info!("Received Ctrl+C signal; initiating graceful shutdown"),
                    Err(err) => tracing::error!(error = %err, "Failed listening for Ctrl+C; initiating shutdown"),
                }
                let _ = shutdown_tx.send(true);
                event_rx.close();
                break;
            }
            join_result = &mut watcher_handle => {
                watcher_result = Some(join_result);
                tracing::warn!("Filesystem watcher task exited; stopping daemon event loop");
                event_rx.close();
                break;
            }
            maybe_path = event_rx.recv() => {
                let Some(path) = maybe_path else {
                    tracing::info!("Watcher event channel closed; stopping daemon event loop");
                    let _ = shutdown_tx.send(true);
                    break;
                };

                process_watcher_event(&path, &runtime_config, &inspect_use_case).await;
            }
        }
    }

    let final_watcher_result = match watcher_result {
        Some(res) => res,
        None => watcher_handle.await,
    };

    match final_watcher_result {
        Ok(Ok(())) => {
            tracing::info!("Sentinel Guard daemon shut down gracefully");
            Ok(())
        }
        Ok(Err(err)) => {
            tracing::error!(error = %err, "Filesystem watcher terminated with domain error");
            Err(err.into())
        }
        Err(join_err) => {
            tracing::error!(error = %join_err, "Filesystem watcher task panicked or was cancelled");
            Err(anyhow::anyhow!(
                "Filesystem watcher task failed: {join_err}"
            ))
        }
    }
}

fn init_tracing() -> anyhow::Result<()> {
    let filter = match EnvFilter::try_from_default_env() {
        Ok(env_filter) => env_filter,
        Err(_) => EnvFilter::new("info"),
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .try_init()
        .map_err(|err| anyhow::anyhow!("Failed to initialize tracing subscriber: {err}"))?;

    Ok(())
}

async fn process_watcher_event(
    path: &Path,
    runtime_config: &RwLock<RuntimeConfig>,
    inspect_use_case: &InspectFileUseCase,
) {
    let current_quarantine_dir = {
        let guard = runtime_config.read().await;
        guard.quarantine_dir.clone()
    };

    if path.parent() != Some(current_quarantine_dir.as_path()) {
        tracing::debug!(
            path = %path.display(),
            quarantine_dir = %current_quarantine_dir.display(),
            "Ignoring filesystem event outside active quarantine directory"
        );
        return;
    }

    match inspect_use_case.execute(path).await {
        Ok(report) => {
            tracing::info!(
                report_id = report.id,
                file_name = %report.artifact.sanitized_name,
                size_bytes = report.artifact.size_bytes,
                verdict = ?report.verdict,
                destination = ?report.destination_path,
                "Inspection pipeline finished for file"
            );
        }
        Err(err) => {
            tracing::error!(
                path = %path.display(),
                error = %err,
                "File inspection failed; continuing daemon loop"
            );
        }
    }
}

async fn validate_startup_config_and_watcher(
    initial_config: &mut RuntimeConfig,
    dir_rx: watch::Receiver<PathBuf>,
    event_tx: mpsc::Sender<PathBuf>,
) -> Result<InotifyWatcher, DomainError> {
    let raw_approved_dir = initial_config.approved_dir.clone();
    let canonical_approved_dir = tokio::task::spawn_blocking(move || {
        validate_real_directory(&raw_approved_dir, "approved_dir")
    })
    .await
    .map_err(|err| {
        DomainError::ConfigError(format!(
            "Startup approved_dir validation task failed: {err}"
        ))
    })??;
    initial_config.approved_dir = canonical_approved_dir;

    let watcher = InotifyWatcher::new(initial_config.quarantine_dir.clone(), dir_rx, event_tx)?;
    initial_config.quarantine_dir = watcher.current_dir().to_path_buf();

    ensure_distinct_non_nested_dirs(&initial_config.quarantine_dir, &initial_config.approved_dir)?;

    Ok(watcher)
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use tempfile::tempdir;

    use super::*;

    fn sample_config(quarantine_dir: PathBuf, approved_dir: PathBuf) -> RuntimeConfig {
        RuntimeConfig {
            quarantine_dir,
            approved_dir,
            clamd_socket_path: PathBuf::from("/var/run/clamav/clamd.ctl"),
            suricata_eve_path: PathBuf::from("/var/log/suricata/eve.json"),
            updated_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn startup_validation_canonicalizes_valid_dirs_and_fails_fast_on_invalid_approved_dir() {
        let root = tempdir().expect("tempdir");
        let q_dir = root.path().join("quarantine");
        let a_dir = root.path().join("approved");
        let nested_in_q = q_dir.join("nested_approved");
        let nested_in_a = a_dir.join("nested_quarantine");
        let regular_file = root.path().join("not_a_dir.txt");

        std::fs::create_dir_all(&nested_in_q).expect("create nested_in_q");
        std::fs::create_dir_all(&nested_in_a).expect("create nested_in_a");
        std::fs::write(&regular_file, b"hello").expect("write regular file");

        let approved_symlink = root.path().join("approved_symlink");
        std::os::unix::fs::symlink(&a_dir, &approved_symlink).expect("symlink approved");

        let etc_symlink = root.path().join("etc_symlink");
        std::os::unix::fs::symlink("/etc", &etc_symlink).expect("symlink /etc");

        // 1. Valid distinct directories succeed and canonicalize (including trailing slash).
        let mut valid_cfg = sample_config(
            q_dir.clone(),
            PathBuf::from(format!("{}/", a_dir.display())),
        );
        let (_dir_tx, dir_rx) = watch::channel(valid_cfg.quarantine_dir.clone());
        let (event_tx, _event_rx) = mpsc::channel(8);
        let watcher = validate_startup_config_and_watcher(&mut valid_cfg, dir_rx, event_tx)
            .await
            .expect("valid startup dirs should succeed");
        assert_eq!(
            valid_cfg.quarantine_dir,
            std::fs::canonicalize(&q_dir).expect("canonical q_dir")
        );
        assert_eq!(
            valid_cfg.approved_dir,
            std::fs::canonicalize(&a_dir).expect("canonical a_dir")
        );
        drop(watcher);

        // 2. Missing approved_dir fails fast.
        let mut missing_cfg = sample_config(q_dir.clone(), root.path().join("missing_approved"));
        let (_dir_tx, dir_rx) = watch::channel(missing_cfg.quarantine_dir.clone());
        let (event_tx, _event_rx) = mpsc::channel(8);
        let err = validate_startup_config_and_watcher(&mut missing_cfg, dir_rx, event_tx)
            .await
            .err()
            .expect("missing approved_dir must fail fast");
        assert!(matches!(err, DomainError::InvalidPath(_)));

        // 3. Regular file as approved_dir fails fast.
        let mut file_cfg = sample_config(q_dir.clone(), regular_file);
        let (_dir_tx, dir_rx) = watch::channel(file_cfg.quarantine_dir.clone());
        let (event_tx, _event_rx) = mpsc::channel(8);
        let err = validate_startup_config_and_watcher(&mut file_cfg, dir_rx, event_tx)
            .await
            .err()
            .expect("regular file approved_dir must fail fast");
        assert!(matches!(err, DomainError::InvalidPath(_)));

        // 4. Leaf symlinks (to approved or /etc) as approved_dir fail fast.
        for sym_path in [approved_symlink, etc_symlink] {
            let mut sym_cfg = sample_config(q_dir.clone(), sym_path);
            let (_dir_tx, dir_rx) = watch::channel(sym_cfg.quarantine_dir.clone());
            let (event_tx, _event_rx) = mpsc::channel(8);
            let err = validate_startup_config_and_watcher(&mut sym_cfg, dir_rx, event_tx)
                .await
                .err()
                .expect("leaf symlink approved_dir must fail fast");
            assert!(matches!(err, DomainError::PathTraversalAttempt(_)));
        }

        // 5. Forbidden system directories fail fast.
        for forbidden in [PathBuf::from("/"), PathBuf::from("/etc")] {
            let mut sys_cfg = sample_config(q_dir.clone(), forbidden);
            let (_dir_tx, dir_rx) = watch::channel(sys_cfg.quarantine_dir.clone());
            let (event_tx, _event_rx) = mpsc::channel(8);
            let err = validate_startup_config_and_watcher(&mut sys_cfg, dir_rx, event_tx)
                .await
                .err()
                .expect("forbidden approved_dir must fail fast");
            assert!(matches!(err, DomainError::ForbiddenSystemDirectory(_)));
        }

        // 6. Equal or nested quarantine_dir and approved_dir fail fast.
        for (q, a) in [
            (q_dir.clone(), q_dir.clone()),
            (q_dir.clone(), nested_in_q),
            (nested_in_a, a_dir),
        ] {
            let mut overlap_cfg = sample_config(q, a);
            let (_dir_tx, dir_rx) = watch::channel(overlap_cfg.quarantine_dir.clone());
            let (event_tx, _event_rx) = mpsc::channel(8);
            let err = validate_startup_config_and_watcher(&mut overlap_cfg, dir_rx, event_tx)
                .await
                .err()
                .expect("equal or nested dirs must fail fast");
            assert!(matches!(err, DomainError::InvalidPath(_)));
        }
    }
}
