//! Composition root and daemon entrypoint for Sentinel Guard.

use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter = match EnvFilter::try_from_default_env() {
        Ok(env_filter) => env_filter,
        Err(_) => EnvFilter::new("info"),
    };

    tracing_subscriber::fmt().with_env_filter(filter).init();

    tracing::info!("Sentinel Guard daemon initialized");
    Ok(())
}
