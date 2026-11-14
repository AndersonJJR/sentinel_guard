//! Environment-based bootstrap configuration loader with secret redaction.

use std::path::PathBuf;

use chrono::Utc;
use secrecy::SecretString;

use crate::domain::entities::RuntimeConfig;
use crate::domain::errors::DomainError;

/// Layer 1 bootstrap configuration loaded strictly from environment variables / `.env`.
#[derive(Debug, Clone)]
pub struct BootstrapConfig {
    /// Execution environment identifier (e.g. `production`, `development`).
    pub app_env: String,
    /// Socket address where the HTTP admin/SSE server binds.
    pub bind_address: String,
    /// Bearer token protecting administrative API endpoints (redacted in `Debug`).
    pub admin_api_token: SecretString,
    /// SQLite connection string (e.g. `sqlite://sentinel.db?mode=rwc`).
    pub database_url: String,
    /// Initial directory monitored for quarantined incoming files.
    pub default_quarantine_dir: PathBuf,
    /// Initial directory where verified clean files are moved.
    pub default_approved_dir: PathBuf,
    /// Default Unix socket path for `clamd`.
    pub clamd_socket_path: PathBuf,
    /// Default path to Suricata `eve.json` alert telemetry.
    pub suricata_eve_path: PathBuf,
}

impl BootstrapConfig {
    /// Loads `.env` (if present) and parses required environment variables.
    pub fn from_env() -> Result<Self, DomainError> {
        let _ = dotenvy::dotenv();
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// Parses bootstrap configuration using an arbitrary key lookup closure.
    ///
    /// This enables deterministic unit testing without mutating process-global environment variables.
    pub fn from_lookup<F>(lookup: F) -> Result<Self, DomainError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let app_env = require_non_empty(&lookup, "APP_ENV")?;
        let bind_address = require_non_empty(&lookup, "BIND_ADDRESS")?;
        let raw_token = require_non_empty(&lookup, "ADMIN_API_TOKEN")?;
        let database_url = require_non_empty(&lookup, "DATABASE_URL")?;
        let default_quarantine_dir =
            PathBuf::from(require_non_empty(&lookup, "DEFAULT_QUARANTINE_DIR")?);
        let default_approved_dir =
            PathBuf::from(require_non_empty(&lookup, "DEFAULT_APPROVED_DIR")?);
        let clamd_socket_path = PathBuf::from(require_non_empty(&lookup, "CLAMD_SOCKET_PATH")?);
        let suricata_eve_path = PathBuf::from(require_non_empty(&lookup, "SURICATA_EVE_PATH")?);

        Ok(Self {
            app_env,
            bind_address,
            admin_api_token: SecretString::from(raw_token),
            database_url,
            default_quarantine_dir,
            default_approved_dir,
            clamd_socket_path,
            suricata_eve_path,
        })
    }

    /// Converts bootstrap default paths into an initial [`RuntimeConfig`] seed.
    pub fn to_default_runtime_config(&self) -> RuntimeConfig {
        RuntimeConfig {
            quarantine_dir: self.default_quarantine_dir.clone(),
            approved_dir: self.default_approved_dir.clone(),
            clamd_socket_path: self.clamd_socket_path.clone(),
            suricata_eve_path: self.suricata_eve_path.clone(),
            updated_at: Utc::now(),
        }
    }
}

fn require_non_empty<F>(lookup: &F, key: &str) -> Result<String, DomainError>
where
    F: Fn(&str) -> Option<String>,
{
    match lookup(key) {
        Some(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                Err(DomainError::ConfigError(format!(
                    "Environment variable '{key}' must not be empty"
                )))
            } else {
                Ok(trimmed.to_owned())
            }
        }
        None => Err(DomainError::ConfigError(format!(
            "Missing required environment variable '{key}'"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use secrecy::ExposeSecret;

    use super::*;

    fn valid_env_map() -> HashMap<&'static str, &'static str> {
        HashMap::from([
            ("APP_ENV", "production"),
            ("BIND_ADDRESS", "127.0.0.1:8080"),
            (
                "ADMIN_API_TOKEN",
                "super_secret_64_char_token_value_1234567890",
            ),
            ("DATABASE_URL", "sqlite::memory:"),
            ("DEFAULT_QUARANTINE_DIR", "/var/lib/sentinel/quarantine"),
            ("DEFAULT_APPROVED_DIR", "/var/lib/sentinel/approved"),
            ("CLAMD_SOCKET_PATH", "/var/run/clamav/clamd.ctl"),
            ("SURICATA_EVE_PATH", "/var/log/suricata/eve.json"),
        ])
    }

    fn load_from_map(
        map: &HashMap<&'static str, &'static str>,
    ) -> Result<BootstrapConfig, DomainError> {
        BootstrapConfig::from_lookup(|k| map.get(k).map(|v| (*v).to_string()))
    }

    #[test]
    fn from_lookup_loads_valid_config_and_redacts_secret_in_debug() {
        let vars = valid_env_map();
        let cfg = load_from_map(&vars).expect("valid configuration should load");

        assert_eq!(cfg.app_env, "production");
        assert_eq!(cfg.bind_address, "127.0.0.1:8080");
        assert_eq!(
            cfg.admin_api_token.expose_secret(),
            "super_secret_64_char_token_value_1234567890"
        );
        assert_eq!(cfg.database_url, "sqlite::memory:");
        assert_eq!(
            cfg.default_quarantine_dir,
            PathBuf::from("/var/lib/sentinel/quarantine")
        );
        assert_eq!(
            cfg.default_approved_dir,
            PathBuf::from("/var/lib/sentinel/approved")
        );
        assert_eq!(
            cfg.clamd_socket_path,
            PathBuf::from("/var/run/clamav/clamd.ctl")
        );
        assert_eq!(
            cfg.suricata_eve_path,
            PathBuf::from("/var/log/suricata/eve.json")
        );

        let debug_repr = format!("{cfg:?}");
        let pretty_debug_repr = format!("{cfg:#?}");
        assert!(
            !debug_repr.contains("super_secret_64_char_token_value_1234567890"),
            "Debug output must redact admin_api_token"
        );
        assert!(
            !pretty_debug_repr.contains("super_secret_64_char_token_value_1234567890"),
            "Pretty debug output must redact admin_api_token"
        );
        assert!(
            debug_repr.contains("SecretBox"),
            "Debug output should use secrecy's redacted wrapper: {debug_repr}"
        );
    }

    #[test]
    fn from_lookup_trims_surrounding_whitespace() {
        let mut vars = valid_env_map();
        vars.insert("APP_ENV", "  staging  ");
        vars.insert("ADMIN_API_TOKEN", "  trimmed_token_abc123  ");
        vars.insert("DEFAULT_QUARANTINE_DIR", "\t/tmp/q\n");

        let cfg = load_from_map(&vars).expect("trimmed values should load");
        assert_eq!(cfg.app_env, "staging");
        assert_eq!(cfg.admin_api_token.expose_secret(), "trimmed_token_abc123");
        assert_eq!(cfg.default_quarantine_dir, PathBuf::from("/tmp/q"));
    }

    #[test]
    fn from_lookup_rejects_missing_empty_and_whitespace_admin_api_token() {
        let mut missing = valid_env_map();
        missing.remove("ADMIN_API_TOKEN");
        let err = load_from_map(&missing).expect_err("missing ADMIN_API_TOKEN must fail");
        assert!(
            matches!(err, DomainError::ConfigError(ref msg) if msg.contains("ADMIN_API_TOKEN")),
            "expected ConfigError referencing ADMIN_API_TOKEN, got {err:?}"
        );

        for blank_value in ["", "   ", "\t\r\n"] {
            let mut blank = valid_env_map();
            blank.insert("ADMIN_API_TOKEN", blank_value);
            let err = load_from_map(&blank).expect_err("empty ADMIN_API_TOKEN must fail");
            assert!(
                matches!(err, DomainError::ConfigError(ref msg) if msg.contains("ADMIN_API_TOKEN")),
                "expected ConfigError referencing ADMIN_API_TOKEN for {blank_value:?}, got {err:?}"
            );
        }
    }

    #[test]
    fn from_lookup_rejects_missing_and_empty_for_all_required_keys() {
        let required_keys = [
            "APP_ENV",
            "BIND_ADDRESS",
            "ADMIN_API_TOKEN",
            "DATABASE_URL",
            "DEFAULT_QUARANTINE_DIR",
            "DEFAULT_APPROVED_DIR",
            "CLAMD_SOCKET_PATH",
            "SURICATA_EVE_PATH",
        ];

        for key in required_keys {
            let mut missing = valid_env_map();
            missing.remove(key);
            let missing_err = load_from_map(&missing).expect_err("missing required key must fail");
            assert!(
                matches!(missing_err, DomainError::ConfigError(ref msg) if msg.contains(key)),
                "expected ConfigError mentioning {key}, got {missing_err:?}"
            );

            let mut empty = valid_env_map();
            empty.insert(key, "   ");
            let empty_err = load_from_map(&empty).expect_err("blank required key must fail");
            assert!(
                matches!(empty_err, DomainError::ConfigError(ref msg) if msg.contains(key)),
                "expected ConfigError mentioning {key}, got {empty_err:?}"
            );
        }
    }

    #[test]
    fn to_default_runtime_config_maps_all_paths() {
        let vars = valid_env_map();
        let before = Utc::now();
        let cfg = load_from_map(&vars).expect("valid configuration should load");
        let runtime = cfg.to_default_runtime_config();
        let after = Utc::now();

        assert_eq!(runtime.quarantine_dir, cfg.default_quarantine_dir);
        assert_eq!(runtime.approved_dir, cfg.default_approved_dir);
        assert_eq!(runtime.clamd_socket_path, cfg.clamd_socket_path);
        assert_eq!(runtime.suricata_eve_path, cfg.suricata_eve_path);
        assert!(runtime.updated_at >= before && runtime.updated_at <= after);
    }
}
