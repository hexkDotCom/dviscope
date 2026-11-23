//! `ServerConfig`: resolved once at startup (defaults → file → environment), unknown keys
//! rejected, validated by the same code `doctor` uses.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// TLS files of the server.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// PEM certificate chain (leaf first).
    pub cert_file: PathBuf,
    /// PEM private key of the leaf.
    pub key_file: PathBuf,
}

/// Database settings. The URL (with its password) is never in the file itself: it comes
/// from `DVISCOPE_SERVER_DATABASE_URL` or from the file named by `url_file`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    /// File holding the database URL (one line).
    #[serde(default)]
    pub url_file: Option<PathBuf>,
    /// Pool size.
    #[serde(default = "default_pool")]
    pub pool_size: u32,
    /// Statement timeout, milliseconds.
    #[serde(default = "default_statement_timeout")]
    pub statement_timeout_ms: u64,
}

fn default_pool() -> u32 {
    16
}

fn default_statement_timeout() -> u64 {
    30_000
}

impl DatabaseConfig {
    /// The database URL: the environment first, then the URL file.
    ///
    /// # Errors
    /// Neither is set, or the file cannot be read.
    pub fn url(&self, env: &[(String, String)]) -> Result<String, ConfigError> {
        if let Some((_, v)) = env
            .iter()
            .find(|(k, _)| k == "DVISCOPE_SERVER_DATABASE_URL")
        {
            return Ok(v.trim().to_string());
        }
        let f = self.url_file.as_ref().ok_or_else(|| {
            ConfigError::Invalid(
                "database: set DVISCOPE_SERVER_DATABASE_URL or database.url_file".into(),
            )
        })?;
        std::fs::read_to_string(f)
            .map(|s| s.trim().to_string())
            .map_err(|source| ConfigError::Read {
                path: f.clone(),
                source,
            })
    }
}

/// Server configuration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Listen address inside the container or host.
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// Canonical origin users and clients reach.
    #[serde(default = "default_origin")]
    pub public_origin: String,
    /// TLS files.
    pub tls: TlsConfig,
    /// Database (absent: health and capabilities only).
    #[serde(default)]
    pub database: Option<DatabaseConfig>,
    /// Directory of the built web UI (`web/dist`); absent: no UI is served.
    #[serde(default)]
    pub ui_dir: Option<PathBuf>,
    /// Seconds a request body may take to arrive (default 60): a client that declares a
    /// body and withholds it never holds its share of the request budget longer.
    #[serde(default = "default_body_timeout")]
    pub request_body_timeout_s: u64,
}

fn default_body_timeout() -> u64 {
    60
}

fn default_listen() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 8443))
}

fn default_origin() -> String {
    "https://127.0.0.1:8443".to_string()
}

/// Configuration errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The file could not be read.
    #[error("cannot read {path}: {source}")]
    Read {
        /// File.
        path: PathBuf,
        /// Cause.
        source: std::io::Error,
    },
    /// The file is not valid configuration.
    #[error("invalid configuration in {path}: {message}")]
    Parse {
        /// File.
        path: PathBuf,
        /// Cause.
        message: String,
    },
    /// A value is not acceptable.
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

impl ServerConfig {
    /// Loads a TOML file and applies `DVISCOPE_SERVER_*` overrides from `env`.
    ///
    /// # Errors
    /// Unreadable or invalid file, unknown keys, invalid values.
    pub fn load(path: &Path, env: &[(String, String)]) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let mut cfg: ServerConfig = toml::from_str(&text).map_err(|e| ConfigError::Parse {
            path: path.to_path_buf(),
            message: e.to_string(),
        })?;
        for (k, v) in env {
            match k.as_str() {
                "DVISCOPE_SERVER_LISTEN" => {
                    cfg.listen = v
                        .parse()
                        .map_err(|_| ConfigError::Invalid(format!("{k}={v} is not an address")))?;
                }
                "DVISCOPE_SERVER_PUBLIC_ORIGIN" => cfg.public_origin.clone_from(v),
                "DVISCOPE_SERVER_TLS_CERT_FILE" => cfg.tls.cert_file = PathBuf::from(v),
                "DVISCOPE_SERVER_TLS_KEY_FILE" => cfg.tls.key_file = PathBuf::from(v),
                "DVISCOPE_SERVER_UI_DIR" => cfg.ui_dir = Some(PathBuf::from(v)),
                // Selects the file itself (read by the binary's argument parser), and the
                // database URL (read by `DatabaseConfig::url`).
                "DVISCOPE_SERVER_CONFIG" | "DVISCOPE_SERVER_DATABASE_URL" => {}
                _ if k.starts_with("DVISCOPE_SERVER_") => {
                    return Err(ConfigError::Invalid(format!("unknown setting {k}")));
                }
                _ => {}
            }
        }
        cfg.validate()?;
        Ok(cfg)
    }

    /// Checks values that the type system does not.
    ///
    /// # Errors
    /// A non-HTTPS origin.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.public_origin.starts_with("https://") {
            return Err(ConfigError::Invalid(format!(
                "public_origin must be https:// ({})",
                self.public_origin
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_keys_and_http_origin() {
        let bad: Result<ServerConfig, _> =
            toml::from_str("listen='0.0.0.0:1'\nsurprise=1\n[tls]\ncert_file='a'\nkey_file='b'\n");
        assert!(bad.is_err());
        let cfg: ServerConfig =
            toml::from_str("public_origin='http://x'\n[tls]\ncert_file='a'\nkey_file='b'\n")
                .unwrap_or_else(|e| panic!("{e}"));
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn ui_dir_from_file_or_environment() {
        let cfg: ServerConfig = toml::from_str(
            "ui_dir='/srv/ui'
[tls]
cert_file='a'
key_file='b'
",
        )
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(cfg.ui_dir, Some(PathBuf::from("/srv/ui")));
        let d = std::env::temp_dir().join(format!("dvs-cfg-{}", std::process::id()));
        std::fs::write(
            &d,
            "[tls]
cert_file='a'
key_file='b'
",
        )
        .unwrap_or_else(|e| panic!("{e}"));
        let env = [("DVISCOPE_SERVER_UI_DIR".to_string(), "/opt/ui".to_string())];
        let cfg = ServerConfig::load(&d, &env).unwrap_or_else(|e| panic!("{e}"));
        std::fs::remove_file(&d).ok();
        assert_eq!(cfg.ui_dir, Some(PathBuf::from("/opt/ui")));
    }
}
