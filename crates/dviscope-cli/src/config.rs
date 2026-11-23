//! `CliConfig`: defaults → `<state_dir>/dviscope.toml` → `DVISCOPE_*` environment → flags.
//! Unknown keys are rejected; `doctor` prints the effective values with their source.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Where a setting's value came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Built-in default.
    Default,
    /// The configuration file.
    File,
    /// An environment variable.
    Env,
    /// A command-line flag.
    Flag,
}

impl Source {
    /// Lowercase name for reports.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Default => "default",
            Source::File => "file",
            Source::Env => "env",
            Source::Flag => "flag",
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    server_url: Option<String>,
    ca_file: Option<PathBuf>,
    token_file: Option<PathBuf>,
}

/// Resolved CLI configuration.
#[derive(Debug, Clone)]
pub struct CliConfig {
    /// Server URL (must be `https://`).
    pub server_url: String,
    /// Extra CA certificate (PEM) trusted besides the OS store.
    pub ca_file: Option<PathBuf>,
    /// Private state directory (journals, spool, config).
    pub state_dir: PathBuf,
    /// File holding the API token.
    pub token_file: Option<PathBuf>,
    /// Source of each setting, for `doctor`.
    pub sources: BTreeMap<&'static str, Source>,
}

/// Flags that override configuration.
#[derive(Debug, Default, Clone)]
pub struct Overrides {
    /// `--server`.
    pub server_url: Option<String>,
    /// `--ca-file`.
    pub ca_file: Option<PathBuf>,
    /// `--state-dir`.
    pub state_dir: Option<PathBuf>,
}

/// The platform default state directory, from environment values passed in.
#[must_use]
pub fn default_state_dir(env: &BTreeMap<String, String>) -> PathBuf {
    if cfg!(windows) {
        if let Some(local) = env.get("LOCALAPPDATA") {
            return Path::new(local).join("dviscope");
        }
    } else {
        if let Some(xdg) = env.get("XDG_STATE_HOME").filter(|v| !v.is_empty()) {
            return Path::new(xdg).join("dviscope");
        }
        if let Some(home) = env.get("HOME") {
            return Path::new(home)
                .join(".local")
                .join("state")
                .join("dviscope");
        }
    }
    PathBuf::from(".dviscope")
}

/// Configuration errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The file is invalid.
    #[error("invalid configuration file {0}: {1}")]
    File(PathBuf, String),
    /// An unknown `DVISCOPE_*` variable.
    #[error("unknown setting {0}")]
    UnknownEnv(String),
}

impl CliConfig {
    /// Resolves the configuration.
    ///
    /// # Errors
    /// Invalid file or unknown `DVISCOPE_*` variable.
    pub fn resolve(env: &BTreeMap<String, String>, flags: &Overrides) -> Result<Self, ConfigError> {
        let mut sources = BTreeMap::new();
        let (state_dir, src) = match (&flags.state_dir, env.get("DVISCOPE_STATE_DIR")) {
            (Some(d), _) => (d.clone(), Source::Flag),
            (None, Some(d)) => (PathBuf::from(d), Source::Env),
            _ => (default_state_dir(env), Source::Default),
        };
        sources.insert("state_dir", src);

        let file_path = state_dir.join("dviscope.toml");
        let file: FileConfig = match std::fs::read_to_string(&file_path) {
            Ok(text) => toml::from_str(&text)
                .map_err(|e| ConfigError::File(file_path.clone(), e.to_string()))?,
            Err(_) => FileConfig::default(),
        };

        for key in env.keys().filter(|k| k.starts_with("DVISCOPE_")) {
            if !matches!(
                key.as_str(),
                "DVISCOPE_SERVER_URL"
                    | "DVISCOPE_CA_FILE"
                    | "DVISCOPE_STATE_DIR"
                    | "DVISCOPE_TOKEN_FILE"
                    // Read by the crash-point test harness (inert unless a test arms it).
                    | "DVISCOPE_TEST_CRASH_POINT"
                    // Read by the database tests, never by the client.
                    | "DVISCOPE_TEST_DATABASE_URL"
                    | "DVISCOPE_REQUIRE_TEST_DB"
            ) && !key.starts_with("DVISCOPE_SERVER_")
            {
                return Err(ConfigError::UnknownEnv(key.clone()));
            }
        }

        let mut server_url = "https://127.0.0.1:8443".to_string();
        sources.insert("server_url", Source::Default);
        if let Some(v) = file.server_url {
            server_url = v;
            sources.insert("server_url", Source::File);
        }
        if let Some(v) = env.get("DVISCOPE_SERVER_URL") {
            server_url.clone_from(v);
            sources.insert("server_url", Source::Env);
        }
        if let Some(v) = &flags.server_url {
            server_url.clone_from(v);
            sources.insert("server_url", Source::Flag);
        }

        let mut ca_file = None;
        sources.insert("ca_file", Source::Default);
        if let Some(v) = file.ca_file {
            ca_file = Some(v);
            sources.insert("ca_file", Source::File);
        }
        if let Some(v) = env.get("DVISCOPE_CA_FILE") {
            ca_file = Some(PathBuf::from(v));
            sources.insert("ca_file", Source::Env);
        }
        if let Some(v) = &flags.ca_file {
            ca_file = Some(v.clone());
            sources.insert("ca_file", Source::Flag);
        }

        let mut token_file = None;
        sources.insert("token_file", Source::Default);
        if let Some(v) = file.token_file {
            token_file = Some(v);
            sources.insert("token_file", Source::File);
        }
        if let Some(v) = env.get("DVISCOPE_TOKEN_FILE") {
            token_file = Some(PathBuf::from(v));
            sources.insert("token_file", Source::Env);
        }

        Ok(Self {
            server_url,
            ca_file,
            state_dir,
            token_file,
            sources,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precedence_default_env_flag() {
        let mut env = BTreeMap::new();
        env.insert(
            "DVISCOPE_STATE_DIR".to_string(),
            "/nonexistent/dviscope-test".to_string(),
        );
        let c = CliConfig::resolve(&env, &Overrides::default()).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(c.server_url, "https://127.0.0.1:8443");
        assert_eq!(c.sources["server_url"], Source::Default);
        env.insert(
            "DVISCOPE_SERVER_URL".to_string(),
            "https://env:1".to_string(),
        );
        let c = CliConfig::resolve(&env, &Overrides::default()).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(c.sources["server_url"], Source::Env);
        let flags = Overrides {
            server_url: Some("https://flag:1".into()),
            ..Overrides::default()
        };
        let c = CliConfig::resolve(&env, &flags).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(c.server_url, "https://flag:1");
        assert_eq!(c.sources["server_url"], Source::Flag);
    }

    #[test]
    fn unknown_env_rejected() {
        let mut env = BTreeMap::new();
        env.insert(
            "DVISCOPE_STATE_DIR".to_string(),
            "/nonexistent/dviscope-test".to_string(),
        );
        env.insert("DVISCOPE_SURPRISE".to_string(), "1".to_string());
        assert!(matches!(
            CliConfig::resolve(&env, &Overrides::default()),
            Err(ConfigError::UnknownEnv(_))
        ));
    }
}
