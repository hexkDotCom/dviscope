//! HTTP client with the origin rules: `https://` only, refused before any
//! credential is sent; redirects never followed; OS trust store plus an optional CA file.

use std::path::Path;
use std::time::Duration;

use dviscope_model::ErrorCode;

/// Client errors.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The URL is not an acceptable `https://` origin (the URL itself is not echoed: it may
    /// contain credentials).
    #[error("{code}: refusing the server URL: only https://host[:port][/path] is allowed (no user name, password, query or fragment)", code = ErrorCode::InsecureUrl.as_str())]
    InsecureUrl,
    /// The CA file could not be used.
    #[error("cannot use CA file {path}: {message}")]
    CaFile {
        /// File.
        path: String,
        /// Cause.
        message: String,
    },
    /// Building the client failed.
    #[error("cannot build HTTP client: {0}")]
    Build(String),
}

/// Checks the origin rule: an absolute `https://` URL with a host, no user name or
/// password, no query or fragment.
///
/// # Errors
/// [`ClientError::InsecureUrl`] otherwise.
pub fn check_url(url: &str) -> Result<(), ClientError> {
    let bad = || ClientError::InsecureUrl;
    let parsed = reqwest::Url::parse(url).map_err(|_| bad())?;
    let ok = parsed.scheme() == "https"
        && parsed.host_str().is_some_and(|h| !h.is_empty())
        && parsed.username().is_empty()
        && parsed.password().is_none()
        && parsed.query().is_none()
        && parsed.fragment().is_none();
    if ok { Ok(()) } else { Err(bad()) }
}

/// A form of `url` safe to print: scheme, host, port and path only; `<invalid URL>` if it
/// does not parse.
#[must_use]
pub fn redact_url(url: &str) -> String {
    match reqwest::Url::parse(url) {
        // Only hierarchical http(s) URLs with a host are reconstructed; anything else (an
        // opaque `user:password@host`, other schemes) is replaced by a placeholder.
        Ok(u)
            if matches!(u.scheme(), "http" | "https") && u.has_host() && !u.cannot_be_a_base() =>
        {
            let host = u.host_str().unwrap_or("");
            let port = u.port().map(|p| format!(":{p}")).unwrap_or_default();
            format!("{}://{host}{port}{}", u.scheme(), u.path())
        }
        _ => "<invalid URL>".to_string(),
    }
}

/// Builds the client for `server_url`.
///
/// # Errors
/// Insecure URL, unreadable CA file, TLS setup failure.
pub fn build(server_url: &str, ca_file: Option<&Path>) -> Result<reqwest::Client, ClientError> {
    check_url(server_url)?;
    let mut builder = reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(60))
        .user_agent(concat!("dviscope/", env!("CARGO_PKG_VERSION")));
    if let Some(path) = ca_file {
        let pem = std::fs::read(path).map_err(|e| ClientError::CaFile {
            path: path.display().to_string(),
            message: e.to_string(),
        })?;
        let cert = reqwest::Certificate::from_pem(&pem).map_err(|e| ClientError::CaFile {
            path: path.display().to_string(),
            message: e.to_string(),
        })?;
        builder = builder.add_root_certificate(cert);
    }
    builder
        .build()
        .map_err(|e| ClientError::Build(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_rule() {
        assert!(check_url("https://127.0.0.1:8443").is_ok());
        assert!(check_url("HTTPS://host").is_ok());
        assert!(check_url("http://127.0.0.1:8443").is_err());
        assert!(check_url("ftp://x").is_err());
        assert!(check_url("https://").is_err());
        assert!(check_url("aaaaaaa\u{e9}").is_err());
        assert!(check_url("https://user:pw@host").is_err());
        assert!(check_url("https://host/?q=1").is_err());
        let e = check_url("https://user:secret@host")
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(!e.contains("secret"));
        assert_eq!(
            redact_url("https://user:secret@host:8443/x?token=t"),
            "https://host:8443/x"
        );
        assert_eq!(redact_url("not a url"), "<invalid URL>");
        assert_eq!(redact_url("user:password@host"), "<invalid URL>");
    }
}
