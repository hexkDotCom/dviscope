//! Web UI hosting: the built single-page app served from the configured `ui_dir`.
//!
//! Only `GET` and `HEAD` are served. A path names a file under `ui_dir` (never outside it:
//! no `.`/`..` segments, no backslashes or drive prefixes, and the canonical file must
//! stay under the canonical directory, so symbolic links cannot escape). A path without
//! a file extension that names no file is an app route and gets `index.html`; `/api/…`
//! paths are never answered with the app. Fingerprinted `/assets/…` files are cached as
//! immutable; everything else is revalidated.

use std::path::{Path, PathBuf};

use axum::body::Body;
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};

/// The content type of a UI file, by extension.
#[must_use]
pub fn content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()).unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" | "map" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// The relative file a request path names, or `None` when the path is not acceptable.
/// `/` names `index.html`.
#[must_use]
pub fn relative(path: &str) -> Option<PathBuf> {
    let p = path.strip_prefix('/')?;
    if p.is_empty() {
        return Some(PathBuf::from("index.html"));
    }
    let mut out = PathBuf::new();
    for seg in p.split('/') {
        if seg.is_empty()
            || seg == "."
            || seg == ".."
            || seg.contains(['\\', ':', '\0'])
            || seg.starts_with('.')
        {
            return None;
        }
        out.push(seg);
    }
    Some(out)
}

fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "not found").into_response()
}

async fn file(root: &Path, rel: &Path) -> Option<(PathBuf, Vec<u8>)> {
    let canon_root = tokio::fs::canonicalize(root).await.ok()?;
    let canon = tokio::fs::canonicalize(root.join(rel)).await.ok()?;
    if !canon.starts_with(&canon_root) || !tokio::fs::metadata(&canon).await.ok()?.is_file() {
        return None;
    }
    let bytes = tokio::fs::read(&canon).await.ok()?;
    Some((canon, bytes))
}

/// Serves the UI (the router's fallback when `ui_dir` is configured).
pub async fn serve(root: PathBuf, method: Method, uri: axum::http::Uri) -> Response {
    if method != Method::GET && method != Method::HEAD {
        return (StatusCode::METHOD_NOT_ALLOWED, "method not allowed").into_response();
    }
    let path = uri.path();
    if path == "/api" || path.starts_with("/api/") {
        return not_found();
    }
    let Some(rel) = relative(path) else {
        return not_found();
    };
    let found = match file(&root, &rel).await {
        Some(f) => Some(f),
        // An app route (no extension): the app itself.
        None if rel.extension().is_none() => file(&root, Path::new("index.html")).await,
        None => None,
    };
    let Some((served, bytes)) = found else {
        return not_found();
    };
    let immutable = path.starts_with("/assets/");
    let len = bytes.len();
    let body = if method == Method::HEAD {
        Body::empty()
    } else {
        Body::from(bytes)
    };
    let mut res = Response::new(body);
    let h = res.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(content_type(&served)),
    );
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(if immutable {
            "public, max-age=31536000, immutable"
        } else {
            "no-cache"
        }),
    );
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_paths_stay_inside() {
        assert_eq!(relative("/"), Some(PathBuf::from("index.html")));
        assert_eq!(
            relative("/assets/index-1.js"),
            Some(PathBuf::from("assets").join("index-1.js"))
        );
        for bad in [
            "/../x", "/a/../b", "/./a", "/a//b", "/a\\b", "/c:/x", "/.env", "/a/", "x", "/a\0b",
        ] {
            assert_eq!(relative(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn content_types() {
        assert_eq!(
            content_type(Path::new("a.js")),
            "text/javascript; charset=utf-8"
        );
        assert_eq!(
            content_type(Path::new("index.html")),
            "text/html; charset=utf-8"
        );
        assert_eq!(content_type(Path::new("x.bin")), "application/octet-stream");
    }
}
