//! HTTP transport: `/healthz`, `/readyz`, `/api/v1/capabilities`, and the
//! security headers every response carries.

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::http::{HeaderName, HeaderValue, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use dviscope_model::{limits, schema};
use serde::Serialize;

use crate::config::ServerConfig;

/// Capabilities response.
#[derive(Debug, Serialize)]
pub struct Capabilities {
    /// Server version.
    pub version: &'static str,
    /// Accepted schema identifiers.
    pub schemas: &'static [&'static str],
    /// Published limits.
    pub limits: Limits,
    /// Feature flags.
    pub features: Vec<&'static str>,
}

/// Published limits.
#[derive(Debug, Serialize)]
pub struct Limits {
    /// Encoded request bytes.
    pub max_encoded_request_bytes: usize,
    /// Decoded request bytes.
    pub max_decoded_request_bytes: usize,
    /// Decompression ratio.
    pub max_compression_ratio: usize,
    /// Records per batch.
    pub max_records_per_batch: usize,
    /// Bytes per record.
    pub max_record_bytes: usize,
}

async fn healthz() -> &'static str {
    "ok"
}

async fn readyz(
    axum::extract::State(app): axum::extract::State<Option<crate::app::App>>,
) -> Response {
    match app {
        // Ready only when the database answers and its schema is this binary's.
        Some(a) if !crate::db::schema_ready(&a.db).await.unwrap_or(false) => (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "database not ready",
        )
            .into_response(),
        Some(a) if crate::backup::maintenance_on(&a.db).await.unwrap_or(false) => {
            (axum::http::StatusCode::SERVICE_UNAVAILABLE, "maintenance").into_response()
        }
        _ => "ready".into_response(),
    }
}

async fn capabilities() -> Json<Capabilities> {
    Json(Capabilities {
        version: env!("CARGO_PKG_VERSION"),
        schemas: schema::ALL,
        limits: Limits {
            max_encoded_request_bytes: limits::MAX_ENCODED_REQUEST_BYTES,
            max_decoded_request_bytes: limits::MAX_DECODED_REQUEST_BYTES,
            max_compression_ratio: limits::MAX_COMPRESSION_RATIO,
            max_records_per_batch: limits::MAX_RECORDS_PER_BATCH,
            max_record_bytes: limits::MAX_RECORD_BYTES,
        },
        features: vec![],
    })
}

/// Security headers, added to every response.
async fn security_headers(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let mut res = next.run(req).await.into_response();
    let h = res.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'",
        ),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000"),
    );
    h.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    res
}

/// The router without a database: health, readiness and capabilities (public by design).
pub fn router(cfg: Arc<ServerConfig>) -> Router {
    router_with(cfg, None)
}

/// The full router: the public routes, plus the API of [`crate::http::ROUTES`] when a
/// database is configured.
pub fn router_with(cfg: Arc<ServerConfig>, app: Option<crate::app::App>) -> Router {
    let public = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/api/v1/capabilities", get(capabilities))
        .with_state(app.clone());
    let ui_dir = cfg.ui_dir.clone();
    let r = match app {
        Some(a) => public.merge(crate::http::router(crate::http::ApiState::new(cfg, a))),
        None => public,
    };
    let r = match ui_dir {
        Some(root) => r.fallback(move |method, uri| crate::ui::serve(root.clone(), method, uri)),
        None => r,
    };
    r.layer(axum::middleware::from_fn(security_headers))
}
