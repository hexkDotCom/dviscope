//! The collection and read API (`docs/api.md`): one table of routes, each mapped to an
//! action; credentials extracted once (bearer token or browser session, never both);
//! total-work bounds on every request (encoded and decoded size, decompression ratio, JSON
//! depth, records per batch, bytes in flight); handlers decode and call one application
//! operation.

use std::io::Read as _;
use std::sync::Arc;

use axum::Router;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use dviscope_model::errors::ErrorCode;
use dviscope_model::limits;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use sqlx::Row as _;
use tokio::sync::Semaphore;

use crate::app::ingest::LineResult;
use crate::app::{App, Receipt};
use crate::auth::{self, Action, Actor};
use crate::config::ServerConfig;
use crate::error::AppError;

/// Cookie of a browser session (`__Host-` prefix: secure, host-only, path `/`).
pub const SESSION_COOKIE: &str = "__Host-dviscope";
/// Header carrying the session's CSRF token on state-changing requests.
pub const CSRF_HEADER: &str = "x-dviscope-csrf";
/// Bytes of request bodies being processed at once (beyond it: 503 with `Retry-After`).
pub const MAX_IN_FLIGHT_BYTES: usize = 64 * 1024 * 1024;

/// A login body is small and uncompressed, and reserves from its own budget: unauthenticated
/// clients never reach the budget authenticated requests share.
pub const MAX_LOGIN_BODY_BYTES: usize = 4 * 1024;
/// The budget of login bodies being read.
pub const MAX_LOGIN_IN_FLIGHT_BYTES: usize = 256 * 1024;
/// Password hashes computed at once.
pub const MAX_CONCURRENT_HASHES: usize = 4;
/// Session idle and absolute lifetimes, seconds.
pub const SESSION_IDLE_S: i64 = 8 * 3600;
/// Absolute lifetime.
pub const SESSION_ABSOLUTE_S: i64 = 7 * 24 * 3600;

/// Shared state of the API.
#[derive(Debug, Clone)]
pub struct ApiState {
    /// Configuration.
    pub cfg: Arc<ServerConfig>,
    /// Application operations.
    pub app: App,
    in_flight: Arc<Semaphore>,
    login_in_flight: Arc<Semaphore>,
    hashes: Arc<Semaphore>,
    /// How long a request body may take to arrive (`request_body_timeout_s`).
    body_deadline: std::time::Duration,
}

impl ApiState {
    /// New state over an application.
    #[must_use]
    pub fn new(cfg: Arc<ServerConfig>, app: App) -> Self {
        let body_deadline = std::time::Duration::from_secs(cfg.request_body_timeout_s.max(1));
        Self {
            cfg,
            app,
            body_deadline,
            in_flight: Arc::new(Semaphore::new(MAX_IN_FLIGHT_BYTES)),
            login_in_flight: Arc::new(Semaphore::new(MAX_LOGIN_IN_FLIGHT_BYTES)),
            hashes: Arc::new(Semaphore::new(MAX_CONCURRENT_HASHES)),
        }
    }
}

/// One route of the table: method, path, the action it maps to (`None`: public or session
/// management, authorized inside), and whether it is state-changing.
pub const ROUTES: &[(&str, &str, Option<Action>)] = &[
    (
        "POST",
        "/api/v1/source-manifests",
        Some(Action::SourceManifestCreate),
    ),
    (
        "POST",
        "/api/v1/regressions",
        Some(Action::RegressionCreate),
    ),
    (
        "PUT",
        "/api/v1/regressions/{ref}/manifest/chunks/{n}",
        Some(Action::ManifestChunk),
    ),
    (
        "POST",
        "/api/v1/regressions/{ref}/manifest/seal",
        Some(Action::ManifestSeal),
    ),
    (
        "POST",
        "/api/v1/regressions/{ref}/manifest/amend",
        Some(Action::ManifestAmend),
    ),
    (
        "POST",
        "/api/v1/regressions/{ref}/slots/mark",
        Some(Action::SlotMark),
    ),
    (
        "POST",
        "/api/v1/regressions/{ref}/finish",
        Some(Action::RegressionFinish),
    ),
    ("POST", "/api/v1/ingest", Some(Action::IngestSubmit)),
    ("POST", "/api/v1/reconcile", Some(Action::IngestSubmit)),
    (
        "GET",
        "/api/v1/projects/{project}/regressions/{ref}",
        Some(Action::RegressionRead),
    ),
    (
        "GET",
        "/api/v1/projects/{project}/regressions/{ref}/comparison",
        Some(Action::ComparisonRead),
    ),
    (
        "PUT",
        "/api/v1/projects/{project}/triage/{signature}",
        Some(Action::TriageWrite),
    ),
    (
        "POST",
        "/api/v1/projects/{project}/triage",
        Some(Action::TriageWrite),
    ),
    (
        "POST",
        "/api/v1/projects/{project}/exceptions",
        Some(Action::ExceptionWrite),
    ),
    (
        "DELETE",
        "/api/v1/projects/{project}/exceptions/{id}",
        Some(Action::ExceptionWrite),
    ),
    (
        "GET",
        "/api/v1/projects/{project}/regressions/{ref}/readiness",
        Some(Action::ReadinessRead),
    ),
    (
        "GET",
        "/api/v1/projects/{project}/changes",
        Some(Action::ChangesRead),
    ),
    ("GET", "/api/v1/projects", Some(Action::RegressionRead)),
    (
        "GET",
        "/api/v1/projects/{project}/regressions",
        Some(Action::RegressionRead),
    ),
    (
        "GET",
        "/api/v1/projects/{project}/signatures/{signature}",
        Some(Action::RegressionRead),
    ),
    (
        "GET",
        "/api/v1/projects/{project}/regressions/{ref}/slots/{slot}/attempts/{seq}",
        Some(Action::RegressionRead),
    ),
    (
        "GET",
        "/api/v1/projects/{project}/admin",
        Some(Action::AdminRead),
    ),
    (
        "GET",
        "/api/v1/projects/{project}/admin/retention",
        Some(Action::AdminRead),
    ),
    (
        "GET",
        "/api/v1/projects/{project}/ledger",
        Some(Action::AdminRead),
    ),
    (
        "POST",
        "/api/v1/projects/{project}/ledger",
        Some(Action::TriageWrite),
    ),
    (
        "GET",
        "/api/v1/projects/{project}/rules",
        Some(Action::RulesRead),
    ),
    (
        "GET",
        "/api/v1/projects/{project}/rules/definition",
        Some(Action::RulesRead),
    ),
    (
        "GET",
        "/api/v1/projects/{project}/rules/sample/files/{sha256}",
        Some(Action::RulesWrite),
    ),
    (
        "PUT",
        "/api/v1/projects/{project}/rules/sample/files/{sha256}",
        Some(Action::RulesWrite),
    ),
    (
        "POST",
        "/api/v1/projects/{project}/rules/sample",
        Some(Action::RulesWrite),
    ),
    (
        "POST",
        "/api/v1/projects/{project}/rules/activations",
        Some(Action::RulesWrite),
    ),
    (
        "POST",
        "/api/v1/projects/{project}/checklists",
        Some(Action::ChecklistWrite),
    ),
    (
        "PUT",
        "/api/v1/projects/{project}/hierarchy",
        Some(Action::HierarchyWrite),
    ),
    (
        "GET",
        "/api/v1/projects/{project}/hierarchy",
        Some(Action::HierarchyRead),
    ),
    (
        "GET",
        "/api/v1/projects/{project}/health",
        Some(Action::HealthRead),
    ),
    (
        "GET",
        "/api/v1/projects/{project}/health/history",
        Some(Action::HealthRead),
    ),
    (
        "GET",
        "/api/v1/projects/{project}/health/growth",
        Some(Action::HealthRead),
    ),
    (
        "GET",
        "/api/v1/projects/{project}/checklists",
        Some(Action::ChecklistRead),
    ),
    (
        "GET",
        "/api/v1/projects/{project}/checklists/{checklist}/evaluation",
        Some(Action::ChecklistRead),
    ),
    (
        "POST",
        "/api/v1/projects/{project}/checklists/{checklist}/attestations",
        Some(Action::ChecklistWrite),
    ),
    (
        "DELETE",
        "/api/v1/projects/{project}/checklists/{checklist}/attestations/{id}",
        Some(Action::ChecklistWrite),
    ),
    (
        "POST",
        "/api/v1/projects/{project}/readiness/publications",
        Some(Action::PublicationWrite),
    ),
    (
        "GET",
        "/api/v1/projects/{project}/readiness/publications",
        Some(Action::PublicationWrite),
    ),
    (
        "POST",
        "/api/v1/projects/{project}/readiness/publications/{digest}/posted",
        Some(Action::PublicationWrite),
    ),
    (
        "POST",
        "/api/v1/projects/{project}/readiness/publications/{digest}/retire",
        Some(Action::PublicationWrite),
    ),
    (
        "GET",
        "/api/v1/projects/{project}/readiness/receipts/{digest}",
        Some(Action::ReadinessRead),
    ),
    (
        "GET",
        "/api/v1/projects/{project}/regressions/{ref}/repair-list",
        Some(Action::RegressionRead),
    ),
    (
        "GET",
        "/api/v1/projects/{project}/regressions/{ref}/readiness/preview",
        Some(Action::ReadinessRead),
    ),
    ("POST", "/api/v1/session", None),
    ("DELETE", "/api/v1/session", None),
];

/// The API router (merged with the health routes by [`crate::api::router`]).
pub fn router(state: ApiState) -> Router {
    Router::new()
        .route("/api/v1/source-manifests", post(source_manifest))
        .route("/api/v1/regressions", post(regression))
        .route("/api/v1/regressions/{ref}/manifest/chunks/{n}", put(chunk))
        .route("/api/v1/regressions/{ref}/manifest/seal", post(seal))
        .route("/api/v1/regressions/{ref}/manifest/amend", post(amend))
        .route("/api/v1/regressions/{ref}/slots/mark", post(mark))
        .route("/api/v1/regressions/{ref}/finish", post(finish))
        .route("/api/v1/ingest", post(ingest))
        .route("/api/v1/reconcile", post(reconcile))
        .route("/api/v1/projects/{project}/regressions/{ref}", get(read))
        .route(
            "/api/v1/projects/{project}/regressions/{ref}/comparison",
            get(comparison),
        )
        .route("/api/v1/projects/{project}/triage/{signature}", put(triage))
        .route("/api/v1/projects/{project}/triage", post(triage_bulk))
        .route(
            "/api/v1/projects/{project}/exceptions",
            post(exception_create),
        )
        .route(
            "/api/v1/projects/{project}/exceptions/{id}",
            axum::routing::delete(exception_revoke),
        )
        .route(
            "/api/v1/projects/{project}/regressions/{ref}/readiness",
            get(readiness),
        )
        .route("/api/v1/projects/{project}/changes", get(changes))
        .route("/api/v1/projects", get(projects))
        .route("/api/v1/projects/{project}/regressions", get(regressions))
        .route(
            "/api/v1/projects/{project}/signatures/{signature}",
            get(signature),
        )
        .route(
            "/api/v1/projects/{project}/regressions/{ref}/slots/{slot}/attempts/{seq}",
            get(attempt),
        )
        .route("/api/v1/projects/{project}/admin", get(admin_overview))
        .route(
            "/api/v1/projects/{project}/admin/retention",
            get(retention_preview),
        )
        .route(
            "/api/v1/projects/{project}/ledger",
            get(ledger_export).post(ledger_import),
        )
        .route("/api/v1/projects/{project}/rules", get(rules_status))
        .route(
            "/api/v1/projects/{project}/rules/definition",
            get(rules_definition),
        )
        .route(
            "/api/v1/projects/{project}/rules/sample/files/{sha256}",
            get(sample_file).put(sample_chunk),
        )
        .route(
            "/api/v1/projects/{project}/rules/sample",
            post(sample_register),
        )
        .route(
            "/api/v1/projects/{project}/rules/activations",
            post(rules_activate),
        )
        .route(
            "/api/v1/projects/{project}/checklists",
            post(checklist_import).get(checklist_list),
        )
        .route(
            "/api/v1/projects/{project}/hierarchy",
            put(hierarchy_import).get(hierarchy_read),
        )
        .route("/api/v1/projects/{project}/health", get(health_read))
        .route(
            "/api/v1/projects/{project}/health/history",
            get(health_history),
        )
        .route(
            "/api/v1/projects/{project}/health/growth",
            get(health_growth),
        )
        .route(
            "/api/v1/projects/{project}/checklists/{checklist}/evaluation",
            get(checklist_evaluation),
        )
        .route(
            "/api/v1/projects/{project}/checklists/{checklist}/attestations",
            post(attestation_create),
        )
        .route(
            "/api/v1/projects/{project}/checklists/{checklist}/attestations/{id}",
            axum::routing::delete(attestation_revoke),
        )
        .route(
            "/api/v1/projects/{project}/readiness/publications",
            post(publish).get(open_publications),
        )
        .route(
            "/api/v1/projects/{project}/readiness/publications/{digest}/posted",
            post(publication_posted),
        )
        .route(
            "/api/v1/projects/{project}/readiness/publications/{digest}/retire",
            post(publication_retire),
        )
        .route(
            "/api/v1/projects/{project}/readiness/receipts/{digest}",
            get(receipt),
        )
        .route(
            "/api/v1/projects/{project}/regressions/{ref}/repair-list",
            get(repair_list),
        )
        .route(
            "/api/v1/projects/{project}/regressions/{ref}/readiness/preview",
            get(readiness_preview),
        )
        .route("/api/v1/session", post(login).delete(logout))
        .layer(DefaultBodyLimit::max(limits::MAX_ENCODED_REQUEST_BYTES))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            maintenance,
        ))
        .with_state(state)
}

/// Maintenance mode: every write is refused (503 `E_UNAVAILABLE`); reads and
/// logins stay possible so an operator can inspect a restored database.
async fn maintenance(
    State(st): State<ApiState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    // Logins and reconciliation (a read sent as POST) stay possible.
    let write = !matches!(*req.method(), Method::GET | Method::HEAD)
        && !matches!(req.uri().path(), "/api/v1/session" | "/api/v1/reconcile");
    if write
        && crate::backup::maintenance_on(&st.app.db)
            .await
            .unwrap_or(true)
    {
        return AppError::new(
            ErrorCode::Unavailable,
            "the server is in maintenance: writes are refused (retry later)",
        )
        .into_response();
    }
    next.run(req).await
}

fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_string())
}

fn bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.strip_prefix("Bearer ").unwrap_or("").trim().to_string())
}

fn same_origin(cfg: &ServerConfig, headers: &HeaderMap) -> bool {
    headers
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|o| o == cfg.public_origin)
}

fn session_hash(id: &str) -> Vec<u8> {
    Sha256::digest(id.as_bytes()).to_vec()
}

/// The actor of a request: a bearer token, or a browser session (with CSRF and Origin
/// checks on state-changing methods). Both at once is refused.
async fn actor(st: &ApiState, method: &Method, headers: &HeaderMap) -> Result<Actor, AppError> {
    let token = bearer(headers);
    let session = cookie(headers, SESSION_COOKIE);
    match (token, session) {
        (Some(_), Some(_)) => Err(AppError::new(
            ErrorCode::MixedCredentials,
            "send a bearer token or a session cookie, not both",
        )),
        (Some(t), None) => auth::actor_from_token(&st.app.db, &t).await,
        (None, Some(s)) => {
            let row = sqlx::query(
                "UPDATE sessions SET last_seen_at = now()
                  WHERE id_hash = $1
                    AND last_seen_at > now() - make_interval(secs => $2)
                    AND created_at > now() - make_interval(secs => $3)
                  RETURNING user_id, csrf",
            )
            .bind(session_hash(&s))
            .bind(SESSION_IDLE_S as f64)
            .bind(SESSION_ABSOLUTE_S as f64)
            .fetch_optional(&st.app.db)
            .await?
            .ok_or_else(|| AppError::new(ErrorCode::Unauthenticated, "no valid session"))?;
            let user_id: i64 = row.get(0);
            let csrf: String = row.get(1);
            if method != Method::GET && method != Method::HEAD {
                let sent = headers.get(CSRF_HEADER).and_then(|v| v.to_str().ok());
                if sent != Some(csrf.as_str()) || !same_origin(&st.cfg, headers) {
                    return Err(AppError::new(
                        ErrorCode::Forbidden,
                        "state-changing browser requests need the CSRF header and the canonical Origin",
                    ));
                }
            }
            let disabled: bool = sqlx::query("SELECT disabled FROM users WHERE id = $1")
                .bind(user_id)
                .fetch_one(&st.app.db)
                .await?
                .get(0);
            if disabled {
                return Err(AppError::new(
                    ErrorCode::Unauthenticated,
                    "no valid session",
                ));
            }
            Ok(Actor::User {
                user_id,
                token_id: None,
                roles: auth::roles_of(&st.app.db, user_id).await?,
            })
        }
        (None, None) => Err(AppError::new(
            ErrorCode::Unauthenticated,
            "a bearer token or a session is required",
        )),
    }
}

/// A request body, reserved against the in-flight budget and decoded (gzip, bounded by
/// size and ratio).
struct Body {
    bytes: Vec<u8>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

fn too_large(msg: &str) -> AppError {
    AppError::new(ErrorCode::TooLarge, msg)
}

/// Reads a request body within the in-flight budget: the declared length (required) is
/// reserved before a byte is read, the body may not exceed it, and the reservation (sized
/// for the decoded body) lives as long as the returned value, i.e. through processing.
async fn body(
    st: &ApiState,
    headers: &HeaderMap,
    stream: axum::body::Body,
) -> Result<Body, AppError> {
    body_within(&st.in_flight, st.body_deadline, headers, stream).await
}

/// [`body`] within a given budget, the read bounded by `deadline`.
async fn body_within(
    budget: &Arc<Semaphore>,
    deadline: std::time::Duration,
    headers: &HeaderMap,
    stream: axum::body::Body,
) -> Result<Body, AppError> {
    let encoded = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        .ok_or_else(|| {
            AppError::new(ErrorCode::Invalid, "a request body needs a Content-Length")
        })?;
    if encoded > limits::MAX_ENCODED_REQUEST_BYTES {
        return Err(too_large("request too large"));
    }
    // gzip or nothing: another or a stacked encoding (in one field or in several) is
    // refused, never read as identity.
    let encodings: Vec<&HeaderValue> = headers.get_all(header::CONTENT_ENCODING).iter().collect();
    if encodings.len() > 1 {
        return Err(AppError::new(
            ErrorCode::Invalid,
            "unsupported Content-Encoding (gzip, or none; one field)",
        ));
    }
    let gzip = match encodings.first().map(|v| v.to_str()) {
        None => false,
        Some(Ok(v)) if v.trim().eq_ignore_ascii_case("identity") => false,
        Some(Ok(v)) if v.trim().eq_ignore_ascii_case("gzip") => true,
        Some(_) => {
            return Err(AppError::new(
                ErrorCode::Invalid,
                "unsupported Content-Encoding (gzip, or none)",
            ));
        }
    };
    let cap = if gzip {
        limits::MAX_DECODED_REQUEST_BYTES.min(encoded.saturating_mul(limits::MAX_COMPRESSION_RATIO))
    } else {
        encoded
    };
    let permits = u32::try_from(cap.max(1)).unwrap_or(u32::MAX);
    let permit = Arc::clone(budget)
        .try_acquire_many_owned(permits)
        .map_err(|_| AppError::new(ErrorCode::Unavailable, "the server is busy, retry"))?;
    let raw = tokio::time::timeout(deadline, axum::body::to_bytes(stream, encoded))
        .await
        .map_err(|_| {
            AppError::new(
                ErrorCode::Unavailable,
                "the request body did not arrive in time, retry",
            )
        })?
        .map_err(|_| too_large("the body is longer than its Content-Length or the limit"))?;
    let bytes = if gzip {
        let mut out = Vec::new();
        let mut d = flate2::read::GzDecoder::new(&raw[..]).take(cap as u64 + 1);
        d.read_to_end(&mut out)
            .map_err(|_| AppError::new(ErrorCode::Invalid, "invalid gzip body"))?;
        if out.len() > cap {
            return Err(too_large(
                "the decoded body exceeds the decoded size or compression ratio limit",
            ));
        }
        out
    } else {
        raw.to_vec()
    };
    Ok(Body {
        bytes,
        _permit: permit,
    })
}

fn depth(v: &Value) -> usize {
    match v {
        Value::Array(a) => 1 + a.iter().map(depth).max().unwrap_or(0),
        Value::Object(o) => 1 + o.values().map(depth).max().unwrap_or(0),
        _ => 0,
    }
}

fn json_value(bytes: &[u8]) -> Result<Value, AppError> {
    if bytes.len() > limits::MAX_RECORD_BYTES {
        return Err(too_large("record too large"));
    }
    let v: Value = serde_json::from_slice(bytes)?;
    if depth(&v) > limits::MAX_JSON_DEPTH {
        return Err(AppError::new(ErrorCode::Invalid, "JSON nested too deeply"));
    }
    Ok(v)
}

/// Route-level authorization, before any body is decoded: a collector needs the action's
/// scope in its own project; a user may only take role-based actions (the project is
/// checked by the read itself).
fn route_auth(actor: &Actor, action: Action) -> Result<(), AppError> {
    match actor {
        Actor::Collector { project_id, .. } => auth::authorize(actor, action, *project_id),
        Actor::User { .. } if auth::policy(action).0.is_some() => Err(AppError::new(
            ErrorCode::Forbidden,
            "only collector tokens submit records",
        )),
        Actor::User { .. } => Ok(()),
    }
}

fn receipt_response(r: Receipt, created: bool) -> Response {
    let status = if created && !r.duplicate {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    (status, axum::Json(r.body)).into_response()
}

/// Authenticates and authorizes from the headers alone, then reads the body within the
/// in-flight budget. The returned `Body` holds the reservation: keep it until the response.
async fn op_body(
    st: &ApiState,
    action: Action,
    req: axum::extract::Request,
) -> Result<(Actor, Value, Body), AppError> {
    let (parts, stream) = req.into_parts();
    let a = actor(st, &parts.method, &parts.headers).await?;
    route_auth(&a, action)?;
    let b = body(st, &parts.headers, stream).await?;
    let v = json_value(&b.bytes)?;
    Ok((a, v, b))
}

/// `POST /api/v1/reconcile`: what the server holds for the collector's record identities
/// and regressions (read-only).
async fn reconcile(
    State(st): State<ApiState>,
    req: axum::extract::Request,
) -> Result<Response, AppError> {
    let (a, v, _held) = op_body(&st, Action::IngestSubmit, req).await?;
    let r: crate::app::reconcile::Request = serde_json::from_value(v)?;
    Ok(axum::Json(st.app.reconcile(&a, &r).await?).into_response())
}

async fn source_manifest(
    State(st): State<ApiState>,
    req: axum::extract::Request,
) -> Result<Response, AppError> {
    let (a, v, _held) = op_body(&st, Action::SourceManifestCreate, req).await?;
    Ok(receipt_response(
        st.app.create_source_manifest(&a, &v).await?,
        true,
    ))
}

async fn regression(
    State(st): State<ApiState>,
    req: axum::extract::Request,
) -> Result<Response, AppError> {
    let (a, v, _held) = op_body(&st, Action::RegressionCreate, req).await?;
    Ok(receipt_response(
        st.app.create_regression(&a, &v).await?,
        true,
    ))
}

async fn chunk(
    State(st): State<ApiState>,
    Path((r, n)): Path<(String, i32)>,
    req: axum::extract::Request,
) -> Result<Response, AppError> {
    let (a, v, _held) = op_body(&st, Action::ManifestChunk, req).await?;
    Ok(receipt_response(
        st.app.manifest_chunk(&a, &r, n, &v).await?,
        false,
    ))
}

async fn seal(
    State(st): State<ApiState>,
    Path(r): Path<String>,
    req: axum::extract::Request,
) -> Result<Response, AppError> {
    let (a, v, _held) = op_body(&st, Action::ManifestSeal, req).await?;
    Ok(receipt_response(
        st.app.manifest_seal(&a, &r, &v).await?,
        false,
    ))
}

async fn amend(
    State(st): State<ApiState>,
    Path(r): Path<String>,
    req: axum::extract::Request,
) -> Result<Response, AppError> {
    let (a, v, _held) = op_body(&st, Action::ManifestAmend, req).await?;
    Ok(receipt_response(
        st.app.manifest_amend(&a, &r, &v).await?,
        false,
    ))
}

async fn mark(
    State(st): State<ApiState>,
    Path(r): Path<String>,
    req: axum::extract::Request,
) -> Result<Response, AppError> {
    let (a, v, _held) = op_body(&st, Action::SlotMark, req).await?;
    Ok(receipt_response(st.app.slot_mark(&a, &r, &v).await?, false))
}

async fn finish(
    State(st): State<ApiState>,
    Path(r): Path<String>,
    req: axum::extract::Request,
) -> Result<Response, AppError> {
    let (a, v, _held) = op_body(&st, Action::RegressionFinish, req).await?;
    Ok(receipt_response(st.app.finish(&a, &r, &v).await?, false))
}

/// `POST /api/v1/ingest`: NDJSON in, one NDJSON result line per input line, in order. Each
/// record is its own transaction; a bad line is rejected alone.
async fn ingest(
    State(st): State<ApiState>,
    req: axum::extract::Request,
) -> Result<Response, AppError> {
    let (parts, stream) = req.into_parts();
    let a = actor(&st, &parts.method, &parts.headers).await?;
    route_auth(&a, Action::IngestSubmit)?;
    let b = body(&st, &parts.headers, stream).await?;
    let text = std::str::from_utf8(&b.bytes)
        .map_err(|_| AppError::new(ErrorCode::Invalid, "the batch is not UTF-8 NDJSON"))?;
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines.len() > limits::MAX_RECORDS_PER_BATCH {
        return Err(too_large("too many records in one batch"));
    }
    let mut out = String::new();
    for (i, line) in lines.iter().enumerate() {
        let n = i + 1;
        let result = match json_value(line.as_bytes()) {
            Ok(v) => st.app.ingest_line(&a, &v).await,
            Err(e) => LineResult::Rejected(e),
        };
        let row = match result {
            LineResult::Ok(r) => json!({
                "line": n,
                "result": if r.duplicate { "duplicate" } else { "committed" },
                "receipt": r.body,
            }),
            LineResult::Rejected(e) => {
                json!({"line": n, "result": "rejected", "status": e.code.http_status(), "error": e.body()})
            }
        };
        out.push_str(&row.to_string());
        out.push('\n');
    }
    let mut res = (StatusCode::OK, out).into_response();
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-ndjson"),
    );
    Ok(res)
}

#[derive(Debug, Deserialize)]
struct ReadQuery {
    producer: Option<String>,
    baseline: Option<String>,
}

async fn read(
    State(st): State<ApiState>,
    Path((project, r)): Path<(String, String)>,
    Query(q): Query<ReadQuery>,
    method: Method,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let a = actor(&st, &method, &headers).await?;
    let v = st
        .app
        .read_regression(&a, &project, &r, q.producer.as_deref())
        .await?;
    Ok(axum::Json(v).into_response())
}

async fn comparison(
    State(st): State<ApiState>,
    Path((project, r)): Path<(String, String)>,
    Query(q): Query<ReadQuery>,
    method: Method,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let a = actor(&st, &method, &headers).await?;
    let c = st
        .app
        .read_comparison(
            &a,
            &project,
            &r,
            q.baseline.as_deref(),
            q.producer.as_deref(),
        )
        .await?;
    let mut cmp = serde_json::to_value(&c.comparison)?;
    if let Some(rows) = cmp.get_mut("rows").and_then(Value::as_array_mut) {
        for row in rows {
            let d = row
                .get("signature")
                .and_then(Value::as_str)
                .and_then(|f| c.decisions.get(f));
            if let (Some(obj), Some(d)) = (row.as_object_mut(), d)
                && let Value::Object(extra) = serde_json::to_value(d)?
            {
                obj.extend(extra);
            }
        }
    }
    Ok(
        axum::Json(json!({"regression": c.regression, "comparison": cmp, "finish": c.finish, "baseline": c.baseline}))
            .into_response(),
    )
}

#[derive(Debug, Deserialize)]
struct TriageQuery {
    branch: Option<String>,
}

/// `PUT …/triage/{signature}?branch=repo/name` with `If-Match: <revision>` for an edit.
async fn triage(
    State(st): State<ApiState>,
    Path((project, signature)): Path<(String, i64)>,
    Query(q): Query<TriageQuery>,
    req: axum::extract::Request,
) -> Result<Response, AppError> {
    let if_match = req
        .headers()
        .get(header::IF_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim_matches('"').parse::<i32>())
        .transpose()
        .map_err(|_| AppError::new(ErrorCode::Invalid, "If-Match is a revision number"))?;
    let (a, v, _held) = op_body(&st, Action::TriageWrite, req).await?;
    let edit: crate::app::decisions::TriageEdit = serde_json::from_value(v)?;
    let branch = q
        .branch
        .ok_or_else(|| AppError::field(ErrorCode::Invalid, "branch is required", "branch"))?;
    let h = st
        .app
        .set_triage(&a, &project, signature, &branch, if_match, &edit)
        .await?;
    let mut res = axum::Json(&h).into_response();
    res.headers_mut().insert(
        header::ETAG,
        HeaderValue::from_str(&format!("\"{}\"", h.revision))
            .map_err(|_| AppError::internal("etag"))?,
    );
    Ok(res)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BulkTriageBody {
    signatures: Vec<crate::app::decisions::BulkTriageItem>,
    state: String,
    #[serde(default)]
    owner: Option<String>,
    #[serde(default)]
    notes: String,
    #[serde(default)]
    bug_urls: Vec<String>,
}

/// `POST …/triage?branch=repo/name`: one decision for several signatures, all or nothing.
async fn triage_bulk(
    State(st): State<ApiState>,
    Path(project): Path<String>,
    Query(q): Query<TriageQuery>,
    req: axum::extract::Request,
) -> Result<Response, AppError> {
    let (a, v, _held) = op_body(&st, Action::TriageWrite, req).await?;
    let body: BulkTriageBody = serde_json::from_value(v)?;
    let edit = crate::app::decisions::TriageEdit {
        state: body.state,
        owner: body.owner,
        notes: body.notes,
        bug_urls: body.bug_urls,
    };
    let branch = q
        .branch
        .ok_or_else(|| AppError::field(ErrorCode::Invalid, "branch is required", "branch"))?;
    let cases = st
        .app
        .set_triage_bulk(&a, &project, &branch, &body.signatures, &edit)
        .await?;
    Ok(axum::Json(json!({ "cases": cases })).into_response())
}

async fn exception_create(
    State(st): State<ApiState>,
    Path(project): Path<String>,
    req: axum::extract::Request,
) -> Result<Response, AppError> {
    let if_match = req
        .headers()
        .get(header::IF_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim_matches('"').parse::<i32>())
        .transpose()
        .map_err(|_| AppError::new(ErrorCode::Invalid, "If-Match is a revision number"))?;
    let (a, v, _held) = op_body(&st, Action::ExceptionWrite, req).await?;
    let r: crate::app::decisions::ExceptionRequest = serde_json::from_value(v)?;
    let h = st
        .app
        .create_exception(&a, &project, &r, if_match, time::OffsetDateTime::now_utc())
        .await?;
    Ok((StatusCode::CREATED, axum::Json(h)).into_response())
}

async fn exception_revoke(
    State(st): State<ApiState>,
    Path((project, id)): Path<(String, i64)>,
    method: Method,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let a = actor(&st, &method, &headers).await?;
    route_auth(&a, Action::ExceptionWrite)?;
    st.app.revoke_exception(&a, &project, id).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[derive(Debug, Deserialize)]
struct ReadinessQuery {
    expect_source: Option<String>,
    producer: Option<String>,
}

async fn readiness(
    State(st): State<ApiState>,
    Path((project, r)): Path<(String, String)>,
    Query(q): Query<ReadinessQuery>,
    method: Method,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let a = actor(&st, &method, &headers).await?;
    let v = st
        .app
        .read_readiness(
            &a,
            &project,
            &r,
            q.expect_source.as_deref(),
            q.producer.as_deref(),
            time::OffsetDateTime::now_utc(),
        )
        .await?;
    Ok(axum::Json(v).into_response())
}

async fn publish(
    State(st): State<ApiState>,
    Path(project): Path<String>,
    req: axum::extract::Request,
) -> Result<Response, AppError> {
    let (a, v, _held) = op_body(&st, Action::PublicationWrite, req).await?;
    let r: crate::app::publications::PublishRequest = serde_json::from_value(v)?;
    let out = st
        .app
        .publish(&a, &project, &r, time::OffsetDateTime::now_utc())
        .await?;
    Ok(axum::Json(out).into_response())
}

#[derive(Debug, Deserialize)]
struct AfterQuery {
    after: Option<String>,
}

async fn open_publications(
    State(st): State<ApiState>,
    Path(project): Path<String>,
    Query(q): Query<AfterQuery>,
    method: Method,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let a = actor(&st, &method, &headers).await?;
    route_auth(&a, Action::PublicationWrite)?;
    Ok(axum::Json(
        st.app
            .open_publications(&a, &project, q.after.as_deref())
            .await?,
    )
    .into_response())
}

async fn publication_posted(
    State(st): State<ApiState>,
    Path((project, digest)): Path<(String, String)>,
    req: axum::extract::Request,
) -> Result<Response, AppError> {
    let (a, v, _held) = op_body(&st, Action::PublicationWrite, req).await?;
    let p: crate::app::publications::Posted = serde_json::from_value(v)?;
    let out = st
        .app
        .mark_posted(&a, &project, &digest, &p, time::OffsetDateTime::now_utc())
        .await?;
    Ok(axum::Json(out).into_response())
}

async fn publication_retire(
    State(st): State<ApiState>,
    Path((project, digest)): Path<(String, String)>,
    req: axum::extract::Request,
) -> Result<Response, AppError> {
    let (a, v, _held) = op_body(&st, Action::PublicationWrite, req).await?;
    let r: crate::app::publications::Retire = serde_json::from_value(v)?;
    let out = st
        .app
        .retire_publication(&a, &project, &digest, &r, time::OffsetDateTime::now_utc())
        .await?;
    Ok(axum::Json(out).into_response())
}

async fn receipt(
    State(st): State<ApiState>,
    Path((project, digest)): Path<(String, String)>,
    method: Method,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let a = actor(&st, &method, &headers).await?;
    route_auth(&a, Action::ReadinessRead)?;
    let out = st
        .app
        .read_receipt(&a, &project, &digest, time::OffsetDateTime::now_utc())
        .await?;
    Ok(axum::Json(out).into_response())
}

async fn ledger_export(
    State(st): State<ApiState>,
    Path(project): Path<String>,
    method: Method,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let a = actor(&st, &method, &headers).await?;
    route_auth(&a, Action::AdminRead)?;
    let l = st
        .app
        .export_ledger(&a, &project, time::OffsetDateTime::now_utc())
        .await?;
    Ok(axum::Json(l).into_response())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LedgerImport {
    ledger: crate::app::ledger::Ledger,
    #[serde(default)]
    mapping: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    dry_run: bool,
}

async fn ledger_import(
    State(st): State<ApiState>,
    Path(project): Path<String>,
    req: axum::extract::Request,
) -> Result<Response, AppError> {
    let (a, v, _held) = op_body(&st, Action::TriageWrite, req).await?;
    let r: LedgerImport = serde_json::from_value(v)?;
    let out = st
        .app
        .import_ledger(
            &a,
            &project,
            &r.ledger,
            &r.mapping,
            r.dry_run,
            time::OffsetDateTime::now_utc(),
        )
        .await?;
    Ok(axum::Json(out).into_response())
}

async fn rules_status(
    State(st): State<ApiState>,
    Path(project): Path<String>,
    method: Method,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let a = actor(&st, &method, &headers).await?;
    route_auth(&a, Action::RulesRead)?;
    Ok(axum::Json(st.app.rules_status(&a, &project).await?).into_response())
}

async fn rules_definition(
    State(st): State<ApiState>,
    Path(project): Path<String>,
    method: Method,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let a = actor(&st, &method, &headers).await?;
    route_auth(&a, Action::RulesRead)?;
    Ok(axum::Json(st.app.rules_definition(&a, &project).await?).into_response())
}

async fn sample_file(
    State(st): State<ApiState>,
    Path((project, sha256)): Path<(String, String)>,
    method: Method,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let a = actor(&st, &method, &headers).await?;
    route_auth(&a, Action::RulesWrite)?;
    Ok(axum::Json(st.app.sample_file(&a, &project, &sha256).await?).into_response())
}

#[derive(Debug, Deserialize)]
struct ChunkQuery {
    size: i64,
    offset: i64,
}

async fn sample_chunk(
    State(st): State<ApiState>,
    Path((project, sha256)): Path<(String, String)>,
    req: axum::extract::Request,
) -> Result<Response, AppError> {
    let (parts, stream) = req.into_parts();
    let a = actor(&st, &parts.method, &parts.headers).await?;
    route_auth(&a, Action::RulesWrite)?;
    // The query is read after authentication (an unauthenticated request is 401 first).
    let Query(q) = Query::<ChunkQuery>::try_from_uri(&parts.uri).map_err(|_| {
        AppError::field(
            ErrorCode::Invalid,
            "size and offset are required integers",
            "offset",
        )
    })?;
    let b = body(&st, &parts.headers, stream).await?;
    let out = st
        .app
        .sample_chunk(&a, &project, &sha256, q.size, q.offset, &b.bytes)
        .await?;
    Ok(axum::Json(out).into_response())
}

async fn sample_register(
    State(st): State<ApiState>,
    Path(project): Path<String>,
    req: axum::extract::Request,
) -> Result<Response, AppError> {
    let (a, v, _held) = op_body(&st, Action::RulesWrite, req).await?;
    let m: dviscope_core::rule_check::SampleManifest = serde_json::from_value(v)?;
    let out = st.app.register_sample(&a, &project, &m).await?;
    Ok((StatusCode::CREATED, axum::Json(out)).into_response())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivationRequest {
    definition: crate::app::rules::PipelineDefinition,
    check: dviscope_core::rule_check::Structural,
}

async fn rules_activate(
    State(st): State<ApiState>,
    Path(project): Path<String>,
    req: axum::extract::Request,
) -> Result<Response, AppError> {
    let (a, v, _held) = op_body(&st, Action::RulesWrite, req).await?;
    let r: ActivationRequest = serde_json::from_value(v)?;
    let out = st
        .app
        .activate_rules(&a, &project, &r.definition, &r.check)
        .await?;
    Ok((StatusCode::CREATED, axum::Json(out)).into_response())
}

async fn checklist_import(
    State(st): State<ApiState>,
    Path(project): Path<String>,
    req: axum::extract::Request,
) -> Result<Response, AppError> {
    let (a, v, _held) = op_body(&st, Action::ChecklistWrite, req).await?;
    let c: dviscope_model::wire::checklist::Checklist = serde_json::from_value(v)?;
    let out = st.app.import_checklist(&a, &project, &c).await?;
    let status = if out["result"] == "imported" {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, axum::Json(out)).into_response())
}

async fn hierarchy_import(
    State(st): State<ApiState>,
    Path(project): Path<String>,
    req: axum::extract::Request,
) -> Result<Response, AppError> {
    let (a, v, _held) = op_body(&st, Action::HierarchyWrite, req).await?;
    let h: dviscope_model::wire::hierarchy::Hierarchy = serde_json::from_value(v)?;
    let out = st.app.import_hierarchy(&a, &project, &h).await?;
    let status = if out["result"] == "imported" {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, axum::Json(out)).into_response())
}

async fn hierarchy_read(
    State(st): State<ApiState>,
    Path(project): Path<String>,
    method: Method,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let a = actor(&st, &method, &headers).await?;
    route_auth(&a, Action::HierarchyRead)?;
    Ok(axum::Json(st.app.read_hierarchy(&a, &project).await?).into_response())
}

#[derive(Debug, Deserialize)]
struct HealthQuery {
    area: Option<String>,
}

async fn health_read(
    State(st): State<ApiState>,
    Path(project): Path<String>,
    Query(q): Query<HealthQuery>,
    method: Method,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let a = actor(&st, &method, &headers).await?;
    route_auth(&a, Action::HealthRead)?;
    let out = st
        .app
        .read_health(
            &a,
            &project,
            q.area.as_deref(),
            time::OffsetDateTime::now_utc(),
        )
        .await?;
    Ok(axum::Json(out).into_response())
}

#[derive(Debug, Deserialize)]
struct GrowthQuery {
    area: Option<String>,
    days: Option<i64>,
}

async fn health_growth(
    State(st): State<ApiState>,
    Path(project): Path<String>,
    Query(q): Query<GrowthQuery>,
    method: Method,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let a = actor(&st, &method, &headers).await?;
    route_auth(&a, Action::HealthRead)?;
    let out = st
        .app
        .read_health_growth(
            &a,
            &project,
            q.area.as_deref(),
            q.days.unwrap_or(90),
            time::OffsetDateTime::now_utc(),
        )
        .await?;
    Ok(axum::Json(out).into_response())
}

#[derive(Debug, Deserialize)]
struct HistoryQuery {
    // Optional here so a request without credentials is answered 401 before 400.
    producer: Option<String>,
    suite: Option<String>,
    branch: Option<String>,
    limit: Option<i64>,
}

async fn health_history(
    State(st): State<ApiState>,
    Path(project): Path<String>,
    Query(q): Query<HistoryQuery>,
    method: Method,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let a = actor(&st, &method, &headers).await?;
    route_auth(&a, Action::HealthRead)?;
    let need = |v: Option<String>, f: &str| {
        v.ok_or_else(|| AppError::field(ErrorCode::Invalid, format!("{f} is required"), f))
    };
    let stream = dviscope_model::wire::hierarchy::StreamRef {
        producer: need(q.producer, "producer")?,
        suite: need(q.suite, "suite")?,
        branch: need(q.branch, "branch")?,
    };
    let out = st
        .app
        .read_health_history(
            &a,
            &project,
            &stream,
            q.limit.unwrap_or(crate::app::health::MAX_HISTORY),
            time::OffsetDateTime::now_utc(),
        )
        .await?;
    Ok(axum::Json(out).into_response())
}

async fn checklist_list(
    State(st): State<ApiState>,
    Path(project): Path<String>,
    method: Method,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let a = actor(&st, &method, &headers).await?;
    Ok(axum::Json(st.app.list_checklists(&a, &project).await?).into_response())
}

#[derive(Debug, Deserialize)]
struct EvaluationQuery {
    branch: Option<String>,
    version: Option<String>,
}

async fn checklist_evaluation(
    State(st): State<ApiState>,
    Path((project, checklist)): Path<(String, String)>,
    Query(q): Query<EvaluationQuery>,
    method: Method,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let a = actor(&st, &method, &headers).await?;
    route_auth(&a, Action::ChecklistRead)?;
    let branch = q
        .branch
        .ok_or_else(|| AppError::field(ErrorCode::Invalid, "branch is required", "branch"))?;
    let out = st
        .app
        .evaluate_feature(
            &a,
            &project,
            &checklist,
            q.version.as_deref(),
            &branch,
            time::OffsetDateTime::now_utc(),
        )
        .await?;
    Ok(axum::Json(out).into_response())
}

async fn attestation_create(
    State(st): State<ApiState>,
    Path((project, checklist)): Path<(String, String)>,
    req: axum::extract::Request,
) -> Result<Response, AppError> {
    let (a, v, _held) = op_body(&st, Action::ChecklistWrite, req).await?;
    let r: crate::app::checklists::AttestRequest = serde_json::from_value(v)?;
    let out = st.app.attest(&a, &project, &checklist, &r).await?;
    Ok((StatusCode::CREATED, axum::Json(out)).into_response())
}

async fn attestation_revoke(
    State(st): State<ApiState>,
    Path((project, checklist, id)): Path<(String, String, i64)>,
    method: Method,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let a = actor(&st, &method, &headers).await?;
    route_auth(&a, Action::ChecklistWrite)?;
    st.app
        .revoke_attestation(&a, &project, &checklist, id)
        .await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn admin_overview(
    State(st): State<ApiState>,
    Path(project): Path<String>,
    method: Method,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let a = actor(&st, &method, &headers).await?;
    Ok(axum::Json(st.app.admin_overview(&a, &project).await?).into_response())
}

async fn retention_preview(
    State(st): State<ApiState>,
    Path(project): Path<String>,
    method: Method,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let a = actor(&st, &method, &headers).await?;
    Ok(axum::Json(st.app.retention_preview(&a, &project).await?).into_response())
}

async fn repair_list(
    State(st): State<ApiState>,
    Path((project, r)): Path<(String, String)>,
    Query(q): Query<ReadQuery>,
    method: Method,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let a = actor(&st, &method, &headers).await?;
    let v = st
        .app
        .repair_list(&a, &project, &r, q.producer.as_deref())
        .await?;
    Ok(axum::Json(v).into_response())
}

#[derive(Debug, Deserialize)]
struct PreviewQuery {
    producer: Option<String>,
    signature: Option<i64>,
    expires_at: Option<String>,
}

/// `GET …/readiness/preview?signature=N&expires_at=T`: the impact of a hypothetical
/// exception for the regression's branch and suite (nothing is stored).
async fn readiness_preview(
    State(st): State<ApiState>,
    Path((project, r)): Path<(String, String)>,
    Query(q): Query<PreviewQuery>,
    method: Method,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let a = actor(&st, &method, &headers).await?;
    route_auth(&a, Action::ReadinessRead)?;
    let signature = q
        .signature
        .ok_or_else(|| AppError::field(ErrorCode::Invalid, "signature is required", "signature"))?;
    let expires_at = q.expires_at.ok_or_else(|| {
        AppError::field(ErrorCode::Invalid, "expires_at is required", "expires_at")
    })?;
    time::OffsetDateTime::parse(&expires_at, &time::format_description::well_known::Rfc3339)
        .map_err(|_| AppError::field(ErrorCode::Invalid, "expires_at is RFC 3339", "expires_at"))?;
    let v = st
        .app
        .preview_exception(
            &a,
            &project,
            &r,
            q.producer.as_deref(),
            crate::app::readiness::ExceptionPreview {
                signature,
                expires_at,
            },
            time::OffsetDateTime::now_utc(),
        )
        .await?;
    Ok(axum::Json(v).into_response())
}

async fn projects(
    State(st): State<ApiState>,
    method: Method,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let a = actor(&st, &method, &headers).await?;
    Ok(axum::Json(st.app.list_projects(&a).await?).into_response())
}

#[derive(Debug, Deserialize)]
struct PageQuery {
    before: Option<String>,
    limit: Option<i64>,
}

async fn regressions(
    State(st): State<ApiState>,
    Path(project): Path<String>,
    Query(q): Query<PageQuery>,
    method: Method,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let a = actor(&st, &method, &headers).await?;
    Ok(axum::Json(
        st.app
            .list_regressions(&a, &project, q.before.as_deref(), q.limit)
            .await?,
    )
    .into_response())
}

async fn signature(
    State(st): State<ApiState>,
    Path((project, number)): Path<(String, i64)>,
    method: Method,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let a = actor(&st, &method, &headers).await?;
    Ok(axum::Json(st.app.signature_detail(&a, &project, number).await?).into_response())
}

async fn attempt(
    State(st): State<ApiState>,
    Path((project, r, slot, seq)): Path<(String, String, String, i32)>,
    Query(q): Query<ReadQuery>,
    method: Method,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let a = actor(&st, &method, &headers).await?;
    Ok(axum::Json(
        st.app
            .attempt_detail(&a, &project, &r, &slot, seq, q.producer.as_deref())
            .await?,
    )
    .into_response())
}

#[derive(Debug, Deserialize)]
struct ChangesQuery {
    #[serde(default)]
    since: i64,
}

async fn changes(
    State(st): State<ApiState>,
    Path(project): Path<String>,
    Query(q): Query<ChangesQuery>,
    method: Method,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let a = actor(&st, &method, &headers).await?;
    Ok(axum::Json(st.app.changes_since(&a, &project, q.since).await?).into_response())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Login {
    username: String,
    password: String,
}

/// Throttle: 5 failed attempts per account and 20 per client address in 15
/// minutes. Every attempt is counted (atomically, before its password is hashed), so a
/// burst of concurrent guesses cannot pass the check together; a success refunds it.
/// Returns whether every key still had room.
async fn reserve_attempt(st: &ApiState, keys: &[(String, i32)]) -> Result<bool, AppError> {
    let mut tx = st.app.db.begin().await?;
    // Expired windows are forgotten, so the table never outgrows the attempts of the last
    // window.
    sqlx::query("DELETE FROM login_throttle WHERE window_start < now() - interval '15 minutes'")
        .execute(&mut *tx)
        .await?;
    let mut room = true;
    // The address first: once it is over its limit nothing more is recorded (a client
    // rotating usernames never creates rows).
    for (k, max) in keys.iter().rev() {
        if !room {
            break;
        }
        let n: i32 = sqlx::query(
            "INSERT INTO login_throttle (key, failures, window_start) VALUES ($1, 1, now())
             ON CONFLICT (key) DO UPDATE SET
               failures = CASE WHEN login_throttle.window_start > now() - interval '15 minutes'
                               THEN login_throttle.failures + 1 ELSE 1 END,
               window_start = CASE WHEN login_throttle.window_start > now() - interval '15 minutes'
                                   THEN login_throttle.window_start ELSE now() END
             RETURNING failures",
        )
        .bind(k)
        .fetch_one(&mut *tx)
        .await?
        .get(0);
        room &= n <= *max;
    }
    tx.commit().await?;
    Ok(room)
}

/// A successful login: the account's count is cleared, the address's attempt refunded.
async fn refund_attempt(st: &ApiState, keys: &[(String, i32)]) -> Result<(), AppError> {
    sqlx::query("DELETE FROM login_throttle WHERE key = $1")
        .bind(&keys[0].0)
        .execute(&st.app.db)
        .await?;
    sqlx::query("UPDATE login_throttle SET failures = greatest(failures - 1, 0) WHERE key = $1")
        .bind(&keys[1].0)
        .execute(&st.app.db)
        .await?;
    Ok(())
}

/// `POST /api/v1/session`: local login (Origin checked), a new session (rotated), the CSRF
/// token in `X-DVIScope-CSRF`.
async fn login(
    State(st): State<ApiState>,
    req: axum::extract::Request,
) -> Result<Response, AppError> {
    let (parts, body_stream) = req.into_parts();
    let headers = parts.headers;
    // The peer address of the connection (never a client-supplied header).
    let addr = parts
        .extensions
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map_or_else(|| "unknown".to_string(), |c| c.0.ip().to_string());
    if bearer(&headers).is_some() {
        return Err(AppError::new(
            ErrorCode::MixedCredentials,
            "a login carries no bearer token",
        ));
    }
    if !same_origin(&st.cfg, &headers) {
        return Err(AppError::new(
            ErrorCode::Forbidden,
            "login needs the canonical Origin",
        ));
    }
    if headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        .is_none_or(|n| n > MAX_LOGIN_BODY_BYTES)
    {
        return Err(too_large("a login body is small"));
    }
    if headers.contains_key(header::CONTENT_ENCODING) {
        return Err(AppError::new(
            ErrorCode::Invalid,
            "a login body is not encoded",
        ));
    }
    let b = body_within(&st.login_in_flight, st.body_deadline, &headers, body_stream).await?;
    let l: Login = serde_json::from_slice(&b.bytes)?;
    if l.username.is_empty() || l.username.chars().count() > 64 {
        return Err(AppError::field(
            ErrorCode::Invalid,
            "a username has 1 to 64 characters",
            "username",
        ));
    }
    let keys = vec![
        (format!("user:{}", l.username), 5),
        (format!("addr:{addr}"), 20),
    ];
    if !reserve_attempt(&st, &keys).await? {
        return Err(AppError::new(
            ErrorCode::RateLimited,
            "too many failed logins, wait",
        ));
    }
    let row = sqlx::query(
        "SELECT u.id, c.phc FROM users u JOIN local_credentials c ON c.user_id = u.id
          WHERE u.username = $1 AND NOT u.disabled",
    )
    .bind(&l.username)
    .fetch_optional(&st.app.db)
    .await?;
    // At most a few hashes at once; a request does not queue for long.
    let permit = tokio::time::timeout(std::time::Duration::from_secs(10), st.hashes.acquire())
        .await
        .map_err(|_| AppError::new(ErrorCode::Unavailable, "busy, retry"))?
        .map_err(|_| AppError::internal("hash limiter"))?;
    // A hash is computed for unknown users too (same cost, no account probing).
    let phc: Option<String> = row.as_ref().map(|r| r.get(1));
    let password = l.password.clone();
    let good = tokio::task::spawn_blocking(move || match phc {
        Some(p) => auth::verify_password(&password, &p),
        None => {
            let _ = auth::hash_password("dviscope-timing-equalizer");
            false
        }
    })
    .await
    .map_err(|_| AppError::internal("password check"))?;
    drop(permit);
    let Some(row) = row.filter(|_| good) else {
        // The attempt was counted when it was admitted.
        return Err(AppError::new(
            ErrorCode::Unauthenticated,
            "unknown user or wrong password",
        ));
    };
    let user_id: i64 = row.get(0);
    let id = auth::new_token()?;
    let csrf = auth::new_token()?;
    sqlx::query(
        "INSERT INTO sessions (id_hash, user_id, csrf, created_at, last_seen_at)
         VALUES ($1, $2, $3, now(), now())",
    )
    .bind(session_hash(&id))
    .bind(user_id)
    .bind(&csrf)
    .execute(&st.app.db)
    .await?;
    refund_attempt(&st, &keys).await?;
    let mut res = StatusCode::NO_CONTENT.into_response();
    let h = res.headers_mut();
    h.insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "{SESSION_COOKIE}={id}; HttpOnly; Secure; SameSite=Lax; Path=/"
        ))
        .map_err(|_| AppError::internal("cookie"))?,
    );
    h.insert(
        CSRF_HEADER,
        HeaderValue::from_str(&csrf).map_err(|_| AppError::internal("csrf"))?,
    );
    Ok(res)
}

/// `DELETE /api/v1/session`: ends this session (CSRF and Origin checked).
async fn logout(State(st): State<ApiState>, headers: HeaderMap) -> Result<Response, AppError> {
    let a = actor(&st, &Method::DELETE, &headers).await?;
    if !matches!(a, Actor::User { token_id: None, .. }) {
        return Err(AppError::new(
            ErrorCode::Invalid,
            "no browser session to end",
        ));
    }
    if let Some(s) = cookie(&headers, SESSION_COOKIE) {
        sqlx::query("DELETE FROM sessions WHERE id_hash = $1")
            .bind(session_hash(&s))
            .execute(&st.app.db)
            .await?;
    }
    let mut res = StatusCode::NO_CONTENT.into_response();
    res.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static(
            "__Host-dviscope=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0",
        ),
    );
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_action_has_a_route() {
        for a in auth::ALL_ACTIONS {
            assert!(
                ROUTES.iter().any(|(_, _, x)| *x == Some(*a)),
                "{a:?} has no route"
            );
        }
    }

    #[test]
    fn json_depth_is_bounded() {
        let mut deep = String::new();
        for _ in 0..40 {
            deep.push('[');
        }
        for _ in 0..40 {
            deep.push(']');
        }
        assert!(json_value(deep.as_bytes()).is_err());
        assert!(json_value(b"[[[1]]]").is_ok());
    }
}
