//! Application errors with stable codes (error registry), rendered as the API error body.
//! SQL errors stay inside: clients see `E_INTERNAL` with a correlation ID.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use dviscope_model::errors::{ApiError, ErrorCode};

/// An error of an application operation.
#[derive(Debug, Clone)]
pub struct AppError {
    /// Code.
    pub code: ErrorCode,
    /// Message (never log text, tokens or paths).
    pub message: String,
    /// Offending field.
    pub field: Option<String>,
    /// Whether anything was committed.
    pub committed: bool,
}

impl AppError {
    /// A new error.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            field: None,
            committed: false,
        }
    }

    /// An error naming a field.
    pub fn field(code: ErrorCode, message: impl Into<String>, field: &str) -> Self {
        Self {
            field: Some(field.to_string()),
            ..Self::new(code, message)
        }
    }

    /// An internal error (details are logged, not returned).
    pub fn internal(what: &str) -> Self {
        Self::new(ErrorCode::Internal, format!("internal error ({what})"))
    }

    /// The API body.
    #[must_use]
    pub fn body(&self) -> ApiError {
        ApiError {
            code: self.code,
            message: self.message.clone(),
            field: self.field.clone(),
            record: None,
            committed: self.committed,
            correlation_id: correlation_id(),
        }
    }
}

fn correlation_id() -> String {
    let mut b = [0u8; 8];
    let _ = getrandom::fill(&mut b);
    hex::encode(b)
}

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        // Unique violations are races the caller may retry; everything else is internal.
        if let sqlx::Error::Database(d) = &e
            && d.code().as_deref() == Some("40001")
        {
            return Self::new(ErrorCode::Unavailable, "concurrent update, retry");
        }
        tracing::error!(error = %e, "database error");
        Self::internal("database")
    }
}

impl From<serde_json::Error> for AppError {
    fn from(e: serde_json::Error) -> Self {
        Self::new(
            ErrorCode::Invalid,
            format!(
                "invalid JSON: {}",
                e.to_string().lines().next().unwrap_or_default()
            ),
        )
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.code.http_status())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let mut res = (status, Json(self.body())).into_response();
        if matches!(
            self.code,
            ErrorCode::RateLimited | ErrorCode::Unavailable | ErrorCode::StorageFull
        ) {
            res.headers_mut().insert(
                axum::http::header::RETRY_AFTER,
                axum::http::HeaderValue::from_static("5"),
            );
        }
        res
    }
}
