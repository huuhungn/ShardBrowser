use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use crate::identity::ReasonCode;

/// Uniform error type for handlers; renders to `{ "error": "..." }`.
#[derive(Debug)]
pub enum AppError {
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict(String),
    BadRequest(String),
    Internal(String),
    /// Rate-limited; the value is the Retry-After hint in seconds.
    TooManyRequests(u64),
    /// The identity authority did not verify at startup, so v2 writes are
    /// off (plan L1238: HTTP 423 with the reason code).
    EpochAuthority(ReasonCode),
    /// A refusal with a plan 8.2 wire code (ADR 0001 R3), for clients that
    /// fail closed on a code they do not know.
    Coded(StatusCode, &'static str, String),
    /// A stored grant that disagrees with its signed container: refused as
    /// `AUTH_CLAIM_COLUMN_MISMATCH`, and quarantined once the request's own
    /// transaction has rolled back (plan 5.6.4).
    Quarantine(Box<crate::quarantine::Mark>),
    /// The replay of a commit a restore rolled back (ADR 0002 D-1):
    /// `BASE_VERSION_MISMATCH` with the allowlisted epoch that superseded it.
    Superseded(u64),
}

impl AppError {
    fn parts(&self) -> (StatusCode, String) {
        match self {
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized".into()),
            AppError::Forbidden => (StatusCode::FORBIDDEN, "forbidden".into()),
            AppError::NotFound => (StatusCode::NOT_FOUND, "not found".into()),
            AppError::Conflict(m) => (StatusCode::CONFLICT, m.clone()),
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, m.clone()),
            AppError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m.clone()),
            AppError::TooManyRequests(_) => (
                StatusCode::TOO_MANY_REQUESTS,
                "too many attempts; try again later".into(),
            ),
            AppError::EpochAuthority(code) => (
                StatusCode::LOCKED,
                format!(
                    "v2 is unavailable until the server's control plane verifies: {}",
                    code.as_str()
                ),
            ),
            AppError::Coded(status, _, m) => (*status, m.clone()),
            AppError::Quarantine(_) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "the stored grant does not match its signed container".into(),
            ),
            AppError::Superseded(_) => (
                StatusCode::CONFLICT,
                "a restore rolled this commit back".into(),
            ),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (code, msg) = self.parts();
        // A 5xx detail stays in the server log; the client only ever sees a
        // generic message, so we never leak SQL text, file paths, or constraint
        // names. 4xx messages are deliberate and safe to return.
        let client_msg = if code.is_server_error() {
            tracing::error!("internal error: {msg}");
            "internal server error".to_string()
        } else {
            msg
        };
        let body = match &self {
            AppError::EpochAuthority(reason) => {
                json!({ "error": client_msg, "code": reason.as_str() })
            }
            AppError::Coded(_, code, _) => json!({ "error": client_msg, "code": code }),
            AppError::Quarantine(_) => {
                json!({ "error": client_msg, "code": "AUTH_CLAIM_COLUMN_MISMATCH" })
            }
            AppError::Superseded(epoch) => json!({
                "error": client_msg,
                "code": "BASE_VERSION_MISMATCH",
                "superseded_by_restore_epoch": epoch,
            }),
            _ => json!({ "error": client_msg }),
        };
        let mut resp = (code, Json(body)).into_response();
        if let AppError::Quarantine(mark) = self {
            resp.extensions_mut().insert(*mark);
            return resp;
        }
        if let AppError::TooManyRequests(secs) = self {
            if let Ok(v) = axum::http::HeaderValue::from_str(&secs.to_string()) {
                resp.headers_mut()
                    .insert(axum::http::header::RETRY_AFTER, v);
            }
        }
        resp
    }
}

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        // Map predictable, client-caused DB errors to 4xx instead of 500; the
        // rest are genuine internal failures (detail logged, not returned).
        match &e {
            sqlx::Error::RowNotFound => AppError::NotFound,
            sqlx::Error::Database(db) if db.is_unique_violation() => {
                AppError::Conflict("resource already exists".into())
            }
            sqlx::Error::Database(db) if db.is_foreign_key_violation() => {
                AppError::BadRequest("references a resource that does not exist".into())
            }
            _ => AppError::Internal(format!("db: {e}")),
        }
    }
}

impl From<anyhow::Error> for AppError {
    fn from(e: anyhow::Error) -> Self {
        AppError::Internal(e.to_string())
    }
}
