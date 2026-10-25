use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug)]
pub struct Error(pub StatusCode, pub &'static str);
impl Error {
    pub fn bad(code: &'static str) -> Self {
        Self(StatusCode::BAD_REQUEST, code)
    }
    pub fn conflict(code: &'static str) -> Self {
        Self(StatusCode::CONFLICT, code)
    }
    pub fn gone(code: &'static str) -> Self {
        Self(StatusCode::GONE, code)
    }
    pub fn denied() -> Self {
        Self(StatusCode::FORBIDDEN, "permission_denied")
    }
    pub fn unauthorized() -> Self {
        Self(StatusCode::UNAUTHORIZED, "unauthorized")
    }
    pub fn not_found() -> Self {
        Self(StatusCode::NOT_FOUND, "not_found")
    }
    pub fn unavailable(code: &'static str) -> Self {
        Self(StatusCode::SERVICE_UNAVAILABLE, code)
    }
    /// Stored data failed validation: never served, always a server error.
    pub fn corrupt() -> Self {
        Self(StatusCode::INTERNAL_SERVER_ERROR, "persisted_data_invalid")
    }
}
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        (
            self.0,
            Json(json!({"error":self.1,"message":self.1.replace('_'," ")})),
        )
            .into_response()
    }
}
impl From<sqlx::Error> for Error {
    fn from(e: sqlx::Error) -> Self {
        match e {
            sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed | sqlx::Error::Io(_) => {
                Self::unavailable("database_unavailable")
            }
            sqlx::Error::Database(ref e) if e.is_unique_violation() => Self::conflict("conflict"),
            sqlx::Error::Database(ref e) if matches!(e.code().as_deref(), Some("5" | "6")) => {
                Self::unavailable("database_unavailable")
            }
            _ => Self(StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        }
    }
}
impl From<anyhow::Error> for Error {
    fn from(_: anyhow::Error) -> Self {
        Self(StatusCode::INTERNAL_SERVER_ERROR, "internal")
    }
}
impl From<serde_json::Error> for Error {
    fn from(_: serde_json::Error) -> Self {
        Self::corrupt()
    }
}
