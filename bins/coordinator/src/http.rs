//! Maps `PortError` to an HTTP status + `WireError` body. Never leaks secrets.

use axum::http::StatusCode;
use axum::Json;
use vault_domain::DomainError;
use vault_ports::PortError;
use vault_proto::WireError;

pub type ApiError = (StatusCode, Json<WireError>);

pub fn err(e: PortError) -> ApiError {
    let (status, code) = match &e {
        PortError::NotFound => (StatusCode::NOT_FOUND, "not_found"),
        PortError::Domain(d) => domain_status(d),
        PortError::Crypto(_) => (StatusCode::UNAUTHORIZED, "invalid_signature"),
        PortError::Integrity(_) => (StatusCode::UNPROCESSABLE_ENTITY, "integrity"),
        PortError::Serialization(_) => (StatusCode::BAD_REQUEST, "bad_request"),
        PortError::Unavailable(_) => (StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        PortError::Backend(_) => (StatusCode::INTERNAL_SERVER_ERROR, "backend"),
    };
    (status, Json(WireError::new(code, e.to_string())))
}

fn domain_status(d: &DomainError) -> (StatusCode, &'static str) {
    match d {
        DomainError::TokenExpired => (StatusCode::UNAUTHORIZED, "token_expired"),
        DomainError::Unauthorized => (StatusCode::FORBIDDEN, "unauthorized"),
        DomainError::NamespaceMismatch => (StatusCode::FORBIDDEN, "namespace_mismatch"),
        DomainError::OperationNotPermitted { .. } => {
            (StatusCode::FORBIDDEN, "operation_not_permitted")
        }
        DomainError::QuotaExceeded => (StatusCode::TOO_MANY_REQUESTS, "quota_exceeded"),
        DomainError::RetentionHold { .. } => (StatusCode::FORBIDDEN, "retention_hold"),
        DomainError::InvalidErasureParams { .. } => (StatusCode::BAD_REQUEST, "invalid_erasure"),
        DomainError::InvalidContract(_) => (StatusCode::BAD_REQUEST, "invalid_contract"),
    }
}
