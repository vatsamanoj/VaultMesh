//! The error type adapters return across every port.

use thiserror::Error;
use vault_domain::DomainError;

pub type PortResult<T> = Result<T, PortError>;

#[derive(Debug, Error)]
pub enum PortError {
    /// The requested entity does not exist.
    #[error("not found")]
    NotFound,

    /// A domain policy was violated (bubbled up through a port).
    #[error(transparent)]
    Domain(#[from] DomainError),

    /// A cryptographic operation failed (encrypt/decrypt/sign/verify).
    #[error("crypto error: {0}")]
    Crypto(String),

    /// Integrity check failed (e.g. shard SHA-256 mismatch).
    #[error("integrity error: {0}")]
    Integrity(String),

    /// Serialization / deserialization failed.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// The backing store/transport is unavailable.
    #[error("backend unavailable: {0}")]
    Unavailable(String),

    /// Any other backend-specific failure.
    #[error("backend error: {0}")]
    Backend(String),
}
