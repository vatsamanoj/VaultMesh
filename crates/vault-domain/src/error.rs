//! Domain errors. Pure policy failures only — no I/O error variants (those live
//! in `vault-ports::PortError`).

use crate::capability::Operation;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DomainError {
    #[error("invalid erasure params: k={k}, n={n} (require k>=1 and n>=k)")]
    InvalidErasureParams { k: u8, n: u8 },

    #[error("capability token is expired")]
    TokenExpired,

    #[error("caller is not authorized (app mismatch)")]
    Unauthorized,

    #[error("token namespace does not match the requested namespace")]
    NamespaceMismatch,

    #[error("token grants '{granted}' but '{requested}' was requested")]
    OperationNotPermitted {
        granted: Operation,
        requested: Operation,
    },

    #[error("namespace quota exceeded")]
    QuotaExceeded,

    #[error("retention hold: blob must be kept at least {min_days} day(s) before deletion")]
    RetentionHold { min_days: u32 },

    #[error("invalid contract: {0}")]
    InvalidContract(String),
}
