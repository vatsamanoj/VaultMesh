//! VaultMesh domain core — pure entities and policies.
//!
//! This crate has **no I/O**. It imports no async runtime, no database driver,
//! no HTTP or object-store client. Everything here is deterministic and
//! unit-testable in isolation, and every side-effecting capability is expressed
//! as a *port* (trait) in `vault-ports`, implemented by adapters.
//!
//! Time is modelled as an explicit [`Timestamp`] passed in by callers (derived
//! from a `Clock` port), never read from the system clock here — so policy such
//! as capability-token expiry is fully testable.

mod backup;
mod capability;
mod contract;
mod error;
mod ids;
mod namespace;
mod placement;

pub use backup::{BackupObject, Manifest, Shard, ShardLocation};
pub use capability::{CapabilityClaims, CapabilityToken, Operation, Timestamp};
pub use contract::{
    AppContract, EncryptionMode, ErasureParams, ProtocolVersion, Quota, RetentionPolicy,
};
pub use error::DomainError;
pub use ids::{AppId, BlobId, NamespaceId, Nonce};
pub use namespace::Namespace;
pub use placement::PlacementPolicy;

/// Result alias for fallible domain operations.
pub type DomainResult<T> = Result<T, DomainError>;
