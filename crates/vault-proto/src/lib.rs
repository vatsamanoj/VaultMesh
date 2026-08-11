//! `vault-proto` — the versioned wire contract. This is the ONLY surface shared
//! between clients and servers. Keep it additive: a **minor** bump must stay
//! backward compatible (new optional fields only), so an old `vault-client`
//! keeps interoperating with a newer server.

mod anchor;
mod control;
mod data;

pub use anchor::{DeleteBlobRequest, PresignOp, PresignRequest, PresignResponse};
pub use control::{
    CoordinatorKey, CreateNamespaceRequest, CreateNamespaceResponse, IssueCapabilityRequest,
    IssueCapabilityResponse, RegisterAppRequest, RegisterAppResponse, RepairRequest,
};
pub use data::{
    DeleteRequest, GetRequest, ListRequest, ListResponse, PutRequest, PutResponse, RestoredBlob,
};

use serde::{Deserialize, Serialize};
use vault_domain::ProtocolVersion;

/// The protocol version this build speaks. Mirrors `ProtocolVersion::CURRENT`.
pub const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::CURRENT;

/// Uniform error envelope returned by both planes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireError {
    /// Stable, machine-readable error code (e.g. "unauthorized", "not_found").
    pub code: String,
    /// Human-readable detail (never contains plaintext or secrets).
    pub message: String,
}

impl WireError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

/// Response to `GET /v1/protocol` — lets a client negotiate compatibility.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProtocolInfo {
    pub version: ProtocolVersion,
}

impl Default for ProtocolInfo {
    fn default() -> Self {
        Self {
            version: PROTOCOL_VERSION,
        }
    }
}
