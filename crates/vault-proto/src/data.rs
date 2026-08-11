//! Data-plane wire types (app → node-agent sidecar over localhost).
//!
//! Payloads are already **ciphertext** — the app encrypts before calling. Bytes
//! travel base64-encoded in JSON bodies.

use serde::{Deserialize, Serialize};
use vault_domain::{BlobId, CapabilityToken, NamespaceId};

/// Store one already-encrypted blob.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PutRequest {
    pub namespace: NamespaceId,
    pub token: CapabilityToken,
    /// Base64 of the client-side ciphertext (`nonce || ct || tag`).
    pub ciphertext_b64: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PutResponse {
    pub blob_id: BlobId,
}

/// Fetch one blob for reconstruction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetRequest {
    pub namespace: NamespaceId,
    pub token: CapabilityToken,
    pub blob_id: BlobId,
}

/// List the opaque blob ids in a namespace.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ListRequest {
    pub namespace: NamespaceId,
    pub token: CapabilityToken,
}

/// Delete one blob (shards + manifest).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeleteRequest {
    pub namespace: NamespaceId,
    pub token: CapabilityToken,
    pub blob_id: BlobId,
}

/// The reconstructed ciphertext returned by a `get`. The app decrypts it with
/// its own key to recover the byte-identical original payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RestoredBlob {
    pub blob_id: BlobId,
    pub ciphertext_b64: String,
}

/// Opaque ids only — the app owns the id ↔ business-object catalog.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ListResponse {
    pub blob_ids: Vec<BlobId>,
}
