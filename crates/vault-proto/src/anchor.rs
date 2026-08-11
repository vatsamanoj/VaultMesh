//! Wire types for coordinator-issued anchor access (presigned URLs).
//!
//! The coordinator holds the object-store credentials; a node-agent asks it for
//! a short-lived, path-scoped presigned URL per shard operation, then does the
//! transfer directly to the store. Node-agents never hold the S3 keys, and the
//! anchor is never reachable by a client without a coordinator-issued URL.

use serde::{Deserialize, Serialize};
use vault_domain::{BlobId, NamespaceId};

/// The shard operation a presigned URL authorizes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PresignOp {
    Put,
    Get,
}

/// Request a presigned URL for one shard object.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PresignRequest {
    pub namespace: NamespaceId,
    pub blob_id: BlobId,
    pub index: u16,
    pub op: PresignOp,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PresignResponse {
    pub url: String,
    pub expires_secs: u64,
}

/// Ask the coordinator to delete a whole blob's objects (it holds the creds).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeleteBlobRequest {
    pub namespace: NamespaceId,
    pub blob_id: BlobId,
}
