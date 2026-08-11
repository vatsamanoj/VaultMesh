//! Storage ports: the authoritative blob anchor and the metadata store.

use crate::error::PortResult;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use vault_domain::{AppContract, AppId, BlobId, Manifest, Namespace, NamespaceId};

/// Addresses one shard of one blob within a namespace.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ShardRef {
    pub namespace: NamespaceId,
    pub blob_id: BlobId,
    pub index: u16,
}

impl ShardRef {
    pub fn new(namespace: NamespaceId, blob_id: BlobId, index: u16) -> Self {
        Self {
            namespace,
            blob_id,
            index,
        }
    }

    /// A stable, filesystem/object-key-safe path for this shard.
    pub fn object_key(&self) -> String {
        format!(
            "{}/{}/{:05}.shard",
            self.namespace, self.blob_id, self.index
        )
    }
}

/// Current usage of a namespace, used for quota enforcement.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamespaceUsage {
    pub bytes: u64,
    pub objects: u64,
}

/// The always-on authoritative object store (RustFS in production, filesystem
/// in dev). Holds the full shard set — restore is guaranteed from here alone.
#[async_trait]
pub trait BlobAnchor: Send + Sync {
    async fn put_shard(&self, at: &ShardRef, bytes: &[u8]) -> PortResult<()>;
    async fn get_shard(&self, at: &ShardRef) -> PortResult<Vec<u8>>;
    async fn delete_blob(&self, namespace: &NamespaceId, blob_id: &BlobId) -> PortResult<()>;
}

/// The control-plane metadata store: app registry, namespaces, manifests.
#[async_trait]
pub trait MetadataStore: Send + Sync {
    // --- registry ---
    async fn register_app(&self, contract: &AppContract) -> PortResult<()>;
    async fn get_contract(&self, app: &AppId) -> PortResult<Option<AppContract>>;

    // --- namespaces ---
    async fn create_namespace(&self, ns: &Namespace) -> PortResult<()>;
    async fn get_namespace(&self, id: &NamespaceId) -> PortResult<Option<Namespace>>;
    async fn namespace_usage(&self, id: &NamespaceId) -> PortResult<NamespaceUsage>;

    // --- manifests ---
    async fn put_manifest(&self, manifest: &Manifest) -> PortResult<()>;
    async fn get_manifest(
        &self,
        namespace: &NamespaceId,
        blob_id: &BlobId,
    ) -> PortResult<Option<Manifest>>;
    async fn list_blobs(&self, namespace: &NamespaceId) -> PortResult<Vec<BlobId>>;
    async fn delete_manifest(&self, namespace: &NamespaceId, blob_id: &BlobId) -> PortResult<()>;
}
