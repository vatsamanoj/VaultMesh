//! The production [`BlobAnchor`]: shards live in **RustFS** (github.com/rustfs/rustfs),
//! reached over its S3-compatible API. This is the authoritative full-set store
//! that makes restore guaranteed; the filesystem anchor (`adapter-blob-fs`) is
//! the dev stand-in behind the same port.
//!
//! Because RustFS speaks S3, this adapter also works against MinIO or AWS S3 —
//! only the endpoint/credentials change. Node-agents talk to it directly here;
//! hardening to coordinator-issued, path-scoped presigned URLs is a later step
//! behind this same port.

use async_trait::async_trait;
use futures::StreamExt;
use object_store::aws::{AmazonS3, AmazonS3Builder};
use object_store::path::Path as ObjPath;
use object_store::signer::Signer;
use object_store::{Error as OsError, ObjectStore, PutPayload};
use std::sync::Arc;
use std::time::Duration;
use vault_domain::{BlobId, NamespaceId};
use vault_ports::{BlobAnchor, PortError, PortResult, ShardRef};

/// Connection settings for the S3-compatible RustFS endpoint.
#[derive(Clone, Debug)]
pub struct RustFsConfig {
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    pub access_key: String,
    pub secret_key: String,
    /// Allow plain HTTP (dev / in-overlay). Production uses TLS.
    pub allow_http: bool,
}

fn backend(e: impl std::fmt::Display) -> PortError {
    PortError::Backend(format!("rustfs/s3: {e}"))
}

fn build_s3(cfg: &RustFsConfig) -> PortResult<AmazonS3> {
    AmazonS3Builder::new()
        .with_endpoint(&cfg.endpoint)
        .with_bucket_name(&cfg.bucket)
        .with_region(&cfg.region)
        .with_access_key_id(&cfg.access_key)
        .with_secret_access_key(&cfg.secret_key)
        .with_allow_http(cfg.allow_http)
        // RustFS/MinIO use path-style addressing (bucket in the path).
        .with_virtual_hosted_style_request(false)
        .build()
        .map_err(backend)
}

fn shard_key(at: &ShardRef) -> ObjPath {
    ObjPath::from(at.object_key())
}

fn blob_prefix(namespace: &NamespaceId, blob_id: &BlobId) -> ObjPath {
    ObjPath::from(format!("{namespace}/{blob_id}"))
}

async fn delete_prefix(store: &dyn ObjectStore, prefix: &ObjPath) -> PortResult<()> {
    let mut listing = store.list(Some(prefix));
    while let Some(entry) = listing.next().await {
        let meta = entry.map_err(backend)?;
        store.delete(&meta.location).await.map_err(backend)?;
    }
    Ok(())
}

pub struct RustFsBlobAnchor {
    store: Arc<dyn ObjectStore>,
}

impl RustFsBlobAnchor {
    pub fn new(cfg: RustFsConfig) -> PortResult<Self> {
        Ok(Self {
            store: Arc::new(build_s3(&cfg)?),
        })
    }
}

/// Coordinator-side presigner: holds the S3 credentials and issues short-lived,
/// path-scoped presigned URLs so node-agents can transfer shards without ever
/// holding the object-store keys. Delete-by-prefix runs here too (it needs the
/// credentials and the shard listing).
pub struct RustFsPresigner {
    store: AmazonS3,
}

impl RustFsPresigner {
    pub fn new(cfg: RustFsConfig) -> PortResult<Self> {
        Ok(Self {
            store: build_s3(&cfg)?,
        })
    }

    /// A presigned URL for `method` (PUT/GET) on one shard, valid for `ttl`.
    pub async fn presign(
        &self,
        method: http::Method,
        at: &ShardRef,
        ttl: Duration,
    ) -> PortResult<String> {
        let url = self
            .store
            .signed_url(method, &shard_key(at), ttl)
            .await
            .map_err(backend)?;
        Ok(url.to_string())
    }

    pub async fn delete_blob(&self, namespace: &NamespaceId, blob_id: &BlobId) -> PortResult<()> {
        delete_prefix(&self.store, &blob_prefix(namespace, blob_id)).await
    }
}

#[async_trait]
impl BlobAnchor for RustFsBlobAnchor {
    async fn put_shard(&self, at: &ShardRef, bytes: &[u8]) -> PortResult<()> {
        self.store
            .put(&shard_key(at), PutPayload::from(bytes.to_vec()))
            .await
            .map(|_| ())
            .map_err(backend)
    }

    async fn get_shard(&self, at: &ShardRef) -> PortResult<Vec<u8>> {
        match self.store.get(&shard_key(at)).await {
            Ok(res) => res.bytes().await.map(|b| b.to_vec()).map_err(backend),
            Err(OsError::NotFound { .. }) => Err(PortError::NotFound),
            Err(e) => Err(backend(e)),
        }
    }

    async fn delete_blob(&self, namespace: &NamespaceId, blob_id: &BlobId) -> PortResult<()> {
        delete_prefix(&*self.store, &blob_prefix(namespace, blob_id)).await
    }
}
