//! A [`BlobAnchor`] that holds **no** object-store credentials. For each shard
//! operation it asks the coordinator for a short-lived presigned URL, then does
//! the transfer directly to the store. Delete-by-prefix is delegated to the
//! coordinator (which holds the credentials).

use async_trait::async_trait;
use reqwest::{Client, StatusCode};
use vault_domain::{BlobId, NamespaceId};
use vault_ports::{BlobAnchor, PortError, PortResult, ShardRef};
use vault_proto::{DeleteBlobRequest, PresignOp, PresignRequest, PresignResponse};

pub struct PresignedBlobAnchor {
    coordinator: String,
    /// mTLS-capable client for coordinator calls.
    coord: Client,
    /// Plain client for the presigned-URL transfer to the object store.
    store: Client,
}

fn unavailable(e: impl std::fmt::Display) -> PortError {
    PortError::Unavailable(format!("presign transport: {e}"))
}

impl PresignedBlobAnchor {
    pub fn new(coordinator: impl Into<String>, coord: Client) -> Self {
        Self {
            coordinator: coordinator.into(),
            coord,
            store: Client::new(),
        }
    }

    async fn presigned_url(&self, at: &ShardRef, op: PresignOp) -> PortResult<String> {
        let req = PresignRequest {
            namespace: at.namespace.clone(),
            blob_id: at.blob_id.clone(),
            index: at.index,
            op,
        };
        let resp = self
            .coord
            .post(format!("{}/v1/anchor/presign", self.coordinator))
            .json(&req)
            .send()
            .await
            .map_err(unavailable)?;
        if !resp.status().is_success() {
            return Err(PortError::Backend(format!(
                "coordinator presign returned {}",
                resp.status()
            )));
        }
        let body: PresignResponse = resp
            .json()
            .await
            .map_err(|e| PortError::Serialization(e.to_string()))?;
        Ok(body.url)
    }
}

#[async_trait]
impl BlobAnchor for PresignedBlobAnchor {
    async fn put_shard(&self, at: &ShardRef, bytes: &[u8]) -> PortResult<()> {
        let url = self.presigned_url(at, PresignOp::Put).await?;
        let resp = self
            .store
            .put(url)
            .body(bytes.to_vec())
            .send()
            .await
            .map_err(unavailable)?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(PortError::Backend(format!("store put {}", resp.status())))
        }
    }

    async fn get_shard(&self, at: &ShardRef) -> PortResult<Vec<u8>> {
        let url = self.presigned_url(at, PresignOp::Get).await?;
        let resp = self.store.get(url).send().await.map_err(unavailable)?;
        match resp.status() {
            s if s.is_success() => resp.bytes().await.map(|b| b.to_vec()).map_err(unavailable),
            StatusCode::NOT_FOUND | StatusCode::FORBIDDEN => Err(PortError::NotFound),
            other => Err(PortError::Backend(format!("store get {other}"))),
        }
    }

    async fn delete_blob(&self, namespace: &NamespaceId, blob_id: &BlobId) -> PortResult<()> {
        let req = DeleteBlobRequest {
            namespace: namespace.clone(),
            blob_id: blob_id.clone(),
        };
        let resp = self
            .coord
            .post(format!("{}/v1/anchor/delete-blob", self.coordinator))
            .json(&req)
            .send()
            .await
            .map_err(unavailable)?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(PortError::Backend(format!(
                "coordinator delete-blob returned {}",
                resp.status()
            )))
        }
    }
}
