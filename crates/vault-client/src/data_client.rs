//! Data-plane client: talks to the localhost node-agent sidecar. Payloads are
//! ciphertext — encrypt with [`ContentCipher`] before `put`.
//!
//! [`ContentCipher`]: crate::ContentCipher

use crate::codec::{b64_decode, b64_encode};
use crate::error::ClientError;
use reqwest::Client;
use vault_domain::{BlobId, CapabilityToken, NamespaceId};
use vault_proto::{
    DeleteRequest, GetRequest, ListRequest, ListResponse, PutRequest, PutResponse, RestoredBlob,
};

pub struct NodeAgentClient {
    base_url: String,
    http: Client,
}

impl NodeAgentClient {
    /// Point at the local sidecar, e.g. `http://127.0.0.1:8790`.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            http: Client::new(),
        }
    }

    /// Store already-encrypted `ciphertext`; returns its opaque blob id.
    pub async fn put(
        &self,
        namespace: &NamespaceId,
        token: &CapabilityToken,
        ciphertext: &[u8],
    ) -> Result<BlobId, ClientError> {
        let req = PutRequest {
            namespace: namespace.clone(),
            token: token.clone(),
            ciphertext_b64: b64_encode(ciphertext),
        };
        let resp: PutResponse = self.post_json("/v1/backups", &req).await?;
        Ok(resp.blob_id)
    }

    /// Fetch and reconstruct the ciphertext for `blob_id`.
    pub async fn get(
        &self,
        namespace: &NamespaceId,
        token: &CapabilityToken,
        blob_id: &BlobId,
    ) -> Result<Vec<u8>, ClientError> {
        let req = GetRequest {
            namespace: namespace.clone(),
            token: token.clone(),
            blob_id: blob_id.clone(),
        };
        let resp: RestoredBlob = self.post_json("/v1/backups/get", &req).await?;
        b64_decode(&resp.ciphertext_b64)
    }

    pub async fn list(
        &self,
        namespace: &NamespaceId,
        token: &CapabilityToken,
    ) -> Result<Vec<BlobId>, ClientError> {
        let req = ListRequest {
            namespace: namespace.clone(),
            token: token.clone(),
        };
        let resp: ListResponse = self.post_json("/v1/backups/list", &req).await?;
        Ok(resp.blob_ids)
    }

    pub async fn delete(
        &self,
        namespace: &NamespaceId,
        token: &CapabilityToken,
        blob_id: &BlobId,
    ) -> Result<(), ClientError> {
        let req = DeleteRequest {
            namespace: namespace.clone(),
            token: token.clone(),
            blob_id: blob_id.clone(),
        };
        let _: serde_json::Value = self.post_json("/v1/backups/delete", &req).await?;
        Ok(())
    }

    async fn post_json<B: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<R, ClientError> {
        let resp = self
            .http
            .post(format!("{}{path}", self.base_url))
            .json(body)
            .send()
            .await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            return Err(ClientError::Server {
                status: status.as_u16(),
                body: text,
            });
        }
        serde_json::from_str(&text).map_err(|e| ClientError::Encoding(e.to_string()))
    }
}
