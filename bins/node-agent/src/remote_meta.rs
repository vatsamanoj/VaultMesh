//! A coordinator-backed [`MetadataStore`]. The node-agent holds the blob anchor
//! locally but reads/writes authoritative metadata (namespaces, contracts,
//! manifests) from the coordinator through this HTTP adapter — so ACLs and the
//! manifest index are shared and consistent. It sits behind the identical port,
//! so use-cases never change.

use async_trait::async_trait;
use reqwest::{Client, StatusCode};
use serde::de::DeserializeOwned;
use serde::Serialize;
use vault_domain::{AppContract, AppId, BlobId, Manifest, Namespace, NamespaceId};
use vault_ports::{MetadataStore, NamespaceUsage, PortError, PortResult};

pub struct RemoteMetadataStore {
    base: String,
    http: Client,
}

impl RemoteMetadataStore {
    pub fn new(base: impl Into<String>) -> Self {
        Self {
            base: base.into(),
            http: Client::new(),
        }
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> PortResult<T> {
        let resp = self
            .http
            .get(format!("{}{path}", self.base))
            .send()
            .await
            .map_err(|e| PortError::Unavailable(format!("coordinator: {e}")))?;
        self.parse(resp).await
    }

    async fn post<B: Serialize>(&self, path: &str, body: &B) -> PortResult<()> {
        let resp = self
            .http
            .post(format!("{}{path}", self.base))
            .json(body)
            .send()
            .await
            .map_err(|e| PortError::Unavailable(format!("coordinator: {e}")))?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(self.status_error(resp.status()))
        }
    }

    async fn parse<T: DeserializeOwned>(&self, resp: reqwest::Response) -> PortResult<T> {
        let status = resp.status();
        if !status.is_success() {
            return Err(self.status_error(status));
        }
        resp.json::<T>()
            .await
            .map_err(|e| PortError::Serialization(e.to_string()))
    }

    fn status_error(&self, status: StatusCode) -> PortError {
        match status {
            StatusCode::NOT_FOUND => PortError::NotFound,
            s => PortError::Backend(format!("coordinator returned {s}")),
        }
    }
}

#[async_trait]
impl MetadataStore for RemoteMetadataStore {
    async fn register_app(&self, _contract: &AppContract) -> PortResult<()> {
        Err(PortError::Unavailable(
            "app registration is a control-plane operation, not available to the node-agent".into(),
        ))
    }

    async fn get_contract(&self, app: &AppId) -> PortResult<Option<AppContract>> {
        self.get(&format!("/v1/meta/contracts/{app}")).await
    }

    async fn create_namespace(&self, ns: &Namespace) -> PortResult<()> {
        self.post("/v1/meta/namespaces", ns).await
    }

    async fn get_namespace(&self, id: &NamespaceId) -> PortResult<Option<Namespace>> {
        self.get(&format!("/v1/meta/namespaces/{id}")).await
    }

    async fn list_namespaces(&self) -> PortResult<Vec<NamespaceId>> {
        self.get("/v1/meta/namespaces").await
    }

    async fn namespace_usage(&self, id: &NamespaceId) -> PortResult<NamespaceUsage> {
        self.get(&format!("/v1/meta/namespaces/{id}/usage")).await
    }

    async fn put_manifest(&self, manifest: &Manifest) -> PortResult<()> {
        self.post("/v1/meta/manifests", manifest).await
    }

    async fn get_manifest(
        &self,
        namespace: &NamespaceId,
        blob_id: &BlobId,
    ) -> PortResult<Option<Manifest>> {
        self.get(&format!(
            "/v1/meta/namespaces/{namespace}/manifests/{blob_id}"
        ))
        .await
    }

    async fn list_blobs(&self, namespace: &NamespaceId) -> PortResult<Vec<BlobId>> {
        self.get(&format!("/v1/meta/namespaces/{namespace}/blobs"))
            .await
    }

    async fn delete_manifest(&self, namespace: &NamespaceId, blob_id: &BlobId) -> PortResult<()> {
        self.post(
            &format!("/v1/meta/namespaces/{namespace}/manifests/{blob_id}/delete"),
            &(),
        )
        .await
    }
}
