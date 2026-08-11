//! Control-plane client: talks to the coordinator over HTTP.

use crate::error::ClientError;
use reqwest::Client;
use vault_domain::{
    AppId, CapabilityToken, ErasureParams, NamespaceId, Operation, Quota, RetentionPolicy,
};
use vault_proto::{
    CreateNamespaceRequest, CreateNamespaceResponse, IssueCapabilityRequest,
    IssueCapabilityResponse, RegisterAppRequest, RegisterAppResponse,
};

pub struct CoordinatorClient {
    base_url: String,
    http: Client,
}

impl CoordinatorClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            http: Client::new(),
        }
    }

    pub async fn register_app(
        &self,
        label: &str,
        quota: Quota,
        retention: RetentionPolicy,
        erasure: ErasureParams,
    ) -> Result<RegisterAppResponse, ClientError> {
        let req = RegisterAppRequest {
            label: label.to_owned(),
            quota,
            retention,
            erasure,
        };
        self.post_json("/v1/apps", &req).await
    }

    pub async fn create_namespace(
        &self,
        app_id: &AppId,
    ) -> Result<CreateNamespaceResponse, ClientError> {
        let req = CreateNamespaceRequest {
            app_id: app_id.clone(),
        };
        self.post_json("/v1/namespaces", &req).await
    }

    pub async fn issue_capability(
        &self,
        app_id: &AppId,
        namespace: &NamespaceId,
        operation: Operation,
        ttl_secs: u64,
    ) -> Result<CapabilityToken, ClientError> {
        let req = IssueCapabilityRequest {
            app_id: app_id.clone(),
            namespace: namespace.clone(),
            operation,
            ttl_secs,
        };
        let resp: IssueCapabilityResponse = self.post_json("/v1/capabilities", &req).await?;
        Ok(resp.token)
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
