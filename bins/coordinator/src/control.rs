//! Control-plane handlers: onboarding, namespaces, capability tokens.

use crate::http::{err, ApiError};
use crate::state::AppState;
use adapter_crypto::Ed25519Signer;
use axum::extract::State;
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use vault_app::{CreateNamespace, IssueCapability, RegisterApp};
use vault_ports::CapabilitySigner;
use vault_proto::{
    CoordinatorKey, CreateNamespaceRequest, CreateNamespaceResponse, IssueCapabilityRequest,
    IssueCapabilityResponse, ProtocolInfo, RegisterAppRequest, RegisterAppResponse,
};

pub async fn health() -> &'static str {
    "ok"
}

pub async fn protocol() -> Json<ProtocolInfo> {
    Json(ProtocolInfo::default())
}

/// The coordinator's capability-verification key, fetched by node-agents.
pub async fn pubkey(State(st): State<AppState>) -> Json<CoordinatorKey> {
    Json(CoordinatorKey {
        public_key_b64: STANDARD.encode(st.signer.public_key()),
    })
}

pub async fn register_app(
    State(st): State<AppState>,
    Json(req): Json<RegisterAppRequest>,
) -> Result<Json<RegisterAppResponse>, ApiError> {
    let uc = RegisterApp::new(st.metadata.clone(), st.ids.clone());
    let contract = uc
        .execute(req.quota, req.retention, req.erasure)
        .await
        .map_err(err)?;

    // The app signing keypair proves control of the registration. In production
    // the private half is delivered to the app over a secure admin channel; here
    // we mint one and return only its public half.
    let app_key = Ed25519Signer::generate();
    let app_id = contract.app_id.clone();
    Ok(Json(RegisterAppResponse {
        app_id,
        contract,
        app_signing_public_key_b64: STANDARD.encode(app_key.public_key()),
    }))
}

pub async fn create_namespace(
    State(st): State<AppState>,
    Json(req): Json<CreateNamespaceRequest>,
) -> Result<Json<CreateNamespaceResponse>, ApiError> {
    let uc = CreateNamespace::new(st.metadata.clone(), st.ids.clone());
    let ns = uc.execute(&req.app_id).await.map_err(err)?;
    Ok(Json(CreateNamespaceResponse {
        namespace_id: ns.id,
    }))
}

pub async fn issue_capability(
    State(st): State<AppState>,
    Json(req): Json<IssueCapabilityRequest>,
) -> Result<Json<IssueCapabilityResponse>, ApiError> {
    let uc = IssueCapability::new(
        st.metadata.clone(),
        st.signer.clone(),
        st.ids.clone(),
        st.clock.clone(),
    );
    let token = uc
        .execute(&req.app_id, &req.namespace, req.operation, req.ttl_secs)
        .await
        .map_err(err)?;
    Ok(Json(IssueCapabilityResponse { token }))
}
