//! Admin/forensics endpoints: intrusion ledger, a status summary, and per-app
//! usage/billing. These live on the admin plane (separate authority in a real
//! deployment; see docs/SECURITY.md).

use crate::http::{err, ApiError};
use crate::state::AppState;
use adapter_perimeter::LedgerEntry;
use axum::extract::{Path, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use vault_app::{UsageReport, UsageStatement};
use vault_ports::{CertAuthority, NameResolver};
use vault_proto::PROTOCOL_VERSION;

#[derive(Serialize)]
pub struct IntrusionView {
    pub entries: Vec<LedgerEntry>,
    pub chain_valid: bool,
    pub blocked: Vec<String>,
}

pub async fn intrusions(State(st): State<AppState>) -> Json<IntrusionView> {
    Json(IntrusionView {
        entries: st.intrusions.entries(),
        chain_valid: st.intrusions.verify(),
        blocked: st.responder.blocked(),
    })
}

#[derive(Serialize)]
pub struct Status {
    pub protocol_version: String,
    pub namespaces: usize,
    pub intrusion_count: usize,
    pub intrusion_chain_valid: bool,
    pub blocked_fingerprints: usize,
}

pub async fn status(State(st): State<AppState>) -> Result<Json<Status>, ApiError> {
    let namespaces = st.metadata.list_namespaces().await.map_err(err)?.len();
    Ok(Json(Status {
        protocol_version: PROTOCOL_VERSION.to_string(),
        namespaces,
        intrusion_count: st.intrusions.len(),
        intrusion_chain_valid: st.intrusions.verify(),
        blocked_fingerprints: st.responder.blocked().len(),
    }))
}

pub async fn usage(
    State(st): State<AppState>,
    Path(app): Path<String>,
) -> Result<Json<UsageStatement>, ApiError> {
    let statement = UsageReport::new(st.metadata.clone())
        .execute(&app.into())
        .await
        .map_err(err)?;
    Ok(Json(statement))
}

// --- self-sovereign CA + naming (P3) ---

/// The pinned Root CA (PEM) an installer bakes in to trust ONLY VaultMesh.
pub async fn ca_root(State(st): State<AppState>) -> String {
    st.ca.root_pem()
}

#[derive(Deserialize)]
pub struct IssueLeafRequest {
    pub subject: String,
}

#[derive(Serialize)]
pub struct IssueLeafResponse {
    pub pem: String,
}

/// Issue a short-lived leaf cert (app/node) signed by the VaultMesh CA.
pub async fn ca_issue(
    State(st): State<AppState>,
    Json(req): Json<IssueLeafRequest>,
) -> Result<Json<IssueLeafResponse>, ApiError> {
    let bytes = st.ca.issue_leaf(&req.subject).await.map_err(err)?;
    let pem =
        String::from_utf8(bytes).map_err(|e| err(vault_ports::PortError::Crypto(e.to_string())))?;
    Ok(Json(IssueLeafResponse { pem }))
}

#[derive(Deserialize)]
pub struct PublishNameRequest {
    pub name: String,
    pub current_ip: String,
}

/// A DDNS agent publishes its current IP under a stable name (dynamic→static).
pub async fn naming_publish(
    State(st): State<AppState>,
    Json(req): Json<PublishNameRequest>,
) -> Result<(), ApiError> {
    st.naming
        .publish(&req.name, &req.current_ip)
        .await
        .map_err(err)
}

#[derive(Serialize)]
pub struct ResolveResponse {
    pub current_ip: String,
}

/// Resolve a stable VaultMesh name to its current IP.
pub async fn naming_resolve(
    State(st): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<ResolveResponse>, ApiError> {
    let current_ip = st.naming.resolve(&name).await.map_err(err)?;
    Ok(Json(ResolveResponse { current_ip }))
}
