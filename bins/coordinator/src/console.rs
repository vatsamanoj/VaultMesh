//! Operator console: a self-contained web UI (served at `/`) plus a one-shot
//! node-enrollment endpoint. Enrollment registers an app, allocates a
//! namespace, and issues a CA-signed mTLS client identity — everything a new
//! node-agent needs to join — in a single call. Intended for the admin plane
//! (bind it to the overlay / localhost, not the public data plane).

use crate::http::{err, ApiError};
use crate::state::AppState;
use axum::extract::State;
use axum::response::Html;
use axum::Json;
use serde::{Deserialize, Serialize};
use vault_app::{CreateNamespace, RegisterApp};
use vault_domain::{ErasureParams, Quota, RetentionPolicy};
use vault_ports::PortError;

/// The single-page operator console (no external assets — CSP-safe).
pub async fn console() -> Html<&'static str> {
    Html(include_str!("console.html"))
}

#[derive(Deserialize, Default)]
pub struct EnrollRequest {
    #[serde(default)]
    pub label: String,
    // Optional Contract terms — sensible defaults apply when omitted.
    #[serde(default)]
    pub quota_bytes: Option<u64>,
    #[serde(default)]
    pub max_objects: Option<u64>,
    #[serde(default)]
    pub keep_versions: Option<u32>,
    #[serde(default)]
    pub min_days: Option<u32>,
    #[serde(default)]
    pub erasure_k: Option<u8>,
    #[serde(default)]
    pub erasure_n: Option<u8>,
}

#[derive(Serialize)]
pub struct EnrollResponse {
    pub label: String,
    pub app_id: String,
    pub namespace: String,
    pub client_cert_pem: String,
    pub client_key_pem: String,
    pub ca_root_pem: String,
    // The effective Contract terms (after defaults), echoed for the UI.
    pub quota_bytes: u64,
    pub max_objects: u64,
    pub keep_versions: u32,
    pub min_days: u32,
    pub erasure_k: u8,
    pub erasure_n: u8,
}

/// Register an app + namespace and mint an mTLS client identity for a new node.
pub async fn enroll(
    State(st): State<AppState>,
    Json(req): Json<EnrollRequest>,
) -> Result<Json<EnrollResponse>, ApiError> {
    let label = match req.label.trim() {
        "" => "node".to_string(),
        s => s.to_string(),
    };

    // Contract terms from the request, with sensible defaults: 1 GiB / 10k
    // objects, keep 3 versions ≥30 days, 4-of-6 erasure. Invalid erasure (k=0
    // or n<k) is rejected as a 400.
    let quota = Quota::new(
        req.quota_bytes.unwrap_or(1 << 30),
        req.max_objects.unwrap_or(10_000),
    );
    let retention =
        RetentionPolicy::new(req.keep_versions.unwrap_or(3), req.min_days.unwrap_or(30));
    let erasure = ErasureParams::new(req.erasure_k.unwrap_or(4), req.erasure_n.unwrap_or(6))
        .map_err(|e| err(PortError::Domain(e)))?;
    let contract = RegisterApp::new(st.metadata.clone(), st.ids.clone())
        .execute(quota, retention, erasure)
        .await
        .map_err(err)?;
    let ns = CreateNamespace::new(st.metadata.clone(), st.ids.clone())
        .execute(&contract.app_id)
        .await
        .map_err(err)?;
    let identity = st.ca.issue_client(&label).map_err(err)?;

    Ok(Json(EnrollResponse {
        label,
        app_id: contract.app_id.to_string(),
        namespace: ns.id.to_string(),
        client_cert_pem: identity.cert_pem,
        client_key_pem: identity.key_pem,
        ca_root_pem: st.ca.root_pem(),
        quota_bytes: contract.quota.max_bytes,
        max_objects: contract.quota.max_objects,
        keep_versions: contract.retention.keep_versions,
        min_days: contract.retention.min_days,
        erasure_k: contract.erasure.k,
        erasure_n: contract.erasure.n,
    }))
}
