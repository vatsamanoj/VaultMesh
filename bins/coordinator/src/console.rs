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

/// The single-page operator console (no external assets — CSP-safe).
pub async fn console() -> Html<&'static str> {
    Html(include_str!("console.html"))
}

#[derive(Deserialize, Default)]
pub struct EnrollRequest {
    #[serde(default)]
    pub label: String,
}

#[derive(Serialize)]
pub struct EnrollResponse {
    pub label: String,
    pub app_id: String,
    pub namespace: String,
    pub client_cert_pem: String,
    pub client_key_pem: String,
    pub ca_root_pem: String,
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

    // Sensible starter contract: 1 GiB / 10k objects, keep 3 versions ≥30 days,
    // 4-of-6 erasure. Operators can raise these later per tenant.
    let erasure = ErasureParams::new(4, 6).expect("4-of-6 is valid");
    let contract = RegisterApp::new(st.metadata.clone(), st.ids.clone())
        .execute(
            Quota::new(1 << 30, 10_000),
            RetentionPolicy::new(3, 30),
            erasure,
        )
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
    }))
}
