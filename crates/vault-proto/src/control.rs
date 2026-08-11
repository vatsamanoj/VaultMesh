//! Control-plane wire types (app/admin → coordinator).

use serde::{Deserialize, Serialize};
use vault_domain::{
    AppContract, AppId, CapabilityToken, ErasureParams, NamespaceId, Operation, Quota,
    RetentionPolicy,
};

/// Onboard an app. An admin performs this out of band.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterAppRequest {
    /// A human label for operators only; never used for auth.
    pub label: String,
    pub quota: Quota,
    pub retention: RetentionPolicy,
    pub erasure: ErasureParams,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterAppResponse {
    pub app_id: AppId,
    pub contract: AppContract,
    /// Base64 ed25519 public key an app uses to prove control of its
    /// registration (the app signing keypair's public half).
    pub app_signing_public_key_b64: String,
}

/// Allocate an opaque namespace under an app.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateNamespaceRequest {
    pub app_id: AppId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateNamespaceResponse {
    pub namespace_id: NamespaceId,
}

/// Request a short-lived capability token for one namespace + one operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IssueCapabilityRequest {
    pub app_id: AppId,
    pub namespace: NamespaceId,
    pub operation: Operation,
    /// Requested time-to-live in seconds (coordinator may clamp it).
    pub ttl_secs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IssueCapabilityResponse {
    pub token: CapabilityToken,
}

/// The coordinator's capability-verification public key, so a node-agent can
/// build its `AuthVerifier` at startup. Base64 of the 32-byte ed25519 key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoordinatorKey {
    pub public_key_b64: String,
}
