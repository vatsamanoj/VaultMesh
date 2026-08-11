//! Shared authorization guard for data-plane use-cases. Enforces the full L2+L3
//! check: token signature, scope/freshness, and namespace ownership.

use std::sync::Arc;
use vault_domain::{AppId, CapabilityToken, DomainError, NamespaceId, Operation};
use vault_ports::{AuthVerifier, Clock, MetadataStore, PortError, PortResult};

/// Verify a capability token for `operation` on `namespace` and return the
/// authenticated `AppId`. Fails closed on any check.
pub(crate) async fn authorize(
    verifier: &Arc<dyn AuthVerifier>,
    metadata: &Arc<dyn MetadataStore>,
    clock: &Arc<dyn Clock>,
    namespace: &NamespaceId,
    token: &CapabilityToken,
    operation: Operation,
) -> PortResult<AppId> {
    // L2a: signature must verify against the coordinator key.
    verifier.verify_signature(token)?;

    // L2b: scope + freshness (expiry, namespace, operation).
    let app = token.claims.app_id.clone();
    token.authorize(&app, namespace, operation, clock.now())?;

    // L3: the cert/token's app must actually own this namespace.
    let ns = metadata
        .get_namespace(namespace)
        .await?
        .ok_or(PortError::NotFound)?;
    if !ns.owned_by(&app) {
        return Err(PortError::Domain(DomainError::Unauthorized));
    }
    Ok(app)
}
