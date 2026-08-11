//! Use-case: issue a short-lived, scoped capability token.

use std::sync::Arc;
use vault_domain::{AppId, CapabilityClaims, CapabilityToken, NamespaceId, Operation};
use vault_ports::{CapabilitySigner, Clock, IdSource, MetadataStore, PortError, PortResult};

/// Upper bound on token lifetime — tokens are meant to be minutes-valid.
pub const MAX_TOKEN_TTL_SECS: u64 = 15 * 60;

pub struct IssueCapability {
    metadata: Arc<dyn MetadataStore>,
    signer: Arc<dyn CapabilitySigner>,
    ids: Arc<dyn IdSource>,
    clock: Arc<dyn Clock>,
}

impl IssueCapability {
    pub fn new(
        metadata: Arc<dyn MetadataStore>,
        signer: Arc<dyn CapabilitySigner>,
        ids: Arc<dyn IdSource>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            metadata,
            signer,
            ids,
            clock,
        }
    }

    /// Issue a token only to the app that owns `namespace`, scoped to one
    /// operation, with a clamped TTL and a fresh single-use nonce.
    pub async fn execute(
        &self,
        app_id: &AppId,
        namespace: &NamespaceId,
        operation: Operation,
        ttl_secs: u64,
    ) -> PortResult<CapabilityToken> {
        // Pre-issue ownership check (L3 at the source).
        let ns = self
            .metadata
            .get_namespace(namespace)
            .await?
            .ok_or(PortError::NotFound)?;
        if !ns.owned_by(app_id) {
            return Err(PortError::Domain(vault_domain::DomainError::Unauthorized));
        }

        let ttl = ttl_secs.clamp(1, MAX_TOKEN_TTL_SECS);
        let expires_at = self.clock.now().plus_secs(ttl);
        let claims = CapabilityClaims::new(
            app_id.clone(),
            namespace.clone(),
            operation,
            self.ids.new_nonce(),
            expires_at,
        );
        self.signer.sign(claims)
    }
}
