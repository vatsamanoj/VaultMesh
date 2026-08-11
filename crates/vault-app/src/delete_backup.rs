//! Use-case: delete a blob (its shards and manifest).

use crate::guard::authorize;
use std::sync::Arc;
use vault_domain::{BlobId, CapabilityToken, DomainError, NamespaceId, Operation};
use vault_ports::{AuthVerifier, BlobAnchor, Clock, MetadataStore, PortError, PortResult};

pub struct DeleteBackup {
    metadata: Arc<dyn MetadataStore>,
    anchor: Arc<dyn BlobAnchor>,
    verifier: Arc<dyn AuthVerifier>,
    clock: Arc<dyn Clock>,
}

impl DeleteBackup {
    pub fn new(
        metadata: Arc<dyn MetadataStore>,
        anchor: Arc<dyn BlobAnchor>,
        verifier: Arc<dyn AuthVerifier>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            metadata,
            anchor,
            verifier,
            clock,
        }
    }

    pub async fn execute(
        &self,
        namespace: &NamespaceId,
        token: &CapabilityToken,
        blob_id: &BlobId,
    ) -> PortResult<()> {
        let app = authorize(
            &self.verifier,
            &self.metadata,
            &self.clock,
            namespace,
            token,
            Operation::Delete,
        )
        .await?;

        // Retention hold: honor the contract's `min_days` from this blob's
        // `created_at`. Enforced server-side from the manifest timestamp — no
        // plaintext needed, so it stays zero-knowledge.
        let contract = self
            .metadata
            .get_contract(&app)
            .await?
            .ok_or(PortError::NotFound)?;
        if contract.retention.min_days > 0 {
            let manifest = self
                .metadata
                .get_manifest(namespace, blob_id)
                .await?
                .ok_or(PortError::NotFound)?;
            if !contract
                .retention
                .hold_elapsed(manifest.created_at, self.clock.now())
            {
                return Err(PortError::Domain(DomainError::RetentionHold {
                    min_days: contract.retention.min_days,
                }));
            }
        }

        self.anchor.delete_blob(namespace, blob_id).await?;
        self.metadata.delete_manifest(namespace, blob_id).await
    }
}
