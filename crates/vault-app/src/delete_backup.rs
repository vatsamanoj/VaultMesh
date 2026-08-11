//! Use-case: delete a blob (its shards and manifest).

use crate::guard::authorize;
use std::sync::Arc;
use vault_domain::{BlobId, CapabilityToken, NamespaceId, Operation};
use vault_ports::{AuthVerifier, BlobAnchor, Clock, MetadataStore, PortResult};

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
        authorize(
            &self.verifier,
            &self.metadata,
            &self.clock,
            namespace,
            token,
            Operation::Delete,
        )
        .await?;
        self.anchor.delete_blob(namespace, blob_id).await?;
        self.metadata.delete_manifest(namespace, blob_id).await
    }
}
