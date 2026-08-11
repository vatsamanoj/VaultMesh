//! Use-case: list the opaque blob ids in a namespace.

use crate::guard::authorize;
use std::sync::Arc;
use vault_domain::{BlobId, CapabilityToken, NamespaceId, Operation};
use vault_ports::{AuthVerifier, Clock, MetadataStore, PortResult};

pub struct ListBackups {
    metadata: Arc<dyn MetadataStore>,
    verifier: Arc<dyn AuthVerifier>,
    clock: Arc<dyn Clock>,
}

impl ListBackups {
    pub fn new(
        metadata: Arc<dyn MetadataStore>,
        verifier: Arc<dyn AuthVerifier>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            metadata,
            verifier,
            clock,
        }
    }

    pub async fn execute(
        &self,
        namespace: &NamespaceId,
        token: &CapabilityToken,
    ) -> PortResult<Vec<BlobId>> {
        authorize(
            &self.verifier,
            &self.metadata,
            &self.clock,
            namespace,
            token,
            Operation::List,
        )
        .await?;
        self.metadata.list_blobs(namespace).await
    }
}
