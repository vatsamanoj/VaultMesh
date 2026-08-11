//! Use-case: reconstruct and return one blob's ciphertext (node-agent).

use crate::guard::authorize;
use std::sync::Arc;
use vault_domain::{BlobId, CapabilityToken, NamespaceId, Operation};
use vault_ports::{
    AuthVerifier, BlobAnchor, Clock, Cryptographer, ErasureCoder, MetadataStore, PortError,
    PortResult, ShardRef,
};

pub struct GetBackup {
    metadata: Arc<dyn MetadataStore>,
    anchor: Arc<dyn BlobAnchor>,
    erasure: Arc<dyn ErasureCoder>,
    crypto: Arc<dyn Cryptographer>,
    verifier: Arc<dyn AuthVerifier>,
    clock: Arc<dyn Clock>,
}

impl GetBackup {
    pub fn new(
        metadata: Arc<dyn MetadataStore>,
        anchor: Arc<dyn BlobAnchor>,
        erasure: Arc<dyn ErasureCoder>,
        crypto: Arc<dyn Cryptographer>,
        verifier: Arc<dyn AuthVerifier>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            metadata,
            anchor,
            erasure,
            crypto,
            verifier,
            clock,
        }
    }

    /// Returns the byte-identical ciphertext originally stored. The caller
    /// (app) decrypts it with its own key.
    pub async fn execute(
        &self,
        namespace: &NamespaceId,
        token: &CapabilityToken,
        blob_id: &BlobId,
    ) -> PortResult<Vec<u8>> {
        authorize(
            &self.verifier,
            &self.metadata,
            &self.clock,
            namespace,
            token,
            Operation::Get,
        )
        .await?;

        let manifest = self
            .metadata
            .get_manifest(namespace, blob_id)
            .await?
            .ok_or(PortError::NotFound)?;

        // Fetch shards; a missing one becomes `None`. Verify integrity of each
        // shard we do get before trusting it (per-shard SHA-256).
        let mut collected: Vec<Option<Vec<u8>>> = Vec::with_capacity(manifest.shards.len());
        let mut available = 0usize;
        for shard in &manifest.shards {
            let at = ShardRef::new(namespace.clone(), blob_id.clone(), shard.index);
            match self.anchor.get_shard(&at).await {
                Ok(bytes) => {
                    if self.crypto.sha256_hex(&bytes) != shard.sha256 {
                        return Err(PortError::Integrity(format!(
                            "shard {} failed SHA-256 verification",
                            shard.index
                        )));
                    }
                    available += 1;
                    collected.push(Some(bytes));
                }
                Err(PortError::NotFound) => collected.push(None),
                Err(other) => return Err(other),
            }
        }

        if !manifest.is_reconstructable(available) {
            return Err(PortError::Unavailable(format!(
                "only {available} of {} shards available (need k={})",
                manifest.shards.len(),
                manifest.erasure.k
            )));
        }

        self.erasure.decode(
            &collected,
            manifest.erasure,
            manifest.ciphertext_len as usize,
        )
    }
}
