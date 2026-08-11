//! Use-case: reconstruct and return one blob's ciphertext (node-agent).

use crate::guard::authorize;
use std::sync::Arc;
use vault_domain::{BlobId, CapabilityToken, NamespaceId, Operation, Shard, ShardLocation};
use vault_ports::{
    AuthVerifier, BlobAnchor, Clock, Cryptographer, ErasureCoder, MetadataStore, PortError,
    PortResult, ShardRef, ShardTransport,
};

pub struct GetBackup {
    metadata: Arc<dyn MetadataStore>,
    anchor: Arc<dyn BlobAnchor>,
    erasure: Arc<dyn ErasureCoder>,
    crypto: Arc<dyn Cryptographer>,
    verifier: Arc<dyn AuthVerifier>,
    clock: Arc<dyn Clock>,
    transport: Option<Arc<dyn ShardTransport>>,
}

/// Result of a restore, including how degraded the blob was on read — so the
/// caller can heal it proactively (reactive repair) before further loss pushes
/// it below `k`.
pub struct RestoreOutcome {
    pub ciphertext: Vec<u8>,
    pub shards_total: usize,
    pub shards_missing: usize,
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
            transport: None,
        }
    }

    /// Enable P2 peer-preferred reads: try a shard's peer replicas first, fall
    /// back to the authoritative anchor.
    pub fn with_mesh(mut self, transport: Arc<dyn ShardTransport>) -> Self {
        self.transport = Some(transport);
        self
    }

    /// Returns the byte-identical ciphertext originally stored. The caller
    /// (app) decrypts it with its own key.
    pub async fn execute(
        &self,
        namespace: &NamespaceId,
        token: &CapabilityToken,
        blob_id: &BlobId,
    ) -> PortResult<Vec<u8>> {
        Ok(self.restore(namespace, token, blob_id).await?.ciphertext)
    }

    /// Like [`Self::execute`], but also reports how many shards were missing on
    /// read so the caller can trigger reactive repair when the blob is degraded.
    pub async fn restore(
        &self,
        namespace: &NamespaceId,
        token: &CapabilityToken,
        blob_id: &BlobId,
    ) -> PortResult<RestoreOutcome> {
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

        // For each shard: prefer a peer replica (locality/speed), fall back to
        // the anchor. Verify SHA-256; a corrupted or absent shard becomes an
        // erasure (`None`) so Reed-Solomon reconstructs around it, up to the
        // parity budget. Restore fails only if fewer than `k` valid shards remain.
        let mut collected: Vec<Option<Vec<u8>>> = Vec::with_capacity(manifest.shards.len());
        let mut available = 0usize;
        for shard in &manifest.shards {
            let at = ShardRef::new(namespace.clone(), blob_id.clone(), shard.index);
            match self.load_shard(&at, shard).await {
                Some(bytes) => {
                    available += 1;
                    collected.push(Some(bytes));
                }
                None => collected.push(None),
            }
        }

        let total = manifest.shards.len();
        if !manifest.is_reconstructable(available) {
            return Err(PortError::Unavailable(format!(
                "only {available} valid of {total} shards (need k={})",
                manifest.erasure.k
            )));
        }

        let ciphertext = self.erasure.decode(
            &collected,
            manifest.erasure,
            manifest.ciphertext_len as usize,
        )?;
        Ok(RestoreOutcome {
            ciphertext,
            shards_total: total,
            shards_missing: total - available,
        })
    }

    /// Load one shard, preferring peers, then the anchor. Returns the verified
    /// bytes, or `None` if no source yields an integrity-valid copy.
    async fn load_shard(&self, at: &ShardRef, shard: &Shard) -> Option<Vec<u8>> {
        if let Some(transport) = &self.transport {
            for location in &shard.locations {
                if let ShardLocation::Peer(peer) = location {
                    if let Ok(bytes) = transport.fetch_shard(peer, at).await {
                        if self.crypto.sha256_hex(&bytes) == shard.sha256 {
                            return Some(bytes);
                        }
                    }
                }
            }
        }
        // Authoritative fallback.
        match self.anchor.get_shard(at).await {
            Ok(bytes) if self.crypto.sha256_hex(&bytes) == shard.sha256 => Some(bytes),
            _ => None,
        }
    }
}
