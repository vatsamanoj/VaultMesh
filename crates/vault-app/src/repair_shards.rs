//! Use-case: self-healing repair. Detect shards that are missing or corrupt on
//! the anchor and rebuild them from the surviving shards via erasure coding —
//! the "repair when nodes go dark" loop. When too few shards survive locally to
//! reconstruct, it borrows the missing ones from their peer replicas first
//! (mesh durability), then heals the anchor. This is an internal maintenance
//! operation (no capability token); a scheduler sweeps blobs periodically.

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use vault_domain::{BlobId, NamespaceId, ShardLocation};
use vault_ports::{
    BlobAnchor, Cryptographer, ErasureCoder, MetadataStore, PortError, PortResult, ShardRef,
    ShardTransport,
};

/// Outcome of a repair pass over one blob.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairReport {
    pub blob_id: BlobId,
    pub checked: usize,
    pub healthy: usize,
    pub repaired: usize,
    /// Shards still bad after the pass (0 unless the blob is unrepairable).
    pub still_bad: usize,
    /// True when fewer than `k` valid shards survive — repair is impossible.
    pub unrepairable: bool,
}

pub struct RepairShards {
    metadata: Arc<dyn MetadataStore>,
    anchor: Arc<dyn BlobAnchor>,
    erasure: Arc<dyn ErasureCoder>,
    crypto: Arc<dyn Cryptographer>,
    transport: Option<Arc<dyn ShardTransport>>,
}

impl RepairShards {
    pub fn new(
        metadata: Arc<dyn MetadataStore>,
        anchor: Arc<dyn BlobAnchor>,
        erasure: Arc<dyn ErasureCoder>,
        crypto: Arc<dyn Cryptographer>,
    ) -> Self {
        Self {
            metadata,
            anchor,
            erasure,
            crypto,
            transport: None,
        }
    }

    /// Enable the mesh: pull missing shards from peer replicas when too few
    /// survive locally to reconstruct, and re-replicate repaired shards back.
    pub fn with_mesh(mut self, transport: Arc<dyn ShardTransport>) -> Self {
        self.transport = Some(transport);
        self
    }

    /// When fewer than `k` shards survive locally, try to borrow the missing
    /// ones from their recorded peer replicas (integrity-checked) so the blob
    /// becomes reconstructable again. Returns how many slots were filled in.
    async fn backfill_from_peers(
        &self,
        namespace: &NamespaceId,
        blob_id: &BlobId,
        manifest: &vault_domain::Manifest,
        collected: &mut [Option<Vec<u8>>],
        bad: &[u16],
    ) -> usize {
        let k = manifest.erasure.k as usize;
        let mut available = collected.iter().filter(|s| s.is_some()).count();
        let Some(transport) = &self.transport else {
            return 0;
        };
        let mut filled = 0;
        for shard in &manifest.shards {
            if available >= k {
                break;
            }
            if !bad.contains(&shard.index) {
                continue;
            }
            let at = ShardRef::new(namespace.clone(), blob_id.clone(), shard.index);
            for location in &shard.locations {
                let ShardLocation::Peer(peer) = location else {
                    continue;
                };
                if let Ok(bytes) = transport.fetch_shard(peer, &at).await {
                    if self.crypto.sha256_hex(&bytes) == shard.sha256 {
                        collected[shard.index as usize] = Some(bytes);
                        available += 1;
                        filled += 1;
                        break;
                    }
                }
            }
        }
        filled
    }

    /// Inspect and repair one blob's shards on the anchor.
    pub async fn execute(
        &self,
        namespace: &NamespaceId,
        blob_id: &BlobId,
    ) -> PortResult<RepairReport> {
        let manifest = self
            .metadata
            .get_manifest(namespace, blob_id)
            .await?
            .ok_or(PortError::NotFound)?;

        // Classify each shard on the anchor: valid, or missing/corrupt.
        let mut collected: Vec<Option<Vec<u8>>> = Vec::with_capacity(manifest.shards.len());
        let mut bad: Vec<u16> = Vec::new();
        for shard in &manifest.shards {
            let at = ShardRef::new(namespace.clone(), blob_id.clone(), shard.index);
            match self.anchor.get_shard(&at).await {
                Ok(bytes) if self.crypto.sha256_hex(&bytes) == shard.sha256 => {
                    collected.push(Some(bytes));
                }
                Ok(_) | Err(PortError::NotFound) => {
                    collected.push(None);
                    bad.push(shard.index);
                }
                Err(other) => return Err(other),
            }
        }

        let checked = manifest.shards.len();
        let healthy = checked - bad.len();
        if bad.is_empty() {
            return Ok(RepairReport {
                blob_id: blob_id.clone(),
                checked,
                healthy,
                repaired: 0,
                still_bad: 0,
                unrepairable: false,
            });
        }

        // Need at least k valid shards to reconstruct. If too few survive
        // locally, borrow the missing ones from peer replicas (mesh durability).
        if !manifest.is_reconstructable(healthy) {
            self.backfill_from_peers(namespace, blob_id, &manifest, &mut collected, &bad)
                .await;
        }
        let available = collected.iter().filter(|s| s.is_some()).count();
        if !manifest.is_reconstructable(available) {
            return Ok(RepairReport {
                blob_id: blob_id.clone(),
                checked,
                healthy,
                repaired: 0,
                still_bad: bad.len(),
                unrepairable: true,
            });
        }

        // Reconstruct the blob, then deterministically re-encode and rewrite the
        // bad shards (RS encode is deterministic, so hashes match the manifest).
        let data = self.erasure.decode(
            &collected,
            manifest.erasure,
            manifest.ciphertext_len as usize,
        )?;
        let fresh = self.erasure.encode(&data, manifest.erasure)?;

        let mut repaired = 0usize;
        for shard in &manifest.shards {
            if !bad.contains(&shard.index) {
                continue;
            }
            let bytes = &fresh[shard.index as usize];
            let at = ShardRef::new(namespace.clone(), blob_id.clone(), shard.index);
            self.anchor.put_shard(&at, bytes).await?;
            self.re_replicate(&at, bytes, shard).await;
            repaired += 1;
        }

        Ok(RepairReport {
            blob_id: blob_id.clone(),
            checked,
            healthy: healthy + repaired,
            repaired,
            still_bad: 0,
            unrepairable: false,
        })
    }

    async fn re_replicate(&self, at: &ShardRef, bytes: &[u8], shard: &vault_domain::Shard) {
        let Some(transport) = &self.transport else {
            return;
        };
        for location in &shard.locations {
            if let ShardLocation::Peer(peer) = location {
                let _ = transport.send_shard(peer, at, bytes).await;
            }
        }
    }
}
