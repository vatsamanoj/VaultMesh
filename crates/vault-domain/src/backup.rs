//! Backup entities: shards, manifests, and the stored object.

use crate::capability::Timestamp;
use crate::contract::ErasureParams;
use crate::ids::{BlobId, NamespaceId};
use serde::{Deserialize, Serialize};

/// Where a shard physically lives.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShardLocation {
    /// The always-on authoritative anchor (RustFS). Present for every shard.
    Anchor,
    /// A peer node-agent holding a replica for locality/speed (P2+).
    Peer(String),
}

/// Metadata for one shard of a blob. The `sha256` is a hex digest used for
/// integrity verification on restore; tampering is caught before reassembly.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Shard {
    pub index: u16,
    /// Hex-encoded SHA-256 of the (padded) shard bytes.
    pub sha256: String,
    /// Fixed, padded shard size in bytes — uniform so sizes don't leak.
    pub size: u32,
    pub locations: Vec<ShardLocation>,
}

impl Shard {
    pub fn new(index: u16, sha256: impl Into<String>, size: u32) -> Self {
        Self {
            index,
            sha256: sha256.into(),
            size,
            locations: vec![ShardLocation::Anchor],
        }
    }
}

/// The manifest records everything needed to reconstruct a blob: its erasure
/// parameters and the shard -> location map. Manifests are encrypted at rest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub blob_id: BlobId,
    pub namespace: NamespaceId,
    pub erasure: ErasureParams,
    pub shards: Vec<Shard>,
    /// Total ciphertext length before sharding.
    pub ciphertext_len: u64,
    pub created_at: Timestamp,
}

impl Manifest {
    pub fn new(
        blob_id: BlobId,
        namespace: NamespaceId,
        erasure: ErasureParams,
        shards: Vec<Shard>,
        ciphertext_len: u64,
        created_at: Timestamp,
    ) -> Self {
        Self {
            blob_id,
            namespace,
            erasure,
            shards,
            ciphertext_len,
            created_at,
        }
    }

    /// Whether enough shards survive to reconstruct: at least `k` present.
    pub fn is_reconstructable(&self, available: usize) -> bool {
        available >= self.erasure.k as usize
    }
}

/// A stored backup object as the app sees it: an opaque id + its size.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupObject {
    pub blob_id: BlobId,
    pub namespace: NamespaceId,
    pub ciphertext_len: u64,
}

impl BackupObject {
    pub fn new(blob_id: BlobId, namespace: NamespaceId, ciphertext_len: u64) -> Self {
        Self {
            blob_id,
            namespace,
            ciphertext_len,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconstructable_needs_k_shards() {
        let m = Manifest::new(
            BlobId::new("b1"),
            NamespaceId::new("ns1"),
            ErasureParams::new(3, 5).unwrap(),
            vec![],
            100,
            Timestamp::from_millis(1),
        );
        assert!(!m.is_reconstructable(2));
        assert!(m.is_reconstructable(3));
        assert!(m.is_reconstructable(5));
    }
}
