//! Ports for later phases, declared now so the domain and use-cases stay stable
//! while adapters land phase by phase. No P0 adapter implements these yet.

use crate::error::PortResult;
use crate::storage::ShardRef;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use vault_domain::{BlobId, NamespaceId};

/// P2 — peer mesh shard transport. Replicate/serve shards between node-agents
/// for speed and locality; the RustFS anchor is always the authoritative
/// fallback, so a peer transport is a pure accelerator.
#[async_trait]
pub trait ShardTransport: Send + Sync {
    /// Best-effort push of a shard replica to `peer` (a dialable peer address).
    async fn send_shard(&self, peer: &str, at: &ShardRef, bytes: &[u8]) -> PortResult<()>;
    /// Fetch a shard replica from `peer`; `PortError::NotFound` if absent.
    async fn fetch_shard(&self, peer: &str, at: &ShardRef) -> PortResult<Vec<u8>>;
}

/// P3 — self-hosted naming: stable VaultMesh name -> current IP (the
/// dynamic→static mechanism). Implemented by `adapter-ddns`.
#[async_trait]
pub trait NameResolver: Send + Sync {
    async fn resolve(&self, stable_name: &str) -> PortResult<String>;
    async fn publish(&self, stable_name: &str, current_ip: &str) -> PortResult<()>;
}

/// P2 — self-hosted NAT traversal: hole-punch, or fall back to coordinator
/// relay of the (still encrypted) shard.
#[async_trait]
pub trait NatBroker: Send + Sync {
    async fn punch(&self, peer: &str) -> PortResult<Option<String>>;
    async fn relay(&self, peer: &str, key: &str, bytes: &[u8]) -> PortResult<()>;
}

/// P3 — self-signed CA: issue/rotate/revoke certs. Implemented by
/// `adapter-rcgen-ca`.
#[async_trait]
pub trait CertAuthority: Send + Sync {
    async fn issue_leaf(&self, subject: &str) -> PortResult<Vec<u8>>;
    async fn revoke(&self, serial: &str) -> PortResult<()>;
    async fn is_revoked(&self, serial: &str) -> PortResult<bool>;
}

/// The escalating response to a caller. See `docs/SECURITY.md`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatDecision {
    Allow,
    Tarpit,
    Block,
}

/// P3 — active perimeter: classify a caller and decide allow / tarpit / block.
pub trait ThreatResponder: Send + Sync {
    fn assess(&self, signal_fingerprint: &str, attack_class: &str) -> ThreatDecision;
}

/// One footprint appended to the tamper-evident intrusion ledger.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntrusionRecord {
    pub source_ip: String,
    pub ja3: Option<String>,
    pub attack_class: String,
    pub rejection_reason: String,
    pub at_millis: u64,
}

/// P3 — append-only, tamper-evident sink for intrusion footprints, plus a hook
/// for mesh-wide blocklist propagation.
#[async_trait]
pub trait IntrusionSink: Send + Sync {
    async fn record(&self, entry: IntrusionRecord) -> PortResult<()>;
    async fn note_unauthorized_shard_access(
        &self,
        namespace: &NamespaceId,
        blob_id: &BlobId,
    ) -> PortResult<()>;
}
