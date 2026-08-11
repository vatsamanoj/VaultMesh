//! VaultMesh ports: the narrow, role-specific traits (ISP) that the use-cases
//! in `vault-app` depend on. The domain core depends on *these*, never on a
//! concrete adapter (DIP), so storage/transport/crypto are swappable.
//!
//! Ports for later phases (`ShardTransport`, `NameResolver`, `NatBroker`,
//! `CertAuthority`, `ThreatResponder`, `IntrusionSink`) are declared now so the
//! domain and use-cases stay stable while adapters land phase by phase.

mod crypto;
mod error;
mod future_ports;
mod storage;
mod time;

pub use crypto::{AuthVerifier, CapabilitySigner, Cryptographer, ErasureCoder, CONTENT_KEY_LEN};
pub use error::{PortError, PortResult};
pub use future_ports::{
    CertAuthority, IntrusionRecord, IntrusionSink, NameResolver, NatBroker, ShardTransport,
    ThreatDecision, ThreatResponder,
};
pub use storage::{BlobAnchor, MetadataStore, NamespaceUsage, ShardRef};
pub use time::{Clock, IdSource};
