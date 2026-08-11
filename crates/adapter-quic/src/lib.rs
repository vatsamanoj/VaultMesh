//! P4 direct peer-to-peer transport over **QUIC** (via `quinn`).
//!
//! Node-agents transfer shards directly to one another, dropping the
//! coordinator-relayed hop of the P2 HTTP mesh when a direct path exists. The
//! link runs over VaultMesh's own self-signed, pinned trust (no public CA), and
//! peer↔peer shard transfers are end-to-end encrypted — TLS 1.3 with forward
//! secrecy, per the "prying eyes" model in `docs/SECURITY.md`.
//!
//! - [`QuicShardTransport`] implements the `ShardTransport` port (dial peers,
//!   `send_shard`/`fetch_shard`).
//! - [`QuicShardServer`] serves shard requests from a local `BlobAnchor`.
//! - [`DirectNatBroker`] implements `NatBroker`: attempt a direct connection
//!   ("punch"); the coordinator relay is the always-works fallback.
//!
//! Certificate verification here trusts the overlay (accept-any); a production
//! deployment pins the VaultMesh root (`adapter-rcgen-ca`) instead — the wire
//! protocol and API are identical.

mod nat;
mod server;
mod tls;
mod transport;
mod wire;

pub use nat::DirectNatBroker;
pub use server::QuicShardServer;
pub use transport::QuicShardTransport;
