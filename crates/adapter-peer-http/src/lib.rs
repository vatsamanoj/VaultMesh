//! P2 peer-mesh shard transport over HTTP.
//!
//! A node-agent replicates shards to, and fetches shards from, its peers'
//! `/v1/peer/shards/{namespace}/{blob}/{index}` endpoints. This is a pure
//! **accelerator**: every shard also lives on the authoritative RustFS anchor,
//! so a peer being unreachable never blocks a restore — the use-case falls back
//! to the anchor.
//!
//! P4 may replace this HTTP transport with direct QUIC (hole-punching /
//! coordinator relay) behind the same `ShardTransport` port; the use-cases do
//! not change.

use async_trait::async_trait;
use reqwest::{Client, StatusCode};
use vault_ports::{PortError, PortResult, ShardRef, ShardTransport};

/// Talks to peers over HTTP. `peer` addresses are dialable base URLs, e.g.
/// `http://10.0.0.4:8790`.
#[derive(Clone, Default)]
pub struct PeerHttpTransport {
    http: Client,
}

impl PeerHttpTransport {
    pub fn new() -> Self {
        Self {
            http: Client::new(),
        }
    }

    fn url(peer: &str, at: &ShardRef) -> String {
        format!(
            "{}/v1/peer/shards/{}/{}/{:05}",
            peer.trim_end_matches('/'),
            at.namespace,
            at.blob_id,
            at.index
        )
    }
}

#[async_trait]
impl ShardTransport for PeerHttpTransport {
    async fn send_shard(&self, peer: &str, at: &ShardRef, bytes: &[u8]) -> PortResult<()> {
        let resp = self
            .http
            .put(Self::url(peer, at))
            .body(bytes.to_vec())
            .send()
            .await
            .map_err(|e| PortError::Unavailable(format!("peer {peer}: {e}")))?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(PortError::Backend(format!(
                "peer {peer} returned {}",
                resp.status()
            )))
        }
    }

    async fn fetch_shard(&self, peer: &str, at: &ShardRef) -> PortResult<Vec<u8>> {
        let resp = self
            .http
            .get(Self::url(peer, at))
            .send()
            .await
            .map_err(|e| PortError::Unavailable(format!("peer {peer}: {e}")))?;
        match resp.status() {
            s if s.is_success() => resp
                .bytes()
                .await
                .map(|b| b.to_vec())
                .map_err(|e| PortError::Unavailable(format!("peer {peer}: {e}"))),
            StatusCode::NOT_FOUND => Err(PortError::NotFound),
            other => Err(PortError::Backend(format!("peer {peer} returned {other}"))),
        }
    }
}
