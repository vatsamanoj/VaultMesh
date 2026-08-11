//! The QUIC client side: dial peers and send/fetch shards. Implements the
//! `ShardTransport` port, so the use-cases don't change when swapping the P2
//! HTTP mesh for direct QUIC.

use crate::tls::client_config;
use crate::wire::{self, MAX_FRAME, OP_GET, OP_PUT, ST_NOT_FOUND, ST_OK};
use async_trait::async_trait;
use quinn::Endpoint;
use std::net::SocketAddr;
use vault_ports::{PortError, PortResult, ShardRef, ShardTransport};

/// A reusable QUIC client endpoint. Peer addresses are `IP:port`.
#[derive(Clone)]
pub struct QuicShardTransport {
    endpoint: Endpoint,
}

fn backend(e: impl std::fmt::Display) -> PortError {
    PortError::Unavailable(format!("quic: {e}"))
}

impl QuicShardTransport {
    pub fn new() -> PortResult<Self> {
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())
            .map_err(|e| PortError::Backend(format!("quic client endpoint: {e}")))?;
        endpoint.set_default_client_config(
            client_config().map_err(|e| PortError::Backend(format!("quic tls: {e}")))?,
        );
        Ok(Self { endpoint })
    }

    async fn round_trip(&self, peer: &str, request: &[u8]) -> PortResult<Vec<u8>> {
        let addr: SocketAddr = peer
            .parse()
            .map_err(|_| PortError::Backend(format!("bad peer address: {peer}")))?;
        let conn = self
            .endpoint
            .connect(addr, "vaultmesh-node")
            .map_err(backend)?
            .await
            .map_err(backend)?;
        let (mut send, mut recv) = conn.open_bi().await.map_err(backend)?;
        send.write_all(request).await.map_err(backend)?;
        send.finish().map_err(backend)?;
        let resp = recv.read_to_end(MAX_FRAME).await.map_err(backend)?;
        conn.close(0u32.into(), b"done");
        Ok(resp)
    }
}

#[async_trait]
impl ShardTransport for QuicShardTransport {
    async fn send_shard(&self, peer: &str, at: &ShardRef, bytes: &[u8]) -> PortResult<()> {
        let req = wire::encode_request(OP_PUT, &wire::shard_key(at), bytes);
        let resp = self.round_trip(peer, &req).await?;
        match resp.first() {
            Some(&ST_OK) => Ok(()),
            _ => Err(PortError::Backend(format!("peer {peer} rejected put"))),
        }
    }

    async fn fetch_shard(&self, peer: &str, at: &ShardRef) -> PortResult<Vec<u8>> {
        let req = wire::encode_request(OP_GET, &wire::shard_key(at), &[]);
        let resp = self.round_trip(peer, &req).await?;
        match resp.first() {
            Some(&ST_OK) => Ok(resp[1..].to_vec()),
            Some(&ST_NOT_FOUND) => Err(PortError::NotFound),
            _ => Err(PortError::Backend(format!("peer {peer} error"))),
        }
    }
}
