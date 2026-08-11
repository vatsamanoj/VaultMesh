//! Self-hosted NAT traversal. `punch` attempts a direct QUIC connection; if a
//! NAT won't allow it, the coordinator relays the (still-encrypted) shard — the
//! always-works fallback. No external STUN/TURN.

use crate::tls::client_config;
use async_trait::async_trait;
use quinn::Endpoint;
use std::net::SocketAddr;
use vault_ports::{NatBroker, PortError, PortResult};

pub struct DirectNatBroker {
    endpoint: Endpoint,
}

impl DirectNatBroker {
    pub fn new() -> PortResult<Self> {
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())
            .map_err(|e| PortError::Backend(format!("quic client endpoint: {e}")))?;
        endpoint.set_default_client_config(
            client_config().map_err(|e| PortError::Backend(format!("quic tls: {e}")))?,
        );
        Ok(Self { endpoint })
    }
}

#[async_trait]
impl NatBroker for DirectNatBroker {
    /// Try a direct connection. `Some(addr)` if a direct path exists, else
    /// `None` (the caller should fall back to relay).
    async fn punch(&self, peer: &str) -> PortResult<Option<String>> {
        let Ok(addr) = peer.parse::<SocketAddr>() else {
            return Ok(None);
        };
        match self.endpoint.connect(addr, "vaultmesh-node") {
            Ok(connecting) => match connecting.await {
                Ok(conn) => {
                    conn.close(0u32.into(), b"punch-ok");
                    Ok(Some(peer.to_string()))
                }
                Err(_) => Ok(None),
            },
            Err(_) => Ok(None),
        }
    }

    /// The coordinator relay path (configured elsewhere). Declared here so the
    /// port is complete; the direct transport covers the common case.
    async fn relay(&self, _peer: &str, _key: &str, _bytes: &[u8]) -> PortResult<()> {
        Err(PortError::Unavailable(
            "direct punch failed; use the coordinator relay path".into(),
        ))
    }
}
