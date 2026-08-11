//! The QUIC server side: accept peer connections and serve shard requests from
//! a local `BlobAnchor`. A shard is opaque, fixed-size erasure-coded ciphertext,
//! so a peer holding it learns nothing.

use crate::tls::server_config;
use crate::wire::{self, MAX_FRAME, OP_GET, OP_PUT, ST_ERR, ST_NOT_FOUND, ST_OK};
use quinn::{Endpoint, Incoming};
use std::net::SocketAddr;
use std::sync::Arc;
use vault_ports::{BlobAnchor, PortError};

/// A QUIC endpoint that serves shard get/put for peers.
pub struct QuicShardServer {
    endpoint: Endpoint,
    anchor: Arc<dyn BlobAnchor>,
}

impl QuicShardServer {
    /// Bind a server on `addr` (use port 0 for an ephemeral port).
    pub fn bind(anchor: Arc<dyn BlobAnchor>, addr: SocketAddr) -> Result<Self, PortError> {
        let cfg = server_config().map_err(|e| PortError::Backend(format!("quic tls: {e}")))?;
        let endpoint = Endpoint::server(cfg, addr)
            .map_err(|e| PortError::Backend(format!("quic server endpoint: {e}")))?;
        Ok(Self { endpoint, anchor })
    }

    /// The bound local address (useful after binding to port 0).
    pub fn local_addr(&self) -> Result<SocketAddr, PortError> {
        self.endpoint
            .local_addr()
            .map_err(|e| PortError::Backend(e.to_string()))
    }

    /// Accept connections forever, serving each on its own task.
    pub async fn run(self) {
        while let Some(incoming) = self.endpoint.accept().await {
            let anchor = self.anchor.clone();
            tokio::spawn(handle_conn(anchor, incoming));
        }
    }
}

async fn handle_conn(anchor: Arc<dyn BlobAnchor>, incoming: Incoming) {
    let connection = match incoming.await {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!(error = %e, "quic: connection failed");
            return;
        }
    };
    while let Ok((send, recv)) = connection.accept_bi().await {
        let anchor = anchor.clone();
        tokio::spawn(handle_stream(anchor, send, recv));
    }
}

async fn handle_stream(
    anchor: Arc<dyn BlobAnchor>,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) {
    let resp = match recv.read_to_end(MAX_FRAME).await {
        Ok(buf) => serve(&anchor, &buf).await,
        Err(_) => wire::encode_response(ST_ERR, &[]),
    };
    let _ = send.write_all(&resp).await;
    let _ = send.finish();
}

async fn serve(anchor: &Arc<dyn BlobAnchor>, buf: &[u8]) -> Vec<u8> {
    let Some((op, key, payload)) = wire::parse_request(buf) else {
        return wire::encode_response(ST_ERR, &[]);
    };
    let Some(at) = wire::parse_key(&key) else {
        return wire::encode_response(ST_ERR, &[]);
    };
    match op {
        OP_GET => match anchor.get_shard(&at).await {
            Ok(bytes) => wire::encode_response(ST_OK, &bytes),
            Err(PortError::NotFound) => wire::encode_response(ST_NOT_FOUND, &[]),
            Err(_) => wire::encode_response(ST_ERR, &[]),
        },
        OP_PUT => match anchor.put_shard(&at, &payload).await {
            Ok(()) => wire::encode_response(ST_OK, &[]),
            Err(_) => wire::encode_response(ST_ERR, &[]),
        },
        _ => wire::encode_response(ST_ERR, &[]),
    }
}
