//! P4 loopback drill: a real QUIC round-trip between a shard server and the
//! transport, proving direct peer-to-peer shard transfer works end to end.

use std::sync::Arc;

use adapter_blob_fs::FsBlobAnchor;
use adapter_quic::{DirectNatBroker, QuicShardServer, QuicShardTransport};
use vault_domain::{BlobId, NamespaceId};
use vault_ports::{BlobAnchor, NatBroker, PortError, ShardRef, ShardTransport};

async fn start_server() -> (String, Arc<dyn BlobAnchor>, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let anchor: Arc<dyn BlobAnchor> = Arc::new(FsBlobAnchor::new(tmp.path()));
    let server = QuicShardServer::bind(anchor.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.run());
    (format!("127.0.0.1:{}", addr.port()), anchor, tmp)
}

#[tokio::test]
async fn quic_put_then_fetch_round_trips() {
    let (peer, anchor, _tmp) = start_server().await;
    let transport = QuicShardTransport::new().unwrap();
    let at = ShardRef::new(NamespaceId::new("ns1"), BlobId::new("b1"), 2);

    // PUT a shard to the peer over QUIC, then GET it back.
    transport
        .send_shard(&peer, &at, b"opaque-shard-bytes")
        .await
        .unwrap();
    let got = transport.fetch_shard(&peer, &at).await.unwrap();
    assert_eq!(got, b"opaque-shard-bytes");

    // The peer's anchor really holds it.
    assert_eq!(anchor.get_shard(&at).await.unwrap(), b"opaque-shard-bytes");
}

#[tokio::test]
async fn quic_fetch_missing_is_not_found() {
    let (peer, _anchor, _tmp) = start_server().await;
    let transport = QuicShardTransport::new().unwrap();
    let at = ShardRef::new(NamespaceId::new("ns"), BlobId::new("nope"), 0);
    assert!(matches!(
        transport.fetch_shard(&peer, &at).await,
        Err(PortError::NotFound)
    ));
}

#[tokio::test]
async fn nat_broker_punches_live_peer_but_not_dead_one() {
    let (peer, _anchor, _tmp) = start_server().await;
    let broker = DirectNatBroker::new().unwrap();

    assert_eq!(broker.punch(&peer).await.unwrap(), Some(peer.clone()));
    // Nothing listening here → no direct path.
    assert_eq!(broker.punch("127.0.0.1:1").await.unwrap(), None);
}
