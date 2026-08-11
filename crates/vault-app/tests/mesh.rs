//! P2 peer-mesh drills: reads are served from peers for locality/speed, and the
//! authoritative anchor is always the fallback — so peers going offline never
//! blocks a restore.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use adapter_blob_fs::FsBlobAnchor;
use adapter_crypto::{AesGcmCryptographer, Ed25519Signer, RandomIdSource, SystemClock};
use adapter_memstore::MemoryMetadataStore;
use adapter_reed_solomon::ReedSolomonCoder;
use async_trait::async_trait;
use tempfile::TempDir;
use vault_app::{
    CreateNamespace, GetBackup, IssueCapability, PutBackup, RegisterApp, RepairShards,
};
use vault_domain::{
    AppId, ErasureParams, NamespaceId, Operation, PlacementPolicy, Quota, RetentionPolicy,
};
use vault_ports::{
    AuthVerifier, BlobAnchor, Clock, Cryptographer, ErasureCoder, IdSource, MetadataStore,
    PortError, PortResult, ShardRef, ShardTransport,
};

/// An in-memory peer that can be toggled offline, and counts fetches so a test
/// can prove a read was actually served from a peer.
#[derive(Default)]
struct FakePeer {
    store: Mutex<HashMap<String, Vec<u8>>>,
    online: AtomicBool,
    fetches: AtomicUsize,
}

impl FakePeer {
    fn new() -> Self {
        Self {
            store: Mutex::new(HashMap::new()),
            online: AtomicBool::new(true),
            fetches: AtomicUsize::new(0),
        }
    }
    fn key(peer: &str, at: &ShardRef) -> String {
        format!("{peer}|{}", at.object_key())
    }
    fn set_online(&self, v: bool) {
        self.online.store(v, Ordering::SeqCst);
    }
    fn stored(&self) -> usize {
        self.store.lock().unwrap().len()
    }
    fn fetches(&self) -> usize {
        self.fetches.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl ShardTransport for FakePeer {
    async fn send_shard(&self, peer: &str, at: &ShardRef, bytes: &[u8]) -> PortResult<()> {
        if !self.online.load(Ordering::SeqCst) {
            return Err(PortError::Unavailable("peer offline".into()));
        }
        self.store
            .lock()
            .unwrap()
            .insert(Self::key(peer, at), bytes.to_vec());
        Ok(())
    }

    async fn fetch_shard(&self, peer: &str, at: &ShardRef) -> PortResult<Vec<u8>> {
        self.fetches.fetch_add(1, Ordering::SeqCst);
        if !self.online.load(Ordering::SeqCst) {
            return Err(PortError::Unavailable("peer offline".into()));
        }
        self.store
            .lock()
            .unwrap()
            .get(&Self::key(peer, at))
            .cloned()
            .ok_or(PortError::NotFound)
    }
}

struct Ctx {
    metadata: Arc<dyn MetadataStore>,
    crypto: Arc<dyn Cryptographer>,
    signer: Arc<Ed25519Signer>,
    ids: Arc<dyn IdSource>,
    clock: Arc<dyn Clock>,
    put: PutBackup,
    get: GetBackup,
    peer: Arc<FakePeer>,
    root: PathBuf,
    _tmp: TempDir,
}

fn ctx() -> Ctx {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();

    let metadata: Arc<dyn MetadataStore> = Arc::new(MemoryMetadataStore::new());
    let anchor: Arc<dyn BlobAnchor> = Arc::new(FsBlobAnchor::new(&root));
    let erasure: Arc<dyn ErasureCoder> = Arc::new(ReedSolomonCoder::new());
    let crypto: Arc<dyn Cryptographer> = Arc::new(AesGcmCryptographer::new());
    let signer = Arc::new(Ed25519Signer::generate());
    let verifier: Arc<dyn AuthVerifier> = Arc::new(signer.verifier());
    let ids: Arc<dyn IdSource> = Arc::new(RandomIdSource::new());
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());

    let peer = Arc::new(FakePeer::new());
    let transport: Arc<dyn ShardTransport> = peer.clone();
    let placement = PlacementPolicy {
        locality_hint: None,
        prefer_peers: true,
    };

    let put = PutBackup::new(
        metadata.clone(),
        anchor.clone(),
        erasure.clone(),
        crypto.clone(),
        verifier.clone(),
        ids.clone(),
        clock.clone(),
    )
    .with_mesh(transport.clone(), vec!["peerA".into()], placement);
    let get = GetBackup::new(
        metadata.clone(),
        anchor.clone(),
        erasure.clone(),
        crypto.clone(),
        verifier.clone(),
        clock.clone(),
    )
    .with_mesh(transport.clone());

    Ctx {
        metadata,
        crypto,
        signer,
        ids,
        clock,
        put,
        get,
        peer,
        root,
        _tmp: tmp,
    }
}

impl Ctx {
    async fn onboard(&self) -> (AppId, NamespaceId) {
        let contract = RegisterApp::new(self.metadata.clone(), self.ids.clone())
            .execute(
                Quota::new(1 << 30, 1000),
                RetentionPolicy::new(3, 30),
                ErasureParams::recommended(),
            )
            .await
            .unwrap();
        let ns = CreateNamespace::new(self.metadata.clone(), self.ids.clone())
            .execute(&contract.app_id)
            .await
            .unwrap();
        (contract.app_id, ns.id)
    }

    async fn token(
        &self,
        app: &AppId,
        ns: &NamespaceId,
        op: Operation,
    ) -> vault_domain::CapabilityToken {
        IssueCapability::new(
            self.metadata.clone(),
            self.signer.clone(),
            self.ids.clone(),
            self.clock.clone(),
        )
        .execute(app, ns, op, 300)
        .await
        .unwrap()
    }

    fn seal(&self, ns: &NamespaceId, payload: &[u8]) -> Vec<u8> {
        let key = self
            .crypto
            .derive_key(b"app-secret", ns.as_str().as_bytes());
        self.crypto.encrypt(&key, payload).unwrap()
    }
    fn open(&self, ns: &NamespaceId, ct: &[u8]) -> Vec<u8> {
        let key = self
            .crypto
            .derive_key(b"app-secret", ns.as_str().as_bytes());
        self.crypto.decrypt(&key, ct).unwrap()
    }
}

/// A put replicates every shard to the peer, and a restore is then served from
/// the peer even when the anchor copy is gone.
#[tokio::test]
async fn read_is_served_from_peer() {
    let c = ctx();
    let (app, ns) = c.onboard().await;
    let payload = b"served from a nearby peer for locality".to_vec();
    let ct = c.seal(&ns, &payload);

    let put_tok = c.token(&app, &ns, Operation::Put).await;
    let blob = c.put.execute(&ns, &put_tok, &ct).await.unwrap();
    assert_eq!(c.peer.stored(), 6, "all 6 shards replicated to the peer");

    // Wipe the anchor copy entirely: only the peer has the shards now.
    std::fs::remove_dir_all(c.root.join(ns.as_str()).join(blob.as_str())).unwrap();

    let get_tok = c.token(&app, &ns, Operation::Get).await;
    let restored = c.get.execute(&ns, &get_tok, &blob).await.unwrap();
    assert_eq!(c.open(&ns, &restored), payload);
    assert!(c.peer.fetches() > 0, "restore was served from the peer");
}

/// When peers are offline, the restore falls back to the authoritative anchor —
/// the core durability guarantee.
#[tokio::test]
async fn anchor_is_the_fallback_when_peers_offline() {
    let c = ctx();
    let (app, ns) = c.onboard().await;
    let payload = b"the anchor always holds the full set".to_vec();
    let ct = c.seal(&ns, &payload);

    let put_tok = c.token(&app, &ns, Operation::Put).await;
    let blob = c.put.execute(&ns, &put_tok, &ct).await.unwrap();

    // All peers vanish; the anchor still has every shard.
    c.peer.set_online(false);

    let get_tok = c.token(&app, &ns, Operation::Get).await;
    let restored = c.get.execute(&ns, &get_tok, &blob).await.unwrap();
    assert_eq!(c.open(&ns, &restored), payload, "restored from the anchor");
}

/// When a node drops BELOW k surviving shards locally, repair borrows the
/// missing ones from their peer replicas, reconstructs, and heals the anchor —
/// so the node becomes independently restorable again.
#[tokio::test]
async fn repair_borrows_from_peer_when_below_k() {
    let c = ctx();
    let (app, ns) = c.onboard().await;
    let payload = b"repair heals from peers when local drops below k".to_vec();
    let ct = c.seal(&ns, &payload);

    let put_tok = c.token(&app, &ns, Operation::Put).await;
    let blob = c.put.execute(&ns, &put_tok, &ct).await.unwrap();
    assert_eq!(c.peer.stored(), 6, "all 6 shards replicated to the peer");

    // Destroy 3 of 6 local shards — only 3 survive locally, below k = 4.
    let dir = c.root.join(ns.as_str()).join(blob.as_str());
    for i in [0u16, 1, 2] {
        std::fs::remove_file(dir.join(format!("{i:05}.shard"))).unwrap();
    }

    let anchor: Arc<dyn BlobAnchor> = Arc::new(FsBlobAnchor::new(&c.root));
    let erasure: Arc<dyn ErasureCoder> = Arc::new(ReedSolomonCoder::new());
    let transport: Arc<dyn ShardTransport> = c.peer.clone();
    let repair = RepairShards::new(c.metadata.clone(), anchor, erasure, c.crypto.clone())
        .with_mesh(transport);

    let report = repair.execute(&ns, &blob).await.unwrap();
    assert!(
        !report.unrepairable,
        "peer replicas make it repairable again"
    );
    assert_eq!(report.repaired, 3, "all 3 missing shards rebuilt locally");
    assert_eq!(report.healthy, 6);
    assert!(c.peer.fetches() > 0, "repair fetched a shard from the peer");

    // The node is independent now: with peers offline, the anchor restores alone.
    c.peer.set_online(false);
    let get_tok = c.token(&app, &ns, Operation::Get).await;
    let restored = c.get.execute(&ns, &get_tok, &blob).await.unwrap();
    assert_eq!(
        c.open(&ns, &restored),
        payload,
        "healed anchor restores alone"
    );
}
