//! End-to-end reliability & security drills for the P0 pipeline, wired with the
//! real adapters (in-memory metadata, filesystem anchor, AES-256-GCM crypto,
//! passthrough erasure) — exactly as `docs/ROADMAP.md` describes.

use std::path::PathBuf;
use std::sync::Arc;

use adapter_blob_fs::FsBlobAnchor;
use adapter_crypto::{AesGcmCryptographer, Ed25519Signer, RandomIdSource, SystemClock};
use adapter_memstore::MemoryMetadataStore;
use adapter_reed_solomon::ReedSolomonCoder;
use tempfile::TempDir;
use vault_app::{
    CreateNamespace, DeleteBackup, GetBackup, IssueCapability, ListBackups, PruneVersions,
    PutBackup, RegisterApp,
};
use vault_domain::{
    AppId, BlobId, CapabilityClaims, DomainError, ErasureParams, NamespaceId, Nonce, Operation,
    Quota, RetentionPolicy, Timestamp,
};
use vault_ports::{
    AuthVerifier, BlobAnchor, CapabilitySigner, Clock, Cryptographer, ErasureCoder, IdSource,
    MetadataStore, PortError,
};

struct Ctx {
    metadata: Arc<dyn MetadataStore>,
    crypto: Arc<dyn Cryptographer>,
    signer: Arc<Ed25519Signer>,
    ids: Arc<dyn IdSource>,
    clock: Arc<dyn Clock>,
    put: PutBackup,
    get: GetBackup,
    list: ListBackups,
    delete: DeleteBackup,
    prune: PruneVersions,
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

    let put = PutBackup::new(
        metadata.clone(),
        anchor.clone(),
        erasure.clone(),
        crypto.clone(),
        verifier.clone(),
        ids.clone(),
        clock.clone(),
    );
    let get = GetBackup::new(
        metadata.clone(),
        anchor.clone(),
        erasure.clone(),
        crypto.clone(),
        verifier.clone(),
        clock.clone(),
    );
    let list = ListBackups::new(metadata.clone(), verifier.clone(), clock.clone());
    let delete = DeleteBackup::new(
        metadata.clone(),
        anchor.clone(),
        verifier.clone(),
        clock.clone(),
    );
    let prune = PruneVersions::new(metadata.clone(), anchor.clone(), clock.clone());

    Ctx {
        metadata,
        crypto,
        signer,
        ids,
        clock,
        put,
        get,
        list,
        delete,
        prune,
        root,
        _tmp: tmp,
    }
}

impl Ctx {
    async fn onboard(&self) -> (AppId, NamespaceId) {
        // Default harness: no retention hold, so CRUD tests can delete freely.
        self.onboard_with(3, 0).await
    }

    async fn onboard_with(&self, keep_versions: u32, min_days: u32) -> (AppId, NamespaceId) {
        let contract = RegisterApp::new(self.metadata.clone(), self.ids.clone())
            .execute(
                Quota::new(1 << 30, 1000),
                RetentionPolicy::new(keep_versions, min_days),
                ErasureParams::recommended(), // Reed-Solomon 4-of-6
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

    fn open(&self, ns: &NamespaceId, ciphertext: &[u8]) -> Vec<u8> {
        let key = self
            .crypto
            .derive_key(b"app-secret", ns.as_str().as_bytes());
        self.crypto.decrypt(&key, ciphertext).unwrap()
    }

    /// Simulate a client publishing an object_id + a deterministic created_at
    /// (so version ordering is unambiguous in tests).
    async fn tag(&self, ns: &NamespaceId, blob: &BlobId, object_id: &str, created_at: Timestamp) {
        let mut m = self.metadata.get_manifest(ns, blob).await.unwrap().unwrap();
        m.object_id = Some(object_id.to_string());
        m.created_at = created_at;
        self.metadata.put_manifest(&m).await.unwrap();
    }

    async fn put_blob(&self, app: &AppId, ns: &NamespaceId, payload: &[u8]) -> BlobId {
        let tok = self.token(app, ns, Operation::Put).await;
        self.put
            .execute(ns, &tok, &self.seal(ns, payload))
            .await
            .unwrap()
    }
}

#[tokio::test]
async fn backup_restore_is_byte_identical() {
    let c = ctx();
    let (app, ns) = c.onboard().await;
    let payload = b"any app's opaque .lfbak container -- VaultMesh never sees this".to_vec();

    let ciphertext = c.seal(&ns, &payload);
    let put_tok = c.token(&app, &ns, Operation::Put).await;
    let blob = c.put.execute(&ns, &put_tok, &ciphertext).await.unwrap();

    let get_tok = c.token(&app, &ns, Operation::Get).await;
    let restored_ct = c.get.execute(&ns, &get_tok, &blob).await.unwrap();
    assert_eq!(restored_ct, ciphertext, "ciphertext must survive intact");
    assert_eq!(
        c.open(&ns, &restored_ct),
        payload,
        "restore is byte-identical"
    );

    // list returns the opaque id; delete removes it.
    let list_tok = c.token(&app, &ns, Operation::List).await;
    assert_eq!(
        c.list.execute(&ns, &list_tok).await.unwrap(),
        vec![blob.clone()]
    );
    let del_tok = c.token(&app, &ns, Operation::Delete).await;
    c.delete.execute(&ns, &del_tok, &blob).await.unwrap();
    let list_tok2 = c.token(&app, &ns, Operation::List).await;
    assert!(c.list.execute(&ns, &list_tok2).await.unwrap().is_empty());
}

/// A `min_days` retention hold blocks deletion until it elapses. The check is
/// server-side from the manifest's `created_at`, so it needs no plaintext.
#[tokio::test]
async fn delete_blocked_by_min_days_retention_hold() {
    let c = ctx();
    let (app, ns) = c.onboard_with(3, 7).await; // 7-day hold
    let payload = b"held for compliance".to_vec();
    let ct = c.seal(&ns, &payload);

    let put_tok = c.token(&app, &ns, Operation::Put).await;
    let blob = c.put.execute(&ns, &put_tok, &ct).await.unwrap();

    // Immediate delete is refused by the retention hold.
    let del_tok = c.token(&app, &ns, Operation::Delete).await;
    let err = c.delete.execute(&ns, &del_tok, &blob).await.unwrap_err();
    assert!(
        matches!(
            err,
            PortError::Domain(DomainError::RetentionHold { min_days: 7 })
        ),
        "expected a 7-day retention hold, got {err:?}"
    );

    // Nothing was deleted — the blob is still listed.
    let list_tok = c.token(&app, &ns, Operation::List).await;
    assert_eq!(c.list.execute(&ns, &list_tok).await.unwrap(), vec![blob]);
}

/// keep_versions pruning: keep the newest N versions of one opaque object group
/// and delete the older ones. Other object groups are untouched.
#[tokio::test]
async fn prune_keeps_newest_versions_and_deletes_older() {
    let c = ctx();
    let (app, ns) = c.onboard_with(2, 0).await; // keep 2, no hold

    // 4 versions of "report" (object_id = grpA), created_at 100..103.
    let mut grp = Vec::new();
    for i in 0..4u64 {
        let b = c
            .put_blob(&app, &ns, format!("report v{i}").as_bytes())
            .await;
        c.tag(&ns, &b, "grpA", Timestamp(100 + i)).await;
        grp.push(b);
    }
    // An unrelated file in another group must survive pruning.
    let other = c.put_blob(&app, &ns, b"unrelated").await;
    c.tag(&ns, &other, "grpB", Timestamp(50)).await;

    let report = c.prune.execute(&ns, "grpA").await.unwrap();
    assert_eq!(report.versions, 4);
    assert_eq!(report.kept, 2);
    assert_eq!(report.pruned, 2);
    assert_eq!(report.held, 0);

    // Newest two of grpA (indices 2,3) + grpB remain; oldest two are gone.
    let mut remaining = c.metadata.list_blobs(&ns).await.unwrap();
    remaining.sort();
    let mut expected = vec![grp[2].clone(), grp[3].clone(), other];
    expected.sort();
    assert_eq!(remaining, expected);
}

/// Pruning never deletes a version still under its `min_days` retention hold,
/// even when it exceeds keep_versions.
#[tokio::test]
async fn prune_respects_retention_hold() {
    let c = ctx();
    let (app, ns) = c.onboard_with(1, 30).await; // keep 1, 30-day hold
    let now = c.clock.now().0;

    // 3 recent versions (all within the 30-day hold).
    for i in 0..3u64 {
        let b = c.put_blob(&app, &ns, format!("v{i}").as_bytes()).await;
        c.tag(&ns, &b, "grp", Timestamp(now - i)).await;
    }

    let report = c.prune.execute(&ns, "grp").await.unwrap();
    assert_eq!(report.versions, 3);
    assert_eq!(report.kept, 1, "newest kept by policy");
    assert_eq!(report.held, 2, "older-but-held retained by min_days");
    assert_eq!(report.pruned, 0);
    assert_eq!(c.metadata.list_blobs(&ns).await.unwrap().len(), 3);
}

/// With no hold (`min_days = 0`), deletion is allowed immediately.
#[tokio::test]
async fn delete_allowed_when_no_retention_hold() {
    let c = ctx();
    let (app, ns) = c.onboard_with(3, 0).await;
    let ct = c.seal(&ns, b"no hold");
    let put_tok = c.token(&app, &ns, Operation::Put).await;
    let blob = c.put.execute(&ns, &put_tok, &ct).await.unwrap();

    let del_tok = c.token(&app, &ns, Operation::Delete).await;
    c.delete.execute(&ns, &del_tok, &blob).await.unwrap();
}

#[tokio::test]
async fn namespace_token_cannot_read_another_namespace() {
    let c = ctx();
    let (app, ns1) = c.onboard().await;
    let ns2 = CreateNamespace::new(c.metadata.clone(), c.ids.clone())
        .execute(&app)
        .await
        .unwrap()
        .id;

    let ct = c.seal(&ns1, b"secret");
    let put_tok = c.token(&app, &ns1, Operation::Put).await;
    let blob = c.put.execute(&ns1, &put_tok, &ct).await.unwrap();

    // A token scoped to ns1 must not read ns2 (nor be reused across namespaces).
    let ns1_get = c.token(&app, &ns1, Operation::Get).await;
    let err = c.get.execute(&ns2, &ns1_get, &blob).await.unwrap_err();
    assert!(matches!(
        err,
        PortError::Domain(vault_domain::DomainError::NamespaceMismatch)
    ));
}

#[tokio::test]
async fn issue_refuses_namespace_the_app_does_not_own() {
    let c = ctx();
    let (_app_a, ns_a) = c.onboard().await;
    let (app_b, _ns_b) = c.onboard().await;

    // app_b asking for a token on app_a's namespace is rejected at issuance.
    let err = IssueCapability::new(
        c.metadata.clone(),
        c.signer.clone(),
        c.ids.clone(),
        c.clock.clone(),
    )
    .execute(&app_b, &ns_a, Operation::Get, 300)
    .await
    .unwrap_err();
    assert!(matches!(
        err,
        PortError::Domain(vault_domain::DomainError::Unauthorized)
    ));
}

#[tokio::test]
async fn expired_token_is_rejected() {
    let c = ctx();
    let (app, ns) = c.onboard().await;
    let ct = c.seal(&ns, b"x");
    let put_tok = c.token(&app, &ns, Operation::Put).await;
    let blob = c.put.execute(&ns, &put_tok, &ct).await.unwrap();

    // Hand-sign a token that expired at t=1ms; the real clock is far past it.
    let claims = CapabilityClaims::new(
        app.clone(),
        ns.clone(),
        Operation::Get,
        Nonce::new("n"),
        Timestamp::from_millis(1),
    );
    let expired = c.signer.sign(claims).unwrap();
    let err = c.get.execute(&ns, &expired, &blob).await.unwrap_err();
    assert!(matches!(
        err,
        PortError::Domain(vault_domain::DomainError::TokenExpired)
    ));
}

#[tokio::test]
async fn foreign_signature_is_rejected() {
    let c = ctx();
    let (app, ns) = c.onboard().await;
    let ct = c.seal(&ns, b"x");
    let put_tok = c.token(&app, &ns, Operation::Put).await;
    let blob = c.put.execute(&ns, &put_tok, &ct).await.unwrap();

    // A token signed by a different key must fail signature verification (L2).
    let attacker = Ed25519Signer::generate();
    let claims = CapabilityClaims::new(
        app.clone(),
        ns.clone(),
        Operation::Get,
        Nonce::new("n"),
        c.clock.now().plus_secs(300),
    );
    let forged = attacker.sign(claims).unwrap();
    let err = c.get.execute(&ns, &forged, &blob).await.unwrap_err();
    assert!(matches!(err, PortError::Crypto(_)));
}

impl Ctx {
    fn shard_path(&self, ns: &NamespaceId, blob: &vault_domain::BlobId, index: u16) -> PathBuf {
        self.root
            .join(ns.as_str())
            .join(blob.as_str())
            .join(format!("{index:05}.shard"))
    }
}

/// Reed-Solomon 4-of-6 tolerates up to 2 lost shards; kill exactly the parity
/// budget and restore still succeeds from the anchor.
#[tokio::test]
async fn losses_within_parity_are_survived() {
    let c = ctx();
    let (app, ns) = c.onboard().await;
    let payload = b"reliability of restore is priority number one".to_vec();
    let ct = c.seal(&ns, &payload);
    let put_tok = c.token(&app, &ns, Operation::Put).await;
    let blob = c.put.execute(&ns, &put_tok, &ct).await.unwrap();

    // Delete 2 shards outright (simulate offline shard-holders).
    std::fs::remove_file(c.shard_path(&ns, &blob, 1)).unwrap();
    std::fs::remove_file(c.shard_path(&ns, &blob, 4)).unwrap();

    let get_tok = c.token(&app, &ns, Operation::Get).await;
    let restored_ct = c.get.execute(&ns, &get_tok, &blob).await.unwrap();
    assert_eq!(c.open(&ns, &restored_ct), payload, "erasure reconstructs");
}

/// A *corrupted* shard is caught by SHA-256 and treated as an erasure, so RS
/// reconstructs around it — corruption within the parity budget is survived.
#[tokio::test]
async fn corrupted_shard_is_reconstructed_around() {
    let c = ctx();
    let (app, ns) = c.onboard().await;
    let payload = vec![0xABu8; 4096];
    let ct = c.seal(&ns, &payload);
    let put_tok = c.token(&app, &ns, Operation::Put).await;
    let blob = c.put.execute(&ns, &put_tok, &ct).await.unwrap();

    // Corrupt one shard (bit-flip) and delete another: 2 erasures, within budget.
    std::fs::write(c.shard_path(&ns, &blob, 0), b"tampered").unwrap();
    std::fs::remove_file(c.shard_path(&ns, &blob, 5)).unwrap();

    let get_tok = c.token(&app, &ns, Operation::Get).await;
    let restored_ct = c.get.execute(&ns, &get_tok, &blob).await.unwrap();
    assert_eq!(c.open(&ns, &restored_ct), payload);
}

/// Losing more than the parity budget (3 of 6, k=4) fails cleanly.
#[tokio::test]
async fn losses_beyond_parity_fail() {
    let c = ctx();
    let (app, ns) = c.onboard().await;
    let ct = c.seal(&ns, b"important backup bytes");
    let put_tok = c.token(&app, &ns, Operation::Put).await;
    let blob = c.put.execute(&ns, &put_tok, &ct).await.unwrap();

    for i in [0u16, 2, 5] {
        std::fs::remove_file(c.shard_path(&ns, &blob, i)).unwrap();
    }
    let get_tok = c.token(&app, &ns, Operation::Get).await;
    let err = c.get.execute(&ns, &get_tok, &blob).await.unwrap_err();
    assert!(matches!(err, PortError::Unavailable(_)));
}

#[tokio::test]
async fn unknown_namespace_is_not_found() {
    let c = ctx();
    let (app, ns) = c.onboard().await;
    let tok = c.token(&app, &ns, Operation::Get).await;
    // A well-formed token but a blob that was never stored.
    let err = c
        .get
        .execute(&ns, &tok, &vault_domain::BlobId::new("nope"))
        .await
        .unwrap_err();
    assert!(matches!(err, PortError::NotFound));
}
