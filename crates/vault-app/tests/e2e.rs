//! End-to-end reliability & security drills for the P0 pipeline, wired with the
//! real adapters (in-memory metadata, filesystem anchor, AES-256-GCM crypto,
//! passthrough erasure) — exactly as `docs/ROADMAP.md` describes.

use std::path::PathBuf;
use std::sync::Arc;

use adapter_blob_fs::FsBlobAnchor;
use adapter_crypto::{AesGcmCryptographer, Ed25519Signer, RandomIdSource, SystemClock};
use adapter_erasure::PassthroughCoder;
use adapter_memstore::MemoryMetadataStore;
use tempfile::TempDir;
use vault_app::{
    CreateNamespace, DeleteBackup, GetBackup, IssueCapability, ListBackups, PutBackup, RegisterApp,
};
use vault_domain::{
    AppId, CapabilityClaims, ErasureParams, NamespaceId, Nonce, Operation, Quota, RetentionPolicy,
    Timestamp,
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
    root: PathBuf,
    _tmp: TempDir,
}

fn ctx() -> Ctx {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();

    let metadata: Arc<dyn MetadataStore> = Arc::new(MemoryMetadataStore::new());
    let anchor: Arc<dyn BlobAnchor> = Arc::new(FsBlobAnchor::new(&root));
    let erasure: Arc<dyn ErasureCoder> = Arc::new(PassthroughCoder::new());
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
                ErasureParams::passthrough(),
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

#[tokio::test]
async fn tampered_shard_is_detected_on_restore() {
    let c = ctx();
    let (app, ns) = c.onboard().await;
    let ct = c.seal(&ns, b"important backup bytes");
    let put_tok = c.token(&app, &ns, Operation::Put).await;
    let blob = c.put.execute(&ns, &put_tok, &ct).await.unwrap();

    // Corrupt the on-disk shard; per-shard SHA-256 must catch it.
    let shard = c
        .root
        .join(ns.as_str())
        .join(blob.as_str())
        .join("00000.shard");
    std::fs::write(&shard, b"corrupted-bytes-of-a-different-length").unwrap();

    let get_tok = c.token(&app, &ns, Operation::Get).await;
    let err = c.get.execute(&ns, &get_tok, &blob).await.unwrap_err();
    assert!(matches!(err, PortError::Integrity(_)));
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
