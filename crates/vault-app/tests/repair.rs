//! P3 repair-loop drills: self-healing reconstruction of missing/corrupt shards.

use std::path::PathBuf;
use std::sync::Arc;

use adapter_blob_fs::FsBlobAnchor;
use adapter_crypto::{AesGcmCryptographer, Ed25519Signer, RandomIdSource, SystemClock};
use adapter_memstore::MemoryMetadataStore;
use adapter_reed_solomon::ReedSolomonCoder;
use tempfile::TempDir;
use vault_app::{
    CreateNamespace, GetBackup, IssueCapability, PutBackup, RegisterApp, RepairShards,
};
use vault_domain::{AppId, BlobId, ErasureParams, NamespaceId, Operation, Quota, RetentionPolicy};
use vault_ports::{
    AuthVerifier, BlobAnchor, Clock, Cryptographer, ErasureCoder, IdSource, MetadataStore,
};

struct Ctx {
    metadata: Arc<dyn MetadataStore>,
    crypto: Arc<dyn Cryptographer>,
    signer: Arc<Ed25519Signer>,
    ids: Arc<dyn IdSource>,
    clock: Arc<dyn Clock>,
    put: PutBackup,
    get: GetBackup,
    repair: RepairShards,
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
    let repair = RepairShards::new(
        metadata.clone(),
        anchor.clone(),
        erasure.clone(),
        crypto.clone(),
    );

    Ctx {
        metadata,
        crypto,
        signer,
        ids,
        clock,
        put,
        get,
        repair,
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

    async fn store(&self, app: &AppId, ns: &NamespaceId, payload: &[u8]) -> BlobId {
        let key = self.crypto.derive_key(b"s", ns.as_str().as_bytes());
        let ct = self.crypto.encrypt(&key, payload).unwrap();
        let tok = IssueCapability::new(
            self.metadata.clone(),
            self.signer.clone(),
            self.ids.clone(),
            self.clock.clone(),
        )
        .execute(app, ns, Operation::Put, 300)
        .await
        .unwrap();
        self.put.execute(ns, &tok, &ct).await.unwrap()
    }

    fn shard(&self, ns: &NamespaceId, blob: &BlobId, i: u16) -> PathBuf {
        self.root
            .join(ns.as_str())
            .join(blob.as_str())
            .join(format!("{i:05}.shard"))
    }
}

#[tokio::test]
async fn repairs_missing_and_corrupt_shards() {
    let c = ctx();
    let (app, ns) = c.onboard().await;
    let blob = c
        .store(&app, &ns, b"self-healing repair when nodes go dark")
        .await;

    // One shard vanishes, one is corrupted — 2 bad, within the parity budget.
    std::fs::remove_file(c.shard(&ns, &blob, 1)).unwrap();
    std::fs::write(c.shard(&ns, &blob, 3), b"corrupt").unwrap();

    let report = c.repair.execute(&ns, &blob).await.unwrap();
    assert_eq!(report.repaired, 2);
    assert_eq!(report.still_bad, 0);
    assert!(!report.unrepairable);

    // A second pass finds everything healthy.
    let again = c.repair.execute(&ns, &blob).await.unwrap();
    assert_eq!(again.repaired, 0);
    assert_eq!(again.healthy, again.checked);

    // The repaired shards are byte-correct on disk.
    for i in [1u16, 3] {
        assert!(c.shard(&ns, &blob, i).exists());
    }
}

#[tokio::test]
async fn degraded_read_reports_missing_and_stays_byte_identical() {
    let c = ctx();
    let (app, ns) = c.onboard().await;
    let payload = b"reactive repair heals on read before hitting the limit";
    let key = c.crypto.derive_key(b"s", ns.as_str().as_bytes());
    let blob = c.store(&app, &ns, payload).await;

    // Two shards go bad — within the parity budget, so the read still succeeds.
    std::fs::remove_file(c.shard(&ns, &blob, 1)).unwrap();
    std::fs::write(c.shard(&ns, &blob, 3), b"corrupt").unwrap();

    let tok = IssueCapability::new(
        c.metadata.clone(),
        c.signer.clone(),
        c.ids.clone(),
        c.clock.clone(),
    )
    .execute(&app, &ns, Operation::Get, 300)
    .await
    .unwrap();

    // restore() reports the degradation the reactive-repair path keys off of...
    let outcome = c.get.restore(&ns, &tok, &blob).await.unwrap();
    assert_eq!(outcome.shards_missing, 2);
    assert_eq!(outcome.shards_total, 6);
    // ...and the restored ciphertext still decrypts byte-identically.
    let plain = c.crypto.decrypt(&key, &outcome.ciphertext).unwrap();
    assert_eq!(plain, payload);
}

#[tokio::test]
async fn reports_unrepairable_beyond_parity() {
    let c = ctx();
    let (app, ns) = c.onboard().await;
    let blob = c.store(&app, &ns, b"too much loss").await;

    // Lose 3 of 6 (k=4): fewer than k valid remain -> cannot reconstruct.
    for i in [0u16, 2, 4] {
        std::fs::remove_file(c.shard(&ns, &blob, i)).unwrap();
    }
    let report = c.repair.execute(&ns, &blob).await.unwrap();
    assert!(report.unrepairable);
    assert_eq!(report.repaired, 0);
}
