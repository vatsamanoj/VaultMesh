//! Use-case: store one already-encrypted blob (node-agent data plane).

use crate::guard::authorize;
use std::sync::Arc;
use vault_domain::{BlobId, CapabilityToken, DomainError, Manifest, NamespaceId, Operation, Shard};
use vault_ports::{
    AuthVerifier, BlobAnchor, Clock, Cryptographer, ErasureCoder, IdSource, MetadataStore,
    PortError, PortResult, ShardRef,
};

pub struct PutBackup {
    metadata: Arc<dyn MetadataStore>,
    anchor: Arc<dyn BlobAnchor>,
    erasure: Arc<dyn ErasureCoder>,
    crypto: Arc<dyn Cryptographer>,
    verifier: Arc<dyn AuthVerifier>,
    ids: Arc<dyn IdSource>,
    clock: Arc<dyn Clock>,
}

impl PutBackup {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        metadata: Arc<dyn MetadataStore>,
        anchor: Arc<dyn BlobAnchor>,
        erasure: Arc<dyn ErasureCoder>,
        crypto: Arc<dyn Cryptographer>,
        verifier: Arc<dyn AuthVerifier>,
        ids: Arc<dyn IdSource>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            metadata,
            anchor,
            erasure,
            crypto,
            verifier,
            ids,
            clock,
        }
    }

    /// The `ciphertext` is opaque to VaultMesh — encrypted by the app already.
    pub async fn execute(
        &self,
        namespace: &NamespaceId,
        token: &CapabilityToken,
        ciphertext: &[u8],
    ) -> PortResult<BlobId> {
        let app = authorize(
            &self.verifier,
            &self.metadata,
            &self.clock,
            namespace,
            token,
            Operation::Put,
        )
        .await?;

        // Quota (L: abuse/DoS containment) from the app's Contract.
        let contract = self
            .metadata
            .get_contract(&app)
            .await?
            .ok_or(PortError::NotFound)?;
        let usage = self.metadata.namespace_usage(namespace).await?;
        if !contract
            .quota
            .admits(usage.bytes, usage.objects, ciphertext.len() as u64)
        {
            return Err(PortError::Domain(DomainError::QuotaExceeded));
        }

        let blob_id: BlobId = self.ids.new_id("blob").into();
        let shards = self.erasure.encode(ciphertext, contract.erasure)?;

        let mut shard_meta = Vec::with_capacity(shards.len());
        for (index, bytes) in shards.iter().enumerate() {
            let index = index as u16;
            let at = ShardRef::new(namespace.clone(), blob_id.clone(), index);
            self.anchor.put_shard(&at, bytes).await?;
            let digest = self.crypto.sha256_hex(bytes);
            shard_meta.push(Shard::new(index, digest, bytes.len() as u32));
        }

        let manifest = Manifest::new(
            blob_id.clone(),
            namespace.clone(),
            contract.erasure,
            shard_meta,
            ciphertext.len() as u64,
            self.clock.now(),
        );
        self.metadata.put_manifest(&manifest).await?;
        Ok(blob_id)
    }
}
