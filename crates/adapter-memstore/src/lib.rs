//! An in-memory [`MetadataStore`] for P0 and tests. The production adapter
//! (`adapter-postgres`) implements the same port; use-cases never change.

use async_trait::async_trait;
use std::collections::HashMap;
use tokio::sync::RwLock;
use vault_domain::{AppContract, AppId, BlobId, Manifest, Namespace, NamespaceId};
use vault_ports::{MetadataStore, NamespaceUsage, PortResult};

#[derive(Default)]
struct Inner {
    contracts: HashMap<AppId, AppContract>,
    namespaces: HashMap<NamespaceId, Namespace>,
    // Keyed by (namespace, blob) so isolation is structural.
    manifests: HashMap<(NamespaceId, BlobId), Manifest>,
}

#[derive(Default)]
pub struct MemoryMetadataStore {
    inner: RwLock<Inner>,
}

impl MemoryMetadataStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl MetadataStore for MemoryMetadataStore {
    async fn register_app(&self, contract: &AppContract) -> PortResult<()> {
        self.inner
            .write()
            .await
            .contracts
            .insert(contract.app_id.clone(), contract.clone());
        Ok(())
    }

    async fn get_contract(&self, app: &AppId) -> PortResult<Option<AppContract>> {
        Ok(self.inner.read().await.contracts.get(app).cloned())
    }

    async fn create_namespace(&self, ns: &Namespace) -> PortResult<()> {
        self.inner
            .write()
            .await
            .namespaces
            .insert(ns.id.clone(), ns.clone());
        Ok(())
    }

    async fn get_namespace(&self, id: &NamespaceId) -> PortResult<Option<Namespace>> {
        Ok(self.inner.read().await.namespaces.get(id).cloned())
    }

    async fn list_namespaces(&self) -> PortResult<Vec<NamespaceId>> {
        Ok(self.inner.read().await.namespaces.keys().cloned().collect())
    }

    async fn namespace_usage(&self, id: &NamespaceId) -> PortResult<NamespaceUsage> {
        let inner = self.inner.read().await;
        let mut usage = NamespaceUsage::default();
        for ((ns, _blob), manifest) in inner.manifests.iter() {
            if ns == id {
                usage.objects += 1;
                usage.bytes += manifest.ciphertext_len;
            }
        }
        Ok(usage)
    }

    async fn put_manifest(&self, manifest: &Manifest) -> PortResult<()> {
        self.inner.write().await.manifests.insert(
            (manifest.namespace.clone(), manifest.blob_id.clone()),
            manifest.clone(),
        );
        Ok(())
    }

    async fn get_manifest(
        &self,
        namespace: &NamespaceId,
        blob_id: &BlobId,
    ) -> PortResult<Option<Manifest>> {
        Ok(self
            .inner
            .read()
            .await
            .manifests
            .get(&(namespace.clone(), blob_id.clone()))
            .cloned())
    }

    async fn list_blobs(&self, namespace: &NamespaceId) -> PortResult<Vec<BlobId>> {
        let inner = self.inner.read().await;
        Ok(inner
            .manifests
            .keys()
            .filter(|(ns, _)| ns == namespace)
            .map(|(_, blob)| blob.clone())
            .collect())
    }

    async fn delete_manifest(&self, namespace: &NamespaceId, blob_id: &BlobId) -> PortResult<()> {
        self.inner
            .write()
            .await
            .manifests
            .remove(&(namespace.clone(), blob_id.clone()));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_domain::{ErasureParams, Quota, RetentionPolicy, Timestamp};

    #[tokio::test]
    async fn tracks_usage_per_namespace() {
        let store = MemoryMetadataStore::new();
        let ns = NamespaceId::new("ns1");
        let manifest = Manifest::new(
            BlobId::new("b1"),
            ns.clone(),
            ErasureParams::passthrough(),
            vec![],
            128,
            Timestamp::from_millis(1),
        );
        store.put_manifest(&manifest).await.unwrap();
        let usage = store.namespace_usage(&ns).await.unwrap();
        assert_eq!(usage.objects, 1);
        assert_eq!(usage.bytes, 128);
        assert_eq!(store.list_blobs(&ns).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn stores_contract() {
        let store = MemoryMetadataStore::new();
        let c = AppContract::new(
            AppId::new("app"),
            Quota::new(1 << 30, 1000),
            RetentionPolicy::new(3, 30),
            ErasureParams::passthrough(),
        );
        store.register_app(&c).await.unwrap();
        assert_eq!(
            store.get_contract(&AppId::new("app")).await.unwrap(),
            Some(c)
        );
    }
}
