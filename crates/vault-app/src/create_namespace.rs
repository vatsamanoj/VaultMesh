//! Use-case: allocate an opaque namespace under a registered app.

use std::sync::Arc;
use vault_domain::{AppId, Namespace};
use vault_ports::{IdSource, MetadataStore, PortError, PortResult};

pub struct CreateNamespace {
    metadata: Arc<dyn MetadataStore>,
    ids: Arc<dyn IdSource>,
}

impl CreateNamespace {
    pub fn new(metadata: Arc<dyn MetadataStore>, ids: Arc<dyn IdSource>) -> Self {
        Self { metadata, ids }
    }

    pub async fn execute(&self, app_id: &AppId) -> PortResult<Namespace> {
        // The app must be registered first.
        if self.metadata.get_contract(app_id).await?.is_none() {
            return Err(PortError::NotFound);
        }
        let ns = Namespace::new(self.ids.new_id("ns").into(), app_id.clone());
        self.metadata.create_namespace(&ns).await?;
        Ok(ns)
    }
}
