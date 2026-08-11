//! Use-case: per-app-namespace usage & billing. Aggregates a registered app's
//! namespaces into a statement (bytes, objects, quota headroom, estimated cost).
//! VaultMesh bills opaque namespaces — it still never learns what a tenant is.

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use vault_domain::{AppId, NamespaceId};
use vault_ports::{MetadataStore, NamespaceUsage, PortError, PortResult};

/// Flat price used for the estimate: micro-units of currency per GiB stored.
pub const MICROS_PER_GIB: u64 = 20_000;
const BYTES_PER_GIB: u64 = 1 << 30;

/// One namespace line in a statement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamespaceLine {
    pub namespace: NamespaceId,
    pub bytes: u64,
    pub objects: u64,
}

/// A billing statement for an app across all its namespaces.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageStatement {
    pub app_id: AppId,
    pub lines: Vec<NamespaceLine>,
    pub total_bytes: u64,
    pub total_objects: u64,
    /// Per-namespace object quota from the Contract (for headroom display).
    pub quota_max_bytes: u64,
    pub estimated_cost_micros: u64,
}

pub struct UsageReport {
    metadata: Arc<dyn MetadataStore>,
}

impl UsageReport {
    pub fn new(metadata: Arc<dyn MetadataStore>) -> Self {
        Self { metadata }
    }

    pub async fn execute(&self, app_id: &AppId) -> PortResult<UsageStatement> {
        let contract = self
            .metadata
            .get_contract(app_id)
            .await?
            .ok_or(PortError::NotFound)?;

        let mut lines = Vec::new();
        let mut total_bytes = 0u64;
        let mut total_objects = 0u64;
        for ns in self.metadata.list_namespaces().await? {
            // Only this app's namespaces.
            match self.metadata.get_namespace(&ns).await? {
                Some(n) if &n.app_id == app_id => {}
                _ => continue,
            }
            let NamespaceUsage { bytes, objects } = self.metadata.namespace_usage(&ns).await?;
            total_bytes += bytes;
            total_objects += objects;
            lines.push(NamespaceLine {
                namespace: ns,
                bytes,
                objects,
            });
        }

        let estimated_cost_micros = total_bytes.saturating_mul(MICROS_PER_GIB) / BYTES_PER_GIB;
        Ok(UsageStatement {
            app_id: app_id.clone(),
            lines,
            total_bytes,
            total_objects,
            quota_max_bytes: contract.quota.max_bytes,
            estimated_cost_micros,
        })
    }
}
