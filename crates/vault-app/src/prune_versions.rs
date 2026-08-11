//! Use-case: `keep_versions` retention pruning. A client tags each backup with
//! an opaque `object_id` = HMAC(index_key, filename) that groups versions of the
//! same logical file without revealing the name. This sweeps one object group,
//! keeps the newest `keep_versions`, and deletes the older ones — but never a
//! version still under its `min_days` retention hold. Zero-knowledge: it works
//! purely from manifest metadata (object_id + created_at), no plaintext.

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use vault_domain::NamespaceId;
use vault_ports::{BlobAnchor, Clock, MetadataStore, PortError, PortResult};

/// Outcome of pruning one object group.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PruneReport {
    pub object_id: String,
    /// Total versions found for this object.
    pub versions: usize,
    /// Newest versions retained by the `keep_versions` policy.
    pub kept: usize,
    /// Older versions deleted.
    pub pruned: usize,
    /// Older versions retained because their `min_days` hold has not elapsed.
    pub held: usize,
}

pub struct PruneVersions {
    metadata: Arc<dyn MetadataStore>,
    anchor: Arc<dyn BlobAnchor>,
    clock: Arc<dyn Clock>,
}

impl PruneVersions {
    pub fn new(
        metadata: Arc<dyn MetadataStore>,
        anchor: Arc<dyn BlobAnchor>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            metadata,
            anchor,
            clock,
        }
    }

    /// Prune older versions of `object_id` in `namespace` beyond the contract's
    /// `keep_versions`, honoring each version's `min_days` hold.
    pub async fn execute(
        &self,
        namespace: &NamespaceId,
        object_id: &str,
    ) -> PortResult<PruneReport> {
        let ns = self
            .metadata
            .get_namespace(namespace)
            .await?
            .ok_or(PortError::NotFound)?;
        let contract = self
            .metadata
            .get_contract(&ns.app_id)
            .await?
            .ok_or(PortError::NotFound)?;
        let keep = contract.retention.keep_versions as usize;

        // Collect every manifest in the namespace tagged with this object_id.
        let mut versions = Vec::new();
        for blob in self.metadata.list_blobs(namespace).await? {
            if let Some(m) = self.metadata.get_manifest(namespace, &blob).await? {
                if m.object_id.as_deref() == Some(object_id) {
                    versions.push(m);
                }
            }
        }
        let total = versions.len();

        // `keep_versions == 0` means "unlimited" — never prune.
        if keep == 0 {
            return Ok(PruneReport {
                object_id: object_id.to_string(),
                versions: total,
                kept: total,
                pruned: 0,
                held: 0,
            });
        }

        // Newest first; the first `keep` are always retained.
        versions.sort_by(|a, b| b.created_at.0.cmp(&a.created_at.0));
        let now = self.clock.now();
        let (mut kept, mut pruned, mut held) = (0usize, 0usize, 0usize);
        for (i, m) in versions.iter().enumerate() {
            if i < keep {
                kept += 1;
                continue;
            }
            if contract.retention.hold_elapsed(m.created_at, now) {
                self.anchor.delete_blob(namespace, &m.blob_id).await?;
                self.metadata.delete_manifest(namespace, &m.blob_id).await?;
                pruned += 1;
            } else {
                held += 1;
            }
        }

        Ok(PruneReport {
            object_id: object_id.to_string(),
            versions: total,
            kept,
            pruned,
            held,
        })
    }
}
