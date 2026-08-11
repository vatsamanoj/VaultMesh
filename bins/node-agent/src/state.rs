//! Node-agent state: the data-plane use-cases, pre-wired with adapters, plus
//! the local anchor for serving peer-mesh shard requests.

use std::sync::Arc;
use vault_app::{DeleteBackup, GetBackup, ListBackups, PutBackup};
use vault_ports::BlobAnchor;

/// Cloneable handle for axum handlers. Each field is a ready-to-run use-case.
#[derive(Clone)]
pub struct AppState {
    pub put: Arc<PutBackup>,
    pub get: Arc<GetBackup>,
    pub list: Arc<ListBackups>,
    pub delete: Arc<DeleteBackup>,
    /// Local anchor, used to store/serve shards for peers (P2 mesh).
    pub anchor: Arc<dyn BlobAnchor>,
}
