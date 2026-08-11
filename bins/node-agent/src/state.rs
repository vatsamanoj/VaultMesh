//! Node-agent state: the data-plane use-cases, pre-wired with adapters.

use std::sync::Arc;
use vault_app::{DeleteBackup, GetBackup, ListBackups, PutBackup};

/// Cloneable handle for axum handlers. Each field is a ready-to-run use-case.
#[derive(Clone)]
pub struct AppState {
    pub put: Arc<PutBackup>,
    pub get: Arc<GetBackup>,
    pub list: Arc<ListBackups>,
    pub delete: Arc<DeleteBackup>,
}
