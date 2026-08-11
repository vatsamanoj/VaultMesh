//! Node-agent state: the data-plane use-cases, pre-wired with adapters, plus
//! the local anchor for serving peer-mesh shard requests.

use serde::Serialize;
use std::sync::{Arc, Mutex};
use vault_app::{DeleteBackup, GetBackup, ListBackups, PruneVersions, PutBackup, RepairShards};
use vault_ports::BlobAnchor;

/// Live status of the background repair sweep, surfaced to the console so an
/// operator can see auto-repair working over time.
#[derive(Clone, Default, Serialize)]
pub struct SweepStatus {
    pub enabled: bool,
    pub interval_secs: u64,
    pub sweeps: u64,
    /// Epoch millis of the last completed sweep (`0` = never yet).
    pub last_run_ms: u64,
    pub last_checked: u64,
    pub last_repaired: u64,
    pub last_unrepairable: u64,
    pub total_repaired: u64,
}

/// Shared handle updated by the sweep loop and read by the status endpoint.
pub type SweepHandle = Arc<Mutex<SweepStatus>>;

/// Cloneable handle for axum handlers. Each field is a ready-to-run use-case.
#[derive(Clone)]
pub struct AppState {
    pub put: Arc<PutBackup>,
    pub get: Arc<GetBackup>,
    pub list: Arc<ListBackups>,
    pub delete: Arc<DeleteBackup>,
    pub repair: Arc<RepairShards>,
    pub prune: Arc<PruneVersions>,
    /// Local anchor, used to store/serve shards for peers (P2 mesh).
    pub anchor: Arc<dyn BlobAnchor>,
    /// Background repair-sweep status (for the console indicator).
    pub sweep: SweepHandle,
}
