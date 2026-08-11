//! Node-agent state: the data-plane use-cases, pre-wired with adapters, plus
//! the local anchor for serving peer-mesh shard requests.

use serde::Serialize;
use std::sync::{Arc, Mutex};
use vault_app::{DeleteBackup, GetBackup, ListBackups, PruneVersions, PutBackup, RepairShards};
use vault_ports::{BlobAnchor, Clock};

/// Live status of the repair subsystem, surfaced to the console so an operator
/// can see auto-repair working over time — both the scheduled background sweep
/// and reactive heals triggered by reads of degraded blobs.
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
    /// Grand total of shards healed, by the sweep and by reactive reads.
    pub total_repaired: u64,
    /// Blobs healed reactively (a read found them degraded and triggered a heal).
    pub reactive_heals: u64,
    /// Shards healed reactively (subset of `total_repaired`).
    pub reactive_repaired: u64,
    /// Epoch millis of the last reactive heal (`0` = never yet).
    pub last_reactive_ms: u64,
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
    /// Repair status (sweep + reactive heals), for the console indicator.
    pub sweep: SweepHandle,
    /// Wall clock, used to timestamp reactive heals.
    pub clock: Arc<dyn Clock>,
}
