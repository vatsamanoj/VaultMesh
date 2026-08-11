//! VaultMesh use-cases. Each is a small service that orchestrates *ports* and
//! depends on traits only (DIP), so every one is unit-testable with fakes.
//!
//! Control plane: [`RegisterApp`], [`CreateNamespace`], [`IssueCapability`].
//! Data plane (node-agent): [`PutBackup`], [`GetBackup`], [`ListBackups`],
//! [`DeleteBackup`].

mod create_namespace;
mod delete_backup;
mod get_backup;
mod guard;
mod issue_capability;
mod list_backups;
mod prune_versions;
mod put_backup;
mod register_app;
mod repair_shards;
mod usage_report;

pub use create_namespace::CreateNamespace;
pub use delete_backup::DeleteBackup;
pub use get_backup::{GetBackup, RestoreOutcome};
pub use issue_capability::{IssueCapability, MAX_TOKEN_TTL_SECS};
pub use list_backups::ListBackups;
pub use prune_versions::{PruneReport, PruneVersions};
pub use put_backup::PutBackup;
pub use register_app::RegisterApp;
pub use repair_shards::{RepairReport, RepairShards};
pub use usage_report::{UsageReport, UsageStatement};

pub use vault_ports::{PortError, PortResult};
