//! Shared coordinator state: the ports, wired to concrete P0 adapters.

use adapter_crypto::{Ed25519Signer, RandomIdSource, SystemClock};
use adapter_memstore::MemoryMetadataStore;
use std::sync::Arc;
use vault_ports::{CapabilitySigner, Clock, IdSource, MetadataStore};

/// Cloneable handle passed to every axum handler.
#[derive(Clone)]
pub struct AppState {
    pub metadata: Arc<dyn MetadataStore>,
    pub signer: Arc<dyn CapabilitySigner>,
    pub ids: Arc<dyn IdSource>,
    pub clock: Arc<dyn Clock>,
}

impl AppState {
    /// Build the P0 in-memory control plane with a freshly generated
    /// capability-signing key.
    pub fn in_memory() -> Self {
        Self {
            metadata: Arc::new(MemoryMetadataStore::new()),
            signer: Arc::new(Ed25519Signer::generate()),
            ids: Arc::new(RandomIdSource::new()),
            clock: Arc::new(SystemClock::new()),
        }
    }
}
