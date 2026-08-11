//! Shared coordinator state: the ports, wired to concrete P0–P3 adapters.

use adapter_crypto::{Ed25519Signer, RandomIdSource, SystemClock};
use adapter_ddns::InMemoryNameRegistry;
use adapter_memstore::MemoryMetadataStore;
use adapter_perimeter::{EscalatingThreatResponder, LedgerIntrusionSink};
use adapter_rcgen_ca::RcgenCertAuthority;
use adapter_rustfs::{RustFsConfig, RustFsPresigner};
use std::sync::Arc;
use vault_ports::{CapabilitySigner, Clock, IdSource, MetadataStore};

/// Cloneable handle passed to every axum handler.
#[derive(Clone)]
pub struct AppState {
    pub metadata: Arc<dyn MetadataStore>,
    pub signer: Arc<dyn CapabilitySigner>,
    pub ids: Arc<dyn IdSource>,
    pub clock: Arc<dyn Clock>,
    // Active perimeter (P3): tamper-evident footprints + escalating blocklist.
    pub intrusions: Arc<LedgerIntrusionSink>,
    pub responder: Arc<EscalatingThreatResponder>,
    // Self-sovereign machinery (P3): own CA + own naming/rendezvous.
    pub ca: Arc<RcgenCertAuthority>,
    pub naming: Arc<InMemoryNameRegistry>,
    // Object-store presigner (holds S3 creds; `None` unless VAULT_S3_* is set).
    pub presigner: Option<Arc<RustFsPresigner>>,
}

/// Build a presigner from `VAULT_S3_*` env, or `None` if not fully configured.
fn build_presigner() -> Option<Arc<RustFsPresigner>> {
    let cfg = RustFsConfig {
        endpoint: std::env::var("VAULT_S3_ENDPOINT").ok()?,
        bucket: std::env::var("VAULT_S3_BUCKET").ok()?,
        region: std::env::var("VAULT_S3_REGION").unwrap_or_else(|_| "us-east-1".into()),
        access_key: std::env::var("VAULT_S3_ACCESS_KEY").ok()?,
        secret_key: std::env::var("VAULT_S3_SECRET_KEY").ok()?,
        allow_http: std::env::var("VAULT_S3_ALLOW_HTTP")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(true),
    };
    match RustFsPresigner::new(cfg) {
        Ok(p) => {
            tracing::info!(
                "presign: object store configured — node-agents can use VAULT_ANCHOR=presigned"
            );
            Some(Arc::new(p))
        }
        Err(e) => {
            tracing::warn!(error = %e, "presign: object store misconfigured; presign disabled");
            None
        }
    }
}

impl AppState {
    /// Build the P0–P3 in-memory control plane with a freshly generated
    /// capability-signing key, an empty perimeter, and a self-signed Root CA.
    pub fn in_memory() -> Self {
        Self {
            metadata: Arc::new(MemoryMetadataStore::new()),
            signer: Arc::new(Ed25519Signer::generate()),
            ids: Arc::new(RandomIdSource::new()),
            clock: Arc::new(SystemClock::new()),
            intrusions: Arc::new(LedgerIntrusionSink::new()),
            responder: Arc::new(EscalatingThreatResponder::with_defaults()),
            ca: Arc::new(RcgenCertAuthority::generate().expect("generate VaultMesh Root CA")),
            naming: Arc::new(InMemoryNameRegistry::new()),
            presigner: build_presigner(),
        }
    }
}
