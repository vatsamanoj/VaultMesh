//! VaultMesh node-agent — the per-machine sidecar. Exposes the localhost data
//! plane (`put`/`get`/`list`/`delete` of ciphertext), stores shards in a local
//! blob anchor, and reads authoritative metadata from the coordinator.
//!
//! Env:
//! - `VAULT_NODE_ADDR`        bind address (default `127.0.0.1:8790`)
//! - `VAULT_COORDINATOR_URL`  control plane (default `http://127.0.0.1:8787`)
//! - `VAULT_ANCHOR_ROOT`      local shard directory (default `./.vaultmesh/anchor`)

mod http;
mod remote_meta;
mod routes;
mod state;

use adapter_blob_fs::FsBlobAnchor;
use adapter_crypto::{AesGcmCryptographer, Ed25519Verifier, RandomIdSource, SystemClock};
use adapter_reed_solomon::ReedSolomonCoder;
use axum::routing::{get, post};
use axum::Router;
use remote_meta::RemoteMetadataStore;
use state::AppState;
use std::net::SocketAddr;
use std::sync::Arc;
use vault_app::{DeleteBackup, GetBackup, ListBackups, PutBackup};
use vault_ports::{
    AuthVerifier, BlobAnchor, Clock, Cryptographer, ErasureCoder, IdSource, MetadataStore,
};
use vault_proto::CoordinatorKey;

/// Fetch the coordinator's capability-verification key so the node-agent can
/// verify tokens (L2). Retries briefly so startup ordering is forgiving.
async fn fetch_verifier(coordinator: &str) -> Result<Ed25519Verifier, Box<dyn std::error::Error>> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    let url = format!("{coordinator}/v1/coordinator/pubkey");
    let key: CoordinatorKey = reqwest::get(&url).await?.error_for_status()?.json().await?;
    let bytes = STANDARD.decode(key.public_key_b64)?;
    Ok(Ed25519Verifier::from_public_key(&bytes)?)
}

fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(routes::health))
        .route("/v1/backups", post(routes::put_backup))
        .route("/v1/backups/get", post(routes::get_backup))
        .route("/v1/backups/list", post(routes::list_backups))
        .route("/v1/backups/delete", post(routes::delete_backup))
        .with_state(state)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let addr: SocketAddr = std::env::var("VAULT_NODE_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8790".into())
        .parse()?;
    let coordinator =
        std::env::var("VAULT_COORDINATOR_URL").unwrap_or_else(|_| "http://127.0.0.1:8787".into());
    let anchor_root =
        std::env::var("VAULT_ANCHOR_ROOT").unwrap_or_else(|_| "./.vaultmesh/anchor".into());

    // Adapters behind their ports.
    let metadata: Arc<dyn MetadataStore> = Arc::new(RemoteMetadataStore::new(coordinator.clone()));
    let anchor: Arc<dyn BlobAnchor> = Arc::new(FsBlobAnchor::new(anchor_root));
    let erasure: Arc<dyn ErasureCoder> = Arc::new(ReedSolomonCoder::new());
    let crypto: Arc<dyn Cryptographer> = Arc::new(AesGcmCryptographer::new());
    let verifier: Arc<dyn AuthVerifier> = Arc::new(fetch_verifier(&coordinator).await?);
    let ids: Arc<dyn IdSource> = Arc::new(RandomIdSource::new());
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());

    // Data-plane use-cases.
    let state = AppState {
        put: Arc::new(PutBackup::new(
            metadata.clone(),
            anchor.clone(),
            erasure.clone(),
            crypto.clone(),
            verifier.clone(),
            ids.clone(),
            clock.clone(),
        )),
        get: Arc::new(GetBackup::new(
            metadata.clone(),
            anchor.clone(),
            erasure.clone(),
            crypto.clone(),
            verifier.clone(),
            clock.clone(),
        )),
        list: Arc::new(ListBackups::new(
            metadata.clone(),
            verifier.clone(),
            clock.clone(),
        )),
        delete: Arc::new(DeleteBackup::new(
            metadata.clone(),
            anchor.clone(),
            verifier.clone(),
            clock.clone(),
        )),
    };

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, %coordinator, "VaultMesh node-agent listening");
    axum::serve(listener, router(state)).await?;
    Ok(())
}
