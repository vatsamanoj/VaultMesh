//! VaultMesh coordinator — the control plane. P0 wiring: in-memory metadata,
//! an ed25519 capability signer, and the authoritative metadata endpoints.
//!
//! Bind address is `VAULT_COORDINATOR_ADDR` (default `127.0.0.1:8787`).

mod control;
mod http;
mod meta;
mod state;

use axum::routing::{get, post};
use axum::Router;
use state::AppState;
use std::net::SocketAddr;

fn router(state: AppState) -> Router {
    Router::new()
        // control plane
        .route("/health", get(control::health))
        .route("/v1/protocol", get(control::protocol))
        .route("/v1/coordinator/pubkey", get(control::pubkey))
        .route("/v1/apps", post(control::register_app))
        .route("/v1/namespaces", post(control::create_namespace))
        .route("/v1/capabilities", post(control::issue_capability))
        // authoritative metadata (private overlay / node-agent facing)
        .route("/v1/meta/contracts/:app", get(meta::get_contract))
        .route("/v1/meta/namespaces", post(meta::create_namespace))
        .route("/v1/meta/namespaces/:ns", get(meta::get_namespace))
        .route("/v1/meta/namespaces/:ns/usage", get(meta::namespace_usage))
        .route("/v1/meta/namespaces/:ns/blobs", get(meta::list_blobs))
        .route("/v1/meta/manifests", post(meta::put_manifest))
        .route(
            "/v1/meta/namespaces/:ns/manifests/:blob",
            get(meta::get_manifest),
        )
        .route(
            "/v1/meta/namespaces/:ns/manifests/:blob/delete",
            post(meta::delete_manifest),
        )
        .with_state(state)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let addr: SocketAddr = std::env::var("VAULT_COORDINATOR_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8787".into())
        .parse()?;

    let state = AppState::in_memory();
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "VaultMesh coordinator listening");
    axum::serve(listener, router(state)).await?;
    Ok(())
}
