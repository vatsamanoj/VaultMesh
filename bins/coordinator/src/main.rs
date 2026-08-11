//! VaultMesh coordinator — the control plane. P0 wiring: in-memory metadata,
//! an ed25519 capability signer, and the authoritative metadata endpoints.
//!
//! Bind address is `VAULT_COORDINATOR_ADDR` (default `127.0.0.1:8787`).

mod admin;
mod control;
mod http;
mod meta;
mod perimeter;
mod state;
mod tls;

use axum::routing::{get, post};
use axum::Router;
use state::AppState;
use std::net::SocketAddr;
use std::sync::Arc;

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
        .route(
            "/v1/meta/namespaces",
            post(meta::create_namespace).get(meta::list_namespaces),
        )
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
        // admin / forensics plane
        .route("/v1/admin/status", get(admin::status))
        .route("/v1/admin/intrusions", get(admin::intrusions))
        .route("/v1/usage/:app", get(admin::usage))
        // self-sovereign CA + naming (P3)
        .route("/v1/ca/root", get(admin::ca_root))
        .route("/v1/admin/ca/leaf", post(admin::ca_issue))
        .route("/v1/naming", post(admin::naming_publish))
        .route("/v1/naming/:name", get(admin::naming_resolve))
        // active perimeter: record footprints + block repeat offenders
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            perimeter::guard,
        ))
        .with_state(state)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let addr: SocketAddr = std::env::var("VAULT_COORDINATOR_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8787".into())
        .parse()?;

    let state = AppState::in_memory();

    // L1 gate: opt-in mTLS ingress (VAULT_TLS_MODE=mtls). Off by default so the
    // demo/dev flows stay plain HTTP.
    if std::env::var("VAULT_TLS_MODE").as_deref() == Ok("mtls") {
        let sans: Vec<String> = std::env::var("VAULT_TLS_SANS")
            .unwrap_or_else(|_| "localhost,127.0.0.1".into())
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        // Emit the pinned Root CA + a bootstrap client cert so node-agents and
        // apps can enroll (mirrors "installers bake the root").
        let dir = std::env::var("VAULT_CERT_DIR").unwrap_or_else(|_| "./certs".into());
        std::fs::create_dir_all(&dir)?;
        std::fs::write(format!("{dir}/ca-root.pem"), state.ca.root_pem())?;
        let client = state.ca.issue_client("bootstrap-app")?;
        std::fs::write(format!("{dir}/client.pem"), &client.cert_pem)?;
        std::fs::write(format!("{dir}/client.key"), &client.key_pem)?;

        let cfg = tls::mtls_server_config(&state.ca, &sans)?;
        let rustls_config = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(cfg));
        tracing::info!(%addr, certs = %dir, "VaultMesh coordinator listening (mTLS — client cert REQUIRED)");
        axum_server::bind_rustls(addr, rustls_config)
            .serve(router(state).into_make_service())
            .await?;
    } else {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        tracing::info!(%addr, "VaultMesh coordinator listening (plain HTTP)");
        axum::serve(listener, router(state)).await?;
    }
    Ok(())
}
