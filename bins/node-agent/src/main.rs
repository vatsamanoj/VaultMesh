//! VaultMesh node-agent — the per-machine sidecar. Exposes the localhost data
//! plane (`put`/`get`/`list`/`delete` of ciphertext), stores shards in a local
//! blob anchor, and reads authoritative metadata from the coordinator.
//!
//! Env:
//! - `VAULT_NODE_ADDR`        bind address (default `127.0.0.1:8790`)
//! - `VAULT_COORDINATOR_URL`  control plane (default `http://127.0.0.1:8787`)
//! - `VAULT_ANCHOR`           `fs` (default), `rustfs`/`s3` for the object store,
//!   or `presigned` — holds NO S3 creds and fetches per-shard presigned URLs
//!   from the coordinator (the coordinator holds the credentials).
//! - `VAULT_ANCHOR_ROOT`      local shard directory (fs anchor; default `./.vaultmesh/anchor`).
//! - `VAULT_S3_*`             ENDPOINT/BUCKET/REGION/ACCESS_KEY/SECRET_KEY/ALLOW_HTTP for RustFS.
//! - `VAULT_PEERS`            comma-separated peer addresses for the mesh. HTTP
//!   base URLs (`http://host:8790`) by default, or `host:port` when QUIC.
//! - `VAULT_TRANSPORT`        `http` (default, P2) or `quic` (P4 direct P2P).
//! - `VAULT_QUIC_ADDR`        QUIC shard-server bind address (default `0.0.0.0:8791`).
//! - `VAULT_REPAIR_SECS`      background repair-sweep interval (0 disables).
//! - `VAULT_CLIENT_CERT`/`VAULT_CLIENT_KEY`/`VAULT_CA_CERT`  mTLS identity + CA
//!   the node-agent presents to (and trusts on) an mTLS coordinator.

mod cors;
mod http;
mod presigned_anchor;
mod remote_meta;
mod routes;
mod state;

use adapter_blob_fs::FsBlobAnchor;
use adapter_crypto::{AesGcmCryptographer, Ed25519Verifier, RandomIdSource, SystemClock};
use adapter_peer_http::PeerHttpTransport;
use adapter_quic::{QuicShardServer, QuicShardTransport};
use adapter_reed_solomon::ReedSolomonCoder;
use adapter_rustfs::{RustFsBlobAnchor, RustFsConfig};
use axum::routing::{get, post, put};
use axum::Router;
use remote_meta::RemoteMetadataStore;
use state::AppState;
use std::net::SocketAddr;
use std::sync::Arc;
use vault_app::{DeleteBackup, GetBackup, ListBackups, PutBackup, RepairShards};
use vault_domain::PlacementPolicy;
use vault_ports::{
    AuthVerifier, BlobAnchor, Clock, Cryptographer, ErasureCoder, IdSource, MetadataStore,
    ShardTransport,
};
use vault_proto::CoordinatorKey;

/// Build the HTTP client used for coordinator calls. When `VAULT_CLIENT_CERT` /
/// `VAULT_CLIENT_KEY` (and optionally `VAULT_CA_CERT`) are set, it carries an
/// mTLS client identity so it can pass the coordinator's L1 gate.
fn coordinator_client() -> Result<reqwest::Client, Box<dyn std::error::Error>> {
    let mut builder = reqwest::Client::builder();
    if let (Ok(cert), Ok(key)) = (
        std::env::var("VAULT_CLIENT_CERT"),
        std::env::var("VAULT_CLIENT_KEY"),
    ) {
        let mut pem = std::fs::read(cert)?;
        pem.extend_from_slice(&std::fs::read(key)?);
        builder = builder.identity(reqwest::Identity::from_pem(&pem)?);
    }
    if let Ok(ca) = std::env::var("VAULT_CA_CERT") {
        builder =
            builder.add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(ca)?)?);
    }
    Ok(builder.build()?)
}

/// Fetch the coordinator's capability-verification key so the node-agent can
/// verify tokens (L2). Retries with backoff so startup ordering is forgiving.
async fn fetch_verifier(
    client: &reqwest::Client,
    coordinator: &str,
) -> Result<Ed25519Verifier, Box<dyn std::error::Error>> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    let url = format!("{coordinator}/v1/coordinator/pubkey");
    let mut last_err: Option<Box<dyn std::error::Error>> = None;
    for attempt in 0..10 {
        match client
            .get(&url)
            .send()
            .await
            .and_then(|r| r.error_for_status())
        {
            Ok(resp) => {
                let key: CoordinatorKey = resp.json().await?;
                let bytes = STANDARD.decode(key.public_key_b64)?;
                return Ok(Ed25519Verifier::from_public_key(&bytes)?);
            }
            Err(e) => {
                last_err = Some(Box::new(e));
                tokio::time::sleep(std::time::Duration::from_millis(300 * (attempt + 1))).await;
            }
        }
    }
    Err(last_err.expect("at least one attempt failed"))
}

/// Periodically sweep every known blob and repair missing/corrupt shards on the
/// anchor — the "repair when nodes go dark" loop.
fn spawn_repair_sweep(
    metadata: Arc<dyn MetadataStore>,
    repair: Arc<RepairShards>,
    interval_secs: u64,
) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        loop {
            ticker.tick().await;
            let namespaces = match metadata.list_namespaces().await {
                Ok(ns) => ns,
                Err(e) => {
                    tracing::warn!(error = %e, "repair sweep: list_namespaces failed");
                    continue;
                }
            };
            for ns in namespaces {
                let blobs = metadata.list_blobs(&ns).await.unwrap_or_default();
                for blob in blobs {
                    match repair.execute(&ns, &blob).await {
                        Ok(r) if r.repaired > 0 || r.unrepairable => {
                            tracing::info!(
                                namespace = %ns, blob = %blob,
                                repaired = r.repaired, unrepairable = r.unrepairable,
                                "repair sweep"
                            );
                        }
                        Ok(_) => {}
                        Err(e) => tracing::warn!(blob = %blob, error = %e, "repair failed"),
                    }
                }
            }
        }
    });
}

/// Select the anchor from `VAULT_ANCHOR`:
/// - `presigned` → the coordinator-issued presigned-URL anchor, which holds NO
///   S3 credentials (it asks the coordinator for a short-lived URL per shard);
/// - `rustfs` / `s3` → the authoritative RustFS (S3-compatible) object store,
///   configured from `VAULT_S3_*` env;
/// - anything else (default) → the local filesystem stand-in.
fn build_anchor(
    anchor_root: &str,
    coordinator: &str,
    coord_client: &reqwest::Client,
) -> Result<Arc<dyn BlobAnchor>, Box<dyn std::error::Error>> {
    fn require(name: &str) -> Result<String, Box<dyn std::error::Error>> {
        std::env::var(name)
            .map_err(|_| format!("{name} is required for VAULT_ANCHOR=rustfs").into())
    }
    match std::env::var("VAULT_ANCHOR").ok().as_deref() {
        Some("presigned") => {
            tracing::info!(%coordinator, "anchor: coordinator-issued presigned URLs (no S3 creds)");
            Ok(Arc::new(presigned_anchor::PresignedBlobAnchor::new(
                coordinator,
                coord_client.clone(),
            )))
        }
        Some("rustfs") | Some("s3") => {
            let cfg = RustFsConfig {
                endpoint: require("VAULT_S3_ENDPOINT")?,
                bucket: require("VAULT_S3_BUCKET")?,
                region: std::env::var("VAULT_S3_REGION").unwrap_or_else(|_| "us-east-1".into()),
                access_key: require("VAULT_S3_ACCESS_KEY")?,
                secret_key: require("VAULT_S3_SECRET_KEY")?,
                allow_http: std::env::var("VAULT_S3_ALLOW_HTTP")
                    .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                    .unwrap_or(true),
            };
            tracing::info!(bucket = %cfg.bucket, endpoint = %cfg.endpoint, "anchor: RustFS (S3-compatible)");
            Ok(Arc::new(RustFsBlobAnchor::new(cfg)?))
        }
        _ => {
            tracing::info!(root = %anchor_root, "anchor: filesystem (dev stand-in)");
            Ok(Arc::new(FsBlobAnchor::new(anchor_root)))
        }
    }
}

fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(routes::health))
        .route("/v1/backups", post(routes::put_backup))
        .route("/v1/backups/get", post(routes::get_backup))
        .route("/v1/backups/list", post(routes::list_backups))
        .route("/v1/backups/delete", post(routes::delete_backup))
        // P2 peer-mesh shard replicas (private overlay).
        .route(
            "/v1/peer/shards/:ns/:blob/:index",
            put(routes::peer_put_shard).get(routes::peer_get_shard),
        )
        // Maintenance plane: on-demand self-healing repair.
        .route("/v1/maintenance/repair", post(routes::repair))
        // Let a browser chat client reach the data plane cross-origin.
        .layer(axum::middleware::from_fn(cors::permissive))
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
    let peers: Vec<String> = std::env::var("VAULT_PEERS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // Coordinator HTTP client (carries an mTLS identity if configured).
    let coord_client = coordinator_client()?;

    // Adapters behind their ports.
    let metadata: Arc<dyn MetadataStore> = Arc::new(RemoteMetadataStore::new(
        coordinator.clone(),
        coord_client.clone(),
    ));
    let anchor: Arc<dyn BlobAnchor> = build_anchor(&anchor_root, &coordinator, &coord_client)?;
    let erasure: Arc<dyn ErasureCoder> = Arc::new(ReedSolomonCoder::new());
    let crypto: Arc<dyn Cryptographer> = Arc::new(AesGcmCryptographer::new());
    let verifier: Arc<dyn AuthVerifier> =
        Arc::new(fetch_verifier(&coord_client, &coordinator).await?);
    let ids: Arc<dyn IdSource> = Arc::new(RandomIdSource::new());
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());

    // Peer transport: HTTP (P2, default) or direct QUIC (P4). With QUIC, also
    // start a QUIC shard server so peers can fetch/put directly.
    let transport: Arc<dyn ShardTransport> =
        if std::env::var("VAULT_TRANSPORT").as_deref() == Ok("quic") {
            let quic_addr = std::env::var("VAULT_QUIC_ADDR")
                .unwrap_or_else(|_| "0.0.0.0:8791".into())
                .parse()?;
            let server = QuicShardServer::bind(anchor.clone(), quic_addr)?;
            tracing::info!(addr = %server.local_addr()?, "VaultMesh QUIC shard server listening");
            tokio::spawn(server.run());
            Arc::new(QuicShardTransport::new()?)
        } else {
            Arc::new(PeerHttpTransport::new())
        };

    // Peers are accelerators only; the anchor always holds the full shard set.
    let placement = PlacementPolicy {
        locality_hint: None,
        prefer_peers: !peers.is_empty(),
    };

    let put = PutBackup::new(
        metadata.clone(),
        anchor.clone(),
        erasure.clone(),
        crypto.clone(),
        verifier.clone(),
        ids.clone(),
        clock.clone(),
    )
    .with_mesh(transport.clone(), peers.clone(), placement);
    let get = GetBackup::new(
        metadata.clone(),
        anchor.clone(),
        erasure.clone(),
        crypto.clone(),
        verifier.clone(),
        clock.clone(),
    )
    .with_mesh(transport.clone());
    let repair = RepairShards::new(
        metadata.clone(),
        anchor.clone(),
        erasure.clone(),
        crypto.clone(),
    )
    .with_mesh(transport.clone());

    // Data-plane + maintenance use-cases.
    let state = AppState {
        put: Arc::new(put),
        get: Arc::new(get),
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
        repair: Arc::new(repair),
        anchor: anchor.clone(),
    };

    // Optional background repair sweep (VAULT_REPAIR_SECS > 0 enables it).
    if let Some(interval) = std::env::var("VAULT_REPAIR_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|s| *s > 0)
    {
        spawn_repair_sweep(metadata.clone(), state.repair.clone(), interval);
    }

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, %coordinator, peers = peers.len(), "VaultMesh node-agent listening");
    axum::serve(listener, router(state)).await?;
    Ok(())
}
