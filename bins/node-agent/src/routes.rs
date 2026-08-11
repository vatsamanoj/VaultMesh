//! Localhost data-plane handlers. Payloads are ciphertext in both directions.

use crate::http::{bad_request, err, ApiError};
use crate::state::AppState;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use vault_app::{PruneReport, RepairReport};
use vault_domain::{BlobId, NamespaceId};
use vault_ports::ShardRef;
use vault_proto::{
    DeleteRequest, GetRequest, ListRequest, ListResponse, PruneRequest, PutRequest, PutResponse,
    RepairRequest, RestoredBlob,
};

pub async fn health() -> &'static str {
    "ok"
}

// --- P2 peer-mesh endpoints: store/serve shard replicas for peers ---
// These sit on the private overlay. A shard is opaque, fixed-size erasure-coded
// ciphertext, so a peer holding it learns nothing (see docs/SECURITY.md).

fn shard_ref(ns: String, blob: String, index: u16) -> ShardRef {
    ShardRef::new(NamespaceId::new(ns), BlobId::new(blob), index)
}

pub async fn peer_put_shard(
    State(st): State<AppState>,
    Path((ns, blob, index)): Path<(String, String, u16)>,
    body: Bytes,
) -> Result<(), ApiError> {
    st.anchor
        .put_shard(&shard_ref(ns, blob, index), &body)
        .await
        .map_err(err)
}

pub async fn peer_get_shard(
    State(st): State<AppState>,
    Path((ns, blob, index)): Path<(String, String, u16)>,
) -> Result<Bytes, ApiError> {
    let bytes = st
        .anchor
        .get_shard(&shard_ref(ns, blob, index))
        .await
        .map_err(err)?;
    Ok(Bytes::from(bytes))
}

/// Maintenance plane: self-healing repair of one blob's shards on the anchor.
pub async fn repair(
    State(st): State<AppState>,
    Json(req): Json<RepairRequest>,
) -> Result<Json<RepairReport>, ApiError> {
    let report = st
        .repair
        .execute(&req.namespace, &req.blob_id)
        .await
        .map_err(err)?;
    Ok(Json(report))
}

/// Maintenance plane: live status of the background repair sweep.
pub async fn sweep_status(State(st): State<AppState>) -> Json<crate::state::SweepStatus> {
    Json(st.sweep.lock().expect("sweep status lock").clone())
}

/// Maintenance plane: prune old versions of one opaque object group.
pub async fn prune(
    State(st): State<AppState>,
    Json(req): Json<PruneRequest>,
) -> Result<Json<PruneReport>, ApiError> {
    let report = st
        .prune
        .execute(&req.namespace, &req.object_id)
        .await
        .map_err(err)?;
    Ok(Json(report))
}

pub async fn put_backup(
    State(st): State<AppState>,
    Json(req): Json<PutRequest>,
) -> Result<Json<PutResponse>, ApiError> {
    let ciphertext = STANDARD
        .decode(&req.ciphertext_b64)
        .map_err(|e| bad_request(format!("ciphertext base64: {e}")))?;
    let blob_id = st
        .put
        .execute(&req.namespace, &req.token, &ciphertext)
        .await
        .map_err(err)?;
    Ok(Json(PutResponse { blob_id }))
}

pub async fn get_backup(
    State(st): State<AppState>,
    Json(req): Json<GetRequest>,
) -> Result<Json<RestoredBlob>, ApiError> {
    let outcome = st
        .get
        .restore(&req.namespace, &req.token, &req.blob_id)
        .await
        .map_err(err)?;
    // Reactive repair: if the read succeeded but the blob was degraded (some
    // shards missing/corrupt), heal it now — in the background, off the read
    // path — so active data never drifts toward the k-shard cliff between
    // scheduled sweeps. Any shards rebuilt are folded into the sweep counter so
    // the console indicator reflects reactive heals too.
    if outcome.shards_missing > 0 {
        let repair = st.repair.clone();
        let sweep = st.sweep.clone();
        let namespace = req.namespace.clone();
        let blob_id = req.blob_id.clone();
        tokio::spawn(async move {
            if let Ok(report) = repair.execute(&namespace, &blob_id).await {
                if report.repaired > 0 {
                    if let Ok(mut s) = sweep.lock() {
                        s.total_repaired += report.repaired as u64;
                    }
                }
            }
        });
    }
    Ok(Json(RestoredBlob {
        blob_id: req.blob_id,
        ciphertext_b64: STANDARD.encode(outcome.ciphertext),
    }))
}

pub async fn list_backups(
    State(st): State<AppState>,
    Json(req): Json<ListRequest>,
) -> Result<Json<ListResponse>, ApiError> {
    let blob_ids = st
        .list
        .execute(&req.namespace, &req.token)
        .await
        .map_err(err)?;
    Ok(Json(ListResponse { blob_ids }))
}

pub async fn delete_backup(
    State(st): State<AppState>,
    Json(req): Json<DeleteRequest>,
) -> Result<(), ApiError> {
    st.delete
        .execute(&req.namespace, &req.token, &req.blob_id)
        .await
        .map_err(err)
}
