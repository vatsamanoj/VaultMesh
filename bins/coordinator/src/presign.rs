//! Coordinator-issued anchor access. The coordinator holds the object-store
//! credentials and hands node-agents short-lived, path-scoped **presigned URLs**
//! per shard operation — so node-agents never hold the S3 keys and the anchor is
//! never reachable without a coordinator-issued URL. Delete-by-prefix runs here
//! too (it needs the credentials).

use crate::http::{err, ApiError};
use crate::state::AppState;
use axum::extract::State;
use axum::Json;
use std::time::Duration;
use vault_ports::{PortError, ShardRef};
use vault_proto::{DeleteBlobRequest, PresignOp, PresignRequest, PresignResponse};

/// URLs are valid for a few minutes — long enough for one transfer, no more.
const TTL_SECS: u64 = 300;

fn no_store() -> ApiError {
    err(PortError::Unavailable(
        "presign: no object store configured (set VAULT_S3_*)".into(),
    ))
}

pub async fn presign(
    State(st): State<AppState>,
    Json(req): Json<PresignRequest>,
) -> Result<Json<PresignResponse>, ApiError> {
    let presigner = st.presigner.as_ref().ok_or_else(no_store)?;
    let at = ShardRef::new(req.namespace, req.blob_id, req.index);
    let method = match req.op {
        PresignOp::Put => http::Method::PUT,
        PresignOp::Get => http::Method::GET,
    };
    let url = presigner
        .presign(method, &at, Duration::from_secs(TTL_SECS))
        .await
        .map_err(err)?;
    Ok(Json(PresignResponse {
        url,
        expires_secs: TTL_SECS,
    }))
}

pub async fn delete_blob(
    State(st): State<AppState>,
    Json(req): Json<DeleteBlobRequest>,
) -> Result<(), ApiError> {
    let presigner = st.presigner.as_ref().ok_or_else(no_store)?;
    presigner
        .delete_blob(&req.namespace, &req.blob_id)
        .await
        .map_err(err)
}
