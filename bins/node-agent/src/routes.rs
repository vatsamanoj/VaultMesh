//! Localhost data-plane handlers. Payloads are ciphertext in both directions.

use crate::http::{bad_request, err, ApiError};
use crate::state::AppState;
use axum::extract::State;
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use vault_proto::{
    DeleteRequest, GetRequest, ListRequest, ListResponse, PutRequest, PutResponse, RestoredBlob,
};

pub async fn health() -> &'static str {
    "ok"
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
    let ciphertext = st
        .get
        .execute(&req.namespace, &req.token, &req.blob_id)
        .await
        .map_err(err)?;
    Ok(Json(RestoredBlob {
        blob_id: req.blob_id,
        ciphertext_b64: STANDARD.encode(ciphertext),
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
