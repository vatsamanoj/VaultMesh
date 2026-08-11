//! Authoritative metadata endpoints. In the full system the coordinator owns
//! the manifest store; node-agents read/write it through these endpoints via
//! the `MetadataStore` port (see `bins/node-agent/src/remote_meta.rs`). On the
//! private overlay these sit behind the admin/control trust, not the public
//! data plane.

use crate::http::{err, ApiError};
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::Json;
use serde::Deserialize;
use vault_domain::{AppContract, BlobId, Manifest, Namespace, NamespaceId};
use vault_ports::{NamespaceUsage, PortError};

pub async fn list_namespaces(
    State(st): State<AppState>,
) -> Result<Json<Vec<NamespaceId>>, ApiError> {
    let ids = st.metadata.list_namespaces().await.map_err(err)?;
    Ok(Json(ids))
}

pub async fn get_contract(
    State(st): State<AppState>,
    Path(app): Path<String>,
) -> Result<Json<Option<AppContract>>, ApiError> {
    let contract = st.metadata.get_contract(&app.into()).await.map_err(err)?;
    Ok(Json(contract))
}

pub async fn create_namespace(
    State(st): State<AppState>,
    Json(ns): Json<Namespace>,
) -> Result<(), ApiError> {
    st.metadata.create_namespace(&ns).await.map_err(err)
}

pub async fn get_namespace(
    State(st): State<AppState>,
    Path(ns): Path<String>,
) -> Result<Json<Option<Namespace>>, ApiError> {
    let found = st
        .metadata
        .get_namespace(&NamespaceId::new(ns))
        .await
        .map_err(err)?;
    Ok(Json(found))
}

pub async fn namespace_usage(
    State(st): State<AppState>,
    Path(ns): Path<String>,
) -> Result<Json<NamespaceUsage>, ApiError> {
    let usage = st
        .metadata
        .namespace_usage(&NamespaceId::new(ns))
        .await
        .map_err(err)?;
    Ok(Json(usage))
}

pub async fn put_manifest(
    State(st): State<AppState>,
    Json(manifest): Json<Manifest>,
) -> Result<(), ApiError> {
    st.metadata.put_manifest(&manifest).await.map_err(err)
}

pub async fn get_manifest(
    State(st): State<AppState>,
    Path((ns, blob)): Path<(String, String)>,
) -> Result<Json<Option<Manifest>>, ApiError> {
    let found = st
        .metadata
        .get_manifest(&NamespaceId::new(ns), &BlobId::new(blob))
        .await
        .map_err(err)?;
    Ok(Json(found))
}

pub async fn list_blobs(
    State(st): State<AppState>,
    Path(ns): Path<String>,
) -> Result<Json<Vec<BlobId>>, ApiError> {
    let blobs = st
        .metadata
        .list_blobs(&NamespaceId::new(ns))
        .await
        .map_err(err)?;
    Ok(Json(blobs))
}

#[derive(Deserialize)]
pub struct SetNameRequest {
    /// base64 of a `VMB1` envelope encrypting the length-padded filename.
    pub name_enc: String,
}

/// Attach the client-encrypted filename to a manifest (the shared name index).
/// The coordinator stores it verbatim — it is ciphertext, so names stay
/// zero-knowledge while becoming visible to any client holding the vault key.
pub async fn set_manifest_name(
    State(st): State<AppState>,
    Path((ns, blob)): Path<(String, String)>,
    Json(req): Json<SetNameRequest>,
) -> Result<(), ApiError> {
    let (ns, blob) = (NamespaceId::new(ns), BlobId::new(blob));
    let mut manifest = st
        .metadata
        .get_manifest(&ns, &blob)
        .await
        .map_err(err)?
        .ok_or_else(|| err(PortError::NotFound))?;
    manifest.name_enc = Some(req.name_enc);
    st.metadata.put_manifest(&manifest).await.map_err(err)
}

pub async fn delete_manifest(
    State(st): State<AppState>,
    Path((ns, blob)): Path<(String, String)>,
) -> Result<(), ApiError> {
    st.metadata
        .delete_manifest(&NamespaceId::new(ns), &BlobId::new(blob))
        .await
        .map_err(err)
}
