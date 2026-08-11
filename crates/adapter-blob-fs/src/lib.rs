//! A filesystem-backed [`BlobAnchor`]. This is the P0 dev stand-in for the
//! production RustFS anchor (`adapter-rustfs`), behind the identical port — so
//! swapping to RustFS never touches the use-cases.
//!
//! Shards are written under `root/<namespace>/<blob_id>/<index>.shard`.

use async_trait::async_trait;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use vault_domain::{BlobId, NamespaceId};
use vault_ports::{BlobAnchor, PortError, PortResult, ShardRef};

pub struct FsBlobAnchor {
    root: PathBuf,
}

impl FsBlobAnchor {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn shard_path(&self, at: &ShardRef) -> PathBuf {
        self.root.join(at.object_key())
    }

    fn blob_dir(&self, namespace: &NamespaceId, blob_id: &BlobId) -> PathBuf {
        self.root.join(namespace.as_str()).join(blob_id.as_str())
    }
}

fn backend(e: std::io::Error) -> PortError {
    PortError::Backend(format!("blob-fs io: {e}"))
}

#[async_trait]
impl BlobAnchor for FsBlobAnchor {
    async fn put_shard(&self, at: &ShardRef, bytes: &[u8]) -> PortResult<()> {
        let path = self.shard_path(at);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(backend)?;
        }
        // Write to a temp file then rename for atomicity within the anchor.
        let tmp = path.with_extension("shard.tmp");
        tokio::fs::write(&tmp, bytes).await.map_err(backend)?;
        tokio::fs::rename(&tmp, &path).await.map_err(backend)?;
        Ok(())
    }

    async fn get_shard(&self, at: &ShardRef) -> PortResult<Vec<u8>> {
        match tokio::fs::read(self.shard_path(at)).await {
            Ok(bytes) => Ok(bytes),
            Err(e) if e.kind() == ErrorKind::NotFound => Err(PortError::NotFound),
            Err(e) => Err(backend(e)),
        }
    }

    async fn delete_blob(&self, namespace: &NamespaceId, blob_id: &BlobId) -> PortResult<()> {
        let dir = self.blob_dir(namespace, blob_id);
        match tokio::fs::remove_dir_all(&dir).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(backend(e)),
        }
    }
}

/// Whether a path exists (small helper for callers/tests).
pub async fn exists(path: impl AsRef<Path>) -> bool {
    tokio::fs::metadata(path).await.is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn put_get_delete_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let anchor = FsBlobAnchor::new(dir.path());
        let at = ShardRef::new(NamespaceId::new("ns1"), BlobId::new("b1"), 0);

        anchor.put_shard(&at, b"shard-bytes").await.unwrap();
        assert_eq!(anchor.get_shard(&at).await.unwrap(), b"shard-bytes");

        anchor
            .delete_blob(&NamespaceId::new("ns1"), &BlobId::new("b1"))
            .await
            .unwrap();
        assert!(matches!(
            anchor.get_shard(&at).await,
            Err(PortError::NotFound)
        ));
    }

    #[tokio::test]
    async fn missing_shard_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let anchor = FsBlobAnchor::new(dir.path());
        let at = ShardRef::new(NamespaceId::new("ns"), BlobId::new("nope"), 3);
        assert!(matches!(
            anchor.get_shard(&at).await,
            Err(PortError::NotFound)
        ));
    }
}
