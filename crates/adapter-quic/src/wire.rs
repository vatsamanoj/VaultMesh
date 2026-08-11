//! Tiny request/response framing for the QUIC shard protocol, carried on a
//! single bidirectional stream per request.

use vault_domain::{BlobId, NamespaceId};
use vault_ports::ShardRef;

/// ALPN protocol id for the VaultMesh peer overlay.
pub const ALPN: &[u8] = b"vaultmesh-p2p";
/// Max bytes read per stream (shards are small, fixed-size).
pub const MAX_FRAME: usize = 16 * 1024 * 1024;

pub const OP_GET: u8 = 0;
pub const OP_PUT: u8 = 1;

pub const ST_OK: u8 = 0;
pub const ST_NOT_FOUND: u8 = 1;
pub const ST_ERR: u8 = 2;

/// `namespace/blob/index` — a slash-joined shard key (ids never contain `/`).
pub fn shard_key(at: &ShardRef) -> String {
    format!("{}/{}/{}", at.namespace, at.blob_id, at.index)
}

/// Parse a `namespace/blob/index` key back into a `ShardRef`.
pub fn parse_key(key: &str) -> Option<ShardRef> {
    let mut it = key.split('/');
    let ns = it.next()?;
    let blob = it.next()?;
    let index: u16 = it.next()?.parse().ok()?;
    if it.next().is_some() {
        return None;
    }
    Some(ShardRef::new(
        NamespaceId::new(ns),
        BlobId::new(blob),
        index,
    ))
}

/// `[op:1][keylen:u16-be][key][payload]`
pub fn encode_request(op: u8, key: &str, payload: &[u8]) -> Vec<u8> {
    let kb = key.as_bytes();
    let mut v = Vec::with_capacity(3 + kb.len() + payload.len());
    v.push(op);
    v.extend_from_slice(&(kb.len() as u16).to_be_bytes());
    v.extend_from_slice(kb);
    v.extend_from_slice(payload);
    v
}

/// Inverse of [`encode_request`]. Returns `(op, key, payload)`.
pub fn parse_request(buf: &[u8]) -> Option<(u8, String, Vec<u8>)> {
    if buf.len() < 3 {
        return None;
    }
    let op = buf[0];
    let klen = u16::from_be_bytes([buf[1], buf[2]]) as usize;
    if buf.len() < 3 + klen {
        return None;
    }
    let key = String::from_utf8(buf[3..3 + klen].to_vec()).ok()?;
    Some((op, key, buf[3 + klen..].to_vec()))
}

/// `[status:1][payload]`
pub fn encode_response(status: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + payload.len());
    v.push(status);
    v.extend_from_slice(payload);
    v
}
