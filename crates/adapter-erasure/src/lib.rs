//! P0 erasure adapter: a passthrough/replication coder behind the
//! `ErasureCoder` port. It supports `k = 1` (any one shard reconstructs), which
//! covers the P0 "whole encrypted blob" story and even gives `n`-way
//! replication for free. Reed-Solomon (`k > 1`) arrives in P1 as a drop-in
//! adapter behind the same port — the use-cases do not change.

use vault_domain::ErasureParams;
use vault_ports::{ErasureCoder, PortError, PortResult};

#[derive(Clone, Default)]
pub struct PassthroughCoder;

impl PassthroughCoder {
    pub fn new() -> Self {
        Self
    }
}

impl ErasureCoder for PassthroughCoder {
    fn encode(&self, data: &[u8], params: ErasureParams) -> PortResult<Vec<Vec<u8>>> {
        if params.k != 1 {
            return Err(PortError::Backend(format!(
                "passthrough coder supports k=1 only (got k={}); use the Reed-Solomon adapter",
                params.k
            )));
        }
        // n identical copies: any single one reconstructs the blob.
        Ok((0..params.n.max(1)).map(|_| data.to_vec()).collect())
    }

    fn decode(
        &self,
        shards: &[Option<Vec<u8>>],
        params: ErasureParams,
        data_len: usize,
    ) -> PortResult<Vec<u8>> {
        if params.k != 1 {
            return Err(PortError::Backend(
                "passthrough coder supports k=1 only".into(),
            ));
        }
        let present = shards.iter().find_map(|s| s.as_ref());
        let bytes = present.ok_or_else(|| PortError::Unavailable("no shards present".into()))?;
        if bytes.len() < data_len {
            return Err(PortError::Integrity(format!(
                "shard too short: {} < {data_len}",
                bytes.len()
            )));
        }
        Ok(bytes[..data_len].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replicates_and_reconstructs_from_any_copy() {
        let coder = PassthroughCoder::new();
        let params = ErasureParams::new(1, 3).unwrap();
        let data = b"reliable restore".to_vec();

        let shards = coder.encode(&data, params).unwrap();
        assert_eq!(shards.len(), 3);

        // Drop two of the three shards; the survivor still reconstructs.
        let partial = vec![None, None, Some(shards[2].clone())];
        let out = coder.decode(&partial, params, data.len()).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn fails_when_no_shards() {
        let coder = PassthroughCoder::new();
        let params = ErasureParams::new(1, 2).unwrap();
        assert!(coder.decode(&[None, None], params, 4).is_err());
    }
}
