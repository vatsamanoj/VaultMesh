//! P1 Reed-Solomon erasure adapter behind the `ErasureCoder` port.
//!
//! A blob is split into `k` fixed-size data shards plus `n - k` parity shards;
//! **any `k` of the `n`** shards reconstruct it. This is a drop-in replacement
//! for the P0 passthrough coder — the use-cases never change.
//!
//! Errors vs erasures: Reed-Solomon corrects **erasures** (known-missing
//! shards), not silent bit-flips. VaultMesh converts a corrupted shard into an
//! erasure *before* decoding by verifying each shard's SHA-256 in `GetBackup`
//! and passing a failed shard as `None`. So a tampered shard is tolerated
//! exactly like a lost one, up to the `n - k` parity budget.

use reed_solomon_erasure::galois_8::ReedSolomon;
use vault_domain::ErasureParams;
use vault_ports::{ErasureCoder, PortError, PortResult};

#[derive(Clone, Default)]
pub struct ReedSolomonCoder;

impl ReedSolomonCoder {
    pub fn new() -> Self {
        Self
    }
}

fn rs_err(e: reed_solomon_erasure::Error) -> PortError {
    PortError::Backend(format!("reed-solomon: {e}"))
}

impl ErasureCoder for ReedSolomonCoder {
    fn encode(&self, data: &[u8], params: ErasureParams) -> PortResult<Vec<Vec<u8>>> {
        let k = params.k as usize;
        let n = params.n as usize;
        // Fixed-size, zero-padded shards: sizes are uniform so they leak nothing.
        let shard_size = data.len().div_ceil(k).max(1);

        let mut shards: Vec<Vec<u8>> = Vec::with_capacity(n);
        for i in 0..k {
            let start = i * shard_size;
            let mut shard = vec![0u8; shard_size];
            if start < data.len() {
                let end = (start + shard_size).min(data.len());
                shard[..end - start].copy_from_slice(&data[start..end]);
            }
            shards.push(shard);
        }
        for _ in k..n {
            shards.push(vec![0u8; shard_size]);
        }

        if n > k {
            ReedSolomon::new(k, n - k)
                .map_err(rs_err)?
                .encode(&mut shards)
                .map_err(rs_err)?;
        }
        Ok(shards)
    }

    fn decode(
        &self,
        shards: &[Option<Vec<u8>>],
        params: ErasureParams,
        data_len: usize,
    ) -> PortResult<Vec<u8>> {
        let k = params.k as usize;
        let n = params.n as usize;
        if shards.len() != n {
            return Err(PortError::Backend(format!(
                "expected {n} shard slots, got {}",
                shards.len()
            )));
        }

        let shard_size = shards
            .iter()
            .flatten()
            .map(|s| s.len())
            .next()
            .ok_or_else(|| PortError::Unavailable("no shards present".into()))?;
        let present = shards.iter().filter(|s| s.is_some()).count();
        if present < k {
            return Err(PortError::Unavailable(format!(
                "only {present} of {n} shards available (need k={k})"
            )));
        }

        let mut slots: Vec<Option<Vec<u8>>> = shards.to_vec();
        if n > k {
            ReedSolomon::new(k, n - k)
                .map_err(rs_err)?
                .reconstruct(&mut slots)
                .map_err(rs_err)?;
        }

        let mut out = Vec::with_capacity(k * shard_size);
        for slot in slots.iter().take(k) {
            let shard = slot
                .as_ref()
                .ok_or_else(|| PortError::Unavailable("missing data shard".into()))?;
            out.extend_from_slice(shard);
        }
        out.truncate(data_len);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn coder() -> ReedSolomonCoder {
        ReedSolomonCoder::new()
    }

    #[test]
    fn reconstructs_from_exactly_k_shards() {
        let params = ErasureParams::new(3, 5).unwrap();
        let data = b"reliability of restore is priority number one".to_vec();
        let shards = coder().encode(&data, params).unwrap();
        assert_eq!(shards.len(), 5);
        assert!(shards.iter().all(|s| s.len() == shards[0].len()));

        // Lose the 2 parity's worth (n-k=2): drop shards 1 and 3, keep 3 shards.
        let mut slots: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        slots[1] = None;
        slots[3] = None;
        let out = coder().decode(&slots, params, data.len()).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn fails_when_more_than_parity_lost() {
        let params = ErasureParams::new(3, 5).unwrap();
        let data = vec![7u8; 1000];
        let shards = coder().encode(&data, params).unwrap();
        let mut slots: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        // Lose 3 (> parity of 2) -> only 2 present < k=3.
        slots[0] = None;
        slots[1] = None;
        slots[2] = None;
        assert!(matches!(
            coder().decode(&slots, params, data.len()),
            Err(PortError::Unavailable(_))
        ));
    }

    #[test]
    fn handles_no_parity_and_empty_data() {
        // n == k: plain split, needs all shards.
        let params = ErasureParams::new(2, 2).unwrap();
        let data = b"abcd".to_vec();
        let shards = coder().encode(&data, params).unwrap();
        let slots: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        assert_eq!(coder().decode(&slots, params, data.len()).unwrap(), data);

        // Empty payload round-trips.
        let empty = coder().encode(&[], params).unwrap();
        let slots: Vec<Option<Vec<u8>>> = empty.into_iter().map(Some).collect();
        assert!(coder().decode(&slots, params, 0).unwrap().is_empty());
    }
}
