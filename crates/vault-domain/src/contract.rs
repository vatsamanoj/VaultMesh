//! The Contract entities — the machine-readable agreement handed to an app at
//! onboarding. See `docs/CONTRACT.md`.

use crate::error::DomainError;
use crate::ids::AppId;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Versioned wire-protocol version. A **minor** bump is backward compatible.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

impl ProtocolVersion {
    /// The protocol version this build speaks.
    pub const CURRENT: ProtocolVersion = ProtocolVersion { major: 1, minor: 0 };

    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    /// Whether `self` (a client) can talk to a server speaking `server`.
    /// Same major, and the client minor is `<=` the server minor.
    pub fn is_compatible_with(self, server: ProtocolVersion) -> bool {
        self.major == server.major && self.minor <= server.minor
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

impl fmt::Debug for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProtocolVersion({self})")
    }
}

/// Reed-Solomon parameters: any `k` of `n` shards reconstruct the blob.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErasureParams {
    /// Data shards required to reconstruct (`k >= 1`).
    pub k: u8,
    /// Total shards produced (`n >= k`).
    pub n: u8,
}

impl ErasureParams {
    pub fn new(k: u8, n: u8) -> Result<Self, DomainError> {
        if k == 0 || n < k {
            return Err(DomainError::InvalidErasureParams { k, n });
        }
        Ok(Self { k, n })
    }

    /// Number of shard losses that can still be tolerated.
    pub fn parity(self) -> u8 {
        self.n - self.k
    }

    /// P0 default: a single whole shard (no erasure yet).
    pub fn passthrough() -> Self {
        Self { k: 1, n: 1 }
    }

    /// A sensible P1 Reed-Solomon default: 4 data + 2 parity (tolerates any 2
    /// shard losses; restore needs any 4 of 6).
    pub fn recommended() -> Self {
        Self { k: 4, n: 6 }
    }
}

/// Per-namespace storage limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Quota {
    pub max_bytes: u64,
    pub max_objects: u64,
}

impl Quota {
    pub fn new(max_bytes: u64, max_objects: u64) -> Self {
        Self {
            max_bytes,
            max_objects,
        }
    }

    /// Whether adding `add_bytes` across `object_count` objects stays in bounds.
    pub fn admits(self, current_bytes: u64, object_count: u64, add_bytes: u64) -> bool {
        current_bytes.saturating_add(add_bytes) <= self.max_bytes && object_count < self.max_objects
    }
}

/// How long backups are retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionPolicy {
    pub keep_versions: u32,
    pub min_days: u32,
}

impl RetentionPolicy {
    pub fn new(keep_versions: u32, min_days: u32) -> Self {
        Self {
            keep_versions,
            min_days,
        }
    }
}

/// VaultMesh only ever supports client-side encryption — it never holds keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncryptionMode {
    /// Payloads are encrypted by the app before upload (zero-knowledge).
    ClientSideOnly,
}

/// The machine-readable Contract document issued to an app at onboarding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppContract {
    pub app_id: AppId,
    pub protocol_version: ProtocolVersion,
    pub quota: Quota,
    pub retention: RetentionPolicy,
    pub erasure: ErasureParams,
    pub encryption: EncryptionMode,
}

impl AppContract {
    pub fn new(
        app_id: AppId,
        quota: Quota,
        retention: RetentionPolicy,
        erasure: ErasureParams,
    ) -> Self {
        Self {
            app_id,
            protocol_version: ProtocolVersion::CURRENT,
            quota,
            retention,
            erasure,
            encryption: EncryptionMode::ClientSideOnly,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_erasure() {
        assert!(ErasureParams::new(0, 3).is_err());
        assert!(ErasureParams::new(4, 3).is_err());
        let ok = ErasureParams::new(3, 5).unwrap();
        assert_eq!(ok.parity(), 2);
    }

    #[test]
    fn protocol_minor_bump_is_compatible() {
        let client = ProtocolVersion::new(1, 0);
        let server = ProtocolVersion::new(1, 3);
        assert!(client.is_compatible_with(server));
        assert!(!ProtocolVersion::new(2, 0).is_compatible_with(server));
    }

    #[test]
    fn quota_admits_within_bounds() {
        let q = Quota::new(1000, 10);
        assert!(q.admits(900, 5, 100));
        assert!(!q.admits(950, 5, 100));
        assert!(!q.admits(0, 10, 1));
    }
}
