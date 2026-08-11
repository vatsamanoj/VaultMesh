//! Placement policy. In P2 this drives peer selection; the locality hint is an
//! **opaque** app-supplied string — VaultMesh never interprets it, so it still
//! learns nothing about tenants.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementPolicy {
    /// Opaque affinity hint (e.g. a hashed region tag). Never interpreted.
    pub locality_hint: Option<String>,
    /// Prefer nearby peers on read; the anchor is always the fallback.
    pub prefer_peers: bool,
}

impl PlacementPolicy {
    /// P0/anchor-only policy: never prefer peers, no locality hint.
    pub fn anchor_only() -> Self {
        Self {
            locality_hint: None,
            prefer_peers: false,
        }
    }
}
