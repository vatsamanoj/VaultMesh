//! Time and identity-generation ports. Kept behind traits so use-cases are
//! deterministic under test (a fake clock, a seeded id source).

use vault_domain::{Nonce, Timestamp};

/// Supplies the current time. The domain never reads the system clock directly.
pub trait Clock: Send + Sync {
    fn now(&self) -> Timestamp;
}

/// Generates opaque, random-looking identifiers and nonces. VaultMesh never
/// encodes tenant identity into an id, so this must be unpredictable.
pub trait IdSource: Send + Sync {
    /// A fresh opaque id, optionally with a human-facing prefix (e.g. "app").
    fn new_id(&self, prefix: &str) -> String;

    /// A fresh single-use nonce for a capability token.
    fn new_nonce(&self) -> Nonce {
        Nonce::new(self.new_id("nonce"))
    }
}
