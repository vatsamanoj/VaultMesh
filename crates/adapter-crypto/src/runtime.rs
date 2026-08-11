//! Local runtime adapters: the system clock and a random id source.

use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use vault_domain::Timestamp;
use vault_ports::{Clock, IdSource};

/// Reads wall-clock time as milliseconds since the Unix epoch.
#[derive(Clone, Default)]
pub struct SystemClock;

impl SystemClock {
    pub fn new() -> Self {
        Self
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        let ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        Timestamp::from_millis(ms)
    }
}

/// Generates opaque, unpredictable ids using UUIDv4. VaultMesh never encodes
/// tenant identity into an id, so unpredictability matters.
#[derive(Clone, Default)]
pub struct RandomIdSource;

impl RandomIdSource {
    pub fn new() -> Self {
        Self
    }
}

impl IdSource for RandomIdSource {
    fn new_id(&self, prefix: &str) -> String {
        format!("{prefix}-{}", Uuid::new_v4().simple())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique_and_prefixed() {
        let s = RandomIdSource::new();
        let a = s.new_id("blob");
        let b = s.new_id("blob");
        assert!(a.starts_with("blob-"));
        assert_ne!(a, b);
    }
}
