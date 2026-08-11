//! Self-hosted naming / rendezvous (P3) implementing `NameResolver`.
//!
//! This is the **dynamic→static** mechanism: a DDNS agent on each dialable
//! machine `publish`es its current public IP under a stable VaultMesh name, and
//! clients `resolve` the stable name — the floating IP stays invisible to them.
//!
//! This adapter is the in-memory registry (the vendor-run rendezvous service).
//! A production deployment fronts it with the self-signed-TLS ingress and
//! requires each publisher to sign its update with its own node cert.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::RwLock;
use vault_ports::{NameResolver, PortError, PortResult};

#[derive(Default)]
pub struct InMemoryNameRegistry {
    table: RwLock<HashMap<String, String>>,
}

impl InMemoryNameRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of registered names.
    pub fn len(&self) -> usize {
        self.table.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait]
impl NameResolver for InMemoryNameRegistry {
    async fn resolve(&self, stable_name: &str) -> PortResult<String> {
        self.table
            .read()
            .unwrap()
            .get(stable_name)
            .cloned()
            .ok_or(PortError::NotFound)
    }

    async fn publish(&self, stable_name: &str, current_ip: &str) -> PortResult<()> {
        if stable_name.is_empty() || current_ip.is_empty() {
            return Err(PortError::Backend("empty name or ip".into()));
        }
        self.table
            .write()
            .unwrap()
            .insert(stable_name.to_string(), current_ip.to_string());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dynamic_ip_is_hidden_behind_a_stable_name() {
        let reg = InMemoryNameRegistry::new();
        assert!(matches!(
            reg.resolve("coordinator.vaultmesh").await,
            Err(PortError::NotFound)
        ));

        reg.publish("coordinator.vaultmesh", "198.51.100.7")
            .await
            .unwrap();
        assert_eq!(
            reg.resolve("coordinator.vaultmesh").await.unwrap(),
            "198.51.100.7"
        );

        // IP floats; the stable name re-resolves to the new address.
        reg.publish("coordinator.vaultmesh", "203.0.113.42")
            .await
            .unwrap();
        assert_eq!(
            reg.resolve("coordinator.vaultmesh").await.unwrap(),
            "203.0.113.42"
        );
    }
}
