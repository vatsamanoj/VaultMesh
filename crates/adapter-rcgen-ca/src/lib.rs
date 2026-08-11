//! Self-signed CA (P3) implementing `CertAuthority`.
//!
//! VaultMesh runs its own Root CA and signs everything itself: coordinator
//! server cert, per-app client certs, per-node certs. Trust is bootstrapped by
//! **pinning** the root in installers — stronger than public-CA TLS because
//! both ends are controlled. No Let's Encrypt, no public CA.
//!
//! Leaf certs are short-lived and revocable via a self-hosted list this adapter
//! serves. Here the root is generated in-process; a production deployment keeps
//! the root key offline and uses an online issuing intermediate.

use async_trait::async_trait;
use rcgen::{BasicConstraints, Certificate, CertificateParams, IsCa, KeyPair};
use std::collections::HashSet;
use std::sync::Mutex;
use vault_ports::{CertAuthority, PortError, PortResult};

fn crypto(e: impl std::fmt::Display) -> PortError {
    PortError::Crypto(format!("rcgen-ca: {e}"))
}

pub struct RcgenCertAuthority {
    ca_cert: Certificate,
    ca_key: KeyPair,
    revoked: Mutex<HashSet<String>>,
}

impl RcgenCertAuthority {
    /// Generate a fresh self-signed Root CA (MVP / tests).
    pub fn generate() -> PortResult<Self> {
        let ca_key = KeyPair::generate().map_err(crypto)?;
        let mut params =
            CertificateParams::new(vec!["VaultMesh Root CA".to_string()]).map_err(crypto)?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = params.self_signed(&ca_key).map_err(crypto)?;
        Ok(Self {
            ca_cert,
            ca_key,
            revoked: Mutex::new(HashSet::new()),
        })
    }

    /// The pinned Root CA certificate (PEM) baked into installers.
    pub fn root_pem(&self) -> String {
        self.ca_cert.pem()
    }
}

#[async_trait]
impl CertAuthority for RcgenCertAuthority {
    async fn issue_leaf(&self, subject: &str) -> PortResult<Vec<u8>> {
        let leaf_key = KeyPair::generate().map_err(crypto)?;
        let params = CertificateParams::new(vec![subject.to_string()]).map_err(crypto)?;
        let leaf = params
            .signed_by(&leaf_key, &self.ca_cert, &self.ca_key)
            .map_err(crypto)?;
        // Return the leaf cert + its private key, both PEM (the app pins the root
        // separately). The order is cert then key.
        let mut out = leaf.pem().into_bytes();
        out.extend_from_slice(leaf_key.serialize_pem().as_bytes());
        Ok(out)
    }

    async fn revoke(&self, serial: &str) -> PortResult<()> {
        self.revoked.lock().unwrap().insert(serial.to_string());
        Ok(())
    }

    async fn is_revoked(&self, serial: &str) -> PortResult<bool> {
        Ok(self.revoked.lock().unwrap().contains(serial))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn issues_leaf_and_exposes_root() {
        let ca = RcgenCertAuthority::generate().unwrap();
        assert!(ca.root_pem().contains("BEGIN CERTIFICATE"));

        let leaf = ca.issue_leaf("app.ledgerflow.vaultmesh").await.unwrap();
        let pem = String::from_utf8(leaf).unwrap();
        assert!(pem.contains("BEGIN CERTIFICATE"));
        assert!(pem.contains("PRIVATE KEY"));
    }

    #[tokio::test]
    async fn revocation_list_is_self_hosted() {
        let ca = RcgenCertAuthority::generate().unwrap();
        assert!(!ca.is_revoked("serial-1").await.unwrap());
        ca.revoke("serial-1").await.unwrap();
        assert!(ca.is_revoked("serial-1").await.unwrap());
        assert!(!ca.is_revoked("serial-2").await.unwrap());
    }
}
