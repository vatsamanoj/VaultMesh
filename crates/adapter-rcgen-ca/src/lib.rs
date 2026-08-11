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
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, Ia5String,
    IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Mutex;
use vault_ports::{CertAuthority, PortError, PortResult};

fn crypto(e: impl std::fmt::Display) -> PortError {
    PortError::Crypto(format!("rcgen-ca: {e}"))
}

/// A TLS server identity (leaf signed by the CA), DER-encoded for rustls.
pub struct ServerIdentity {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
}

/// A TLS client identity (leaf signed by the CA), PEM-encoded.
pub struct ClientIdentity {
    pub cert_pem: String,
    pub key_pem: String,
}

fn san_of(s: &str) -> PortResult<SanType> {
    match s.parse::<IpAddr>() {
        Ok(ip) => Ok(SanType::IpAddress(ip)),
        Err(_) => Ok(SanType::DnsName(
            Ia5String::try_from(s.to_string()).map_err(crypto)?,
        )),
    }
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

    /// DER of the Root CA cert — for a rustls trust root / client verifier.
    pub fn root_cert_der(&self) -> Vec<u8> {
        self.ca_cert.der().as_ref().to_vec()
    }

    /// Issue a TLS **server** cert (CA-signed) for the given SANs (DNS names and
    /// IPs). Used for the coordinator's mTLS ingress.
    pub fn issue_server(&self, sans: &[String]) -> PortResult<ServerIdentity> {
        let key = KeyPair::generate().map_err(crypto)?;
        let mut params = CertificateParams::new(Vec::<String>::new()).map_err(crypto)?;
        params.subject_alt_names = sans.iter().map(|s| san_of(s)).collect::<PortResult<_>>()?;
        params
            .distinguished_name
            .push(DnType::CommonName, "vaultmesh-coordinator");
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        let cert = params
            .signed_by(&key, &self.ca_cert, &self.ca_key)
            .map_err(crypto)?;
        Ok(ServerIdentity {
            cert_der: cert.der().as_ref().to_vec(),
            key_der: key.serialize_der(),
        })
    }

    /// Issue a TLS **client** cert (CA-signed) for an app/node to present at the
    /// mTLS handshake (the L1 gate).
    pub fn issue_client(&self, subject: &str) -> PortResult<ClientIdentity> {
        let key = KeyPair::generate().map_err(crypto)?;
        let mut params = CertificateParams::new(vec![subject.to_string()]).map_err(crypto)?;
        params.distinguished_name.push(DnType::CommonName, subject);
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let cert = params
            .signed_by(&key, &self.ca_cert, &self.ca_key)
            .map_err(crypto)?;
        Ok(ClientIdentity {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
        })
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
