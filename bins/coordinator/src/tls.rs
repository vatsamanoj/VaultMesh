//! mTLS ingress (L1): the coordinator presents a CA-signed server cert and
//! **requires** callers to present a client cert signed by the same VaultMesh
//! CA. No/invalid client cert → the TLS handshake fails and the request never
//! reaches app code. This is the hard "only my apps" gate from docs/SECURITY.md.

use adapter_rcgen_ca::RcgenCertAuthority;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use std::sync::Arc;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

/// Build a rustls `ServerConfig` that trusts only the VaultMesh CA for both the
/// server identity and (mandatory) client-certificate verification.
pub fn mtls_server_config(
    ca: &RcgenCertAuthority,
    sans: &[String],
) -> Result<ServerConfig, BoxErr> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    // Trust root for verifying CLIENT certs = the VaultMesh CA.
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(ca.root_cert_der()))?;
    // No `.allow_unauthenticated()` → a client cert is REQUIRED.
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone()).build()?;

    // Server identity: a CA-signed leaf for the coordinator's names.
    let srv = ca.issue_server(sans)?;
    let chain = vec![CertificateDer::from(srv.cert_der)];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(srv.key_der));

    let mut cfg = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(cfg)
}
