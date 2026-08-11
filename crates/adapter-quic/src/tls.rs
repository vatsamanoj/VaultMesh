//! QUIC TLS setup over VaultMesh's own self-signed trust. The server presents a
//! freshly generated self-signed cert; the client trusts the overlay
//! (accept-any). A production deployment pins the VaultMesh root instead — the
//! wire protocol is unchanged.

use crate::wire::ALPN;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, ServerConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::sync::Arc;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Build the server config with a fresh self-signed cert.
pub fn server_config() -> Result<ServerConfig, BoxErr> {
    let cert = rcgen::generate_simple_self_signed(vec!["vaultmesh-node".to_string()])?;
    let cert_der = cert.cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));

    let mut sc = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)?;
    sc.alpn_protocols = vec![ALPN.to_vec()];
    Ok(ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(sc)?,
    )))
}

/// Build the client config that trusts the overlay (accept-any). A short idle
/// timeout means a dead/unpunchable peer fails fast, so the caller can fall
/// back to the anchor or relay quickly.
pub fn client_config() -> Result<ClientConfig, BoxErr> {
    let mut cc = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(TrustOverlay(provider())))
        .with_no_client_auth();
    cc.alpn_protocols = vec![ALPN.to_vec()];

    let mut client = ClientConfig::new(Arc::new(QuicClientConfig::try_from(cc)?));
    let mut transport = quinn::TransportConfig::default();
    let timeout = quinn::IdleTimeout::try_from(std::time::Duration::from_secs(4))?;
    transport.max_idle_timeout(Some(timeout));
    client.transport_config(Arc::new(transport));
    Ok(client)
}

/// Accepts any server certificate — trust is established at the overlay layer
/// (in production, by pinning the VaultMesh root). Signatures are still checked.
#[derive(Debug)]
struct TrustOverlay(Arc<CryptoProvider>);

impl ServerCertVerifier for TrustOverlay {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
