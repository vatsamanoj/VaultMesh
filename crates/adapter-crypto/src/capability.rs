//! ed25519 capability-token signing (coordinator) and verification (node-agent).

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use vault_domain::{CapabilityClaims, CapabilityToken};
use vault_ports::{AuthVerifier, CapabilitySigner, PortError, PortResult};

/// Signs capability tokens. In production the key lives in an HSM/KMS; for MVP
/// it is generated/loaded here.
pub struct Ed25519Signer {
    key: SigningKey,
}

impl Ed25519Signer {
    /// Generate a fresh signing key (MVP / tests).
    pub fn generate() -> Self {
        Self {
            key: SigningKey::generate(&mut rand::rngs::OsRng),
        }
    }

    /// Load a signing key from its 32 raw bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(bytes),
        }
    }

    /// The matching verifier for tokens this signer produces.
    pub fn verifier(&self) -> Ed25519Verifier {
        Ed25519Verifier {
            key: self.key.verifying_key(),
        }
    }
}

impl CapabilitySigner for Ed25519Signer {
    fn sign(&self, claims: CapabilityClaims) -> PortResult<CapabilityToken> {
        let sig = self.key.sign(&claims.canonical_bytes());
        Ok(CapabilityToken::new(claims, sig.to_bytes().to_vec()))
    }

    fn public_key(&self) -> Vec<u8> {
        self.key.verifying_key().to_bytes().to_vec()
    }
}

/// Verifies capability-token signatures against the coordinator's public key.
pub struct Ed25519Verifier {
    key: VerifyingKey,
}

impl Ed25519Verifier {
    /// Build from a 32-byte ed25519 public key.
    pub fn from_public_key(bytes: &[u8]) -> PortResult<Self> {
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| PortError::Crypto("public key must be 32 bytes".into()))?;
        let key = VerifyingKey::from_bytes(&arr)
            .map_err(|e| PortError::Crypto(format!("bad public key: {e}")))?;
        Ok(Self { key })
    }
}

impl AuthVerifier for Ed25519Verifier {
    fn verify_signature(&self, token: &CapabilityToken) -> PortResult<()> {
        let sig_bytes: [u8; 64] = token
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| PortError::Crypto("signature must be 64 bytes".into()))?;
        let sig = Signature::from_bytes(&sig_bytes);
        self.key
            .verify(&token.claims.canonical_bytes(), &sig)
            .map_err(|_| PortError::Crypto("capability signature invalid".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_domain::{AppId, NamespaceId, Nonce, Operation, Timestamp};

    fn claims() -> CapabilityClaims {
        CapabilityClaims::new(
            AppId::new("app"),
            NamespaceId::new("ns"),
            Operation::Put,
            Nonce::new("n"),
            Timestamp::from_millis(1_000),
        )
    }

    #[test]
    fn signs_and_verifies() {
        let signer = Ed25519Signer::generate();
        let token = signer.sign(claims()).unwrap();
        assert!(signer.verifier().verify_signature(&token).is_ok());
    }

    #[test]
    fn rejects_tampered_claims() {
        let signer = Ed25519Signer::generate();
        let mut token = signer.sign(claims()).unwrap();
        token.claims.namespace = NamespaceId::new("ns-evil");
        assert!(signer.verifier().verify_signature(&token).is_err());
    }

    #[test]
    fn rejects_foreign_signer() {
        let a = Ed25519Signer::generate();
        let b = Ed25519Signer::generate();
        let token = a.sign(claims()).unwrap();
        assert!(b.verifier().verify_signature(&token).is_err());
    }
}
