//! Client-side content encryption. The app holds the secret; VaultMesh never
//! sees the key or the plaintext (zero-knowledge).

use crate::error::ClientError;
use adapter_crypto::AesGcmCryptographer;
use vault_ports::Cryptographer;

/// Wraps the default cryptographer with a per-namespace derived key. Construct
/// one per `(app secret, namespace)` and use it to encrypt before `put` and
/// decrypt after `get`.
pub struct ContentCipher {
    crypto: AesGcmCryptographer,
    key: [u8; 32],
}

impl ContentCipher {
    /// Derive the content key from an app-held `secret` bound to `namespace`.
    pub fn for_namespace(secret: &[u8], namespace: &str) -> Self {
        let crypto = AesGcmCryptographer::new();
        let key = crypto.derive_key(secret, namespace.as_bytes());
        Self { crypto, key }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, ClientError> {
        self.crypto
            .encrypt(&self.key, plaintext)
            .map_err(|e| ClientError::Crypto(e.to_string()))
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, ClientError> {
        self.crypto
            .decrypt(&self.key, ciphertext)
            .map_err(|e| ClientError::Crypto(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let c = ContentCipher::for_namespace(b"app-secret", "ns-1");
        let ct = c.encrypt(b"ledger backup").unwrap();
        assert_eq!(c.decrypt(&ct).unwrap(), b"ledger backup");
    }
}
