//! AES-256-GCM content cryptography + HKDF key derivation + SHA-256.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest, Sha256};
use vault_ports::{Cryptographer, PortError, PortResult, CONTENT_KEY_LEN};

const NONCE_LEN: usize = 12;

/// The default, dependency-free content cryptographer. Zero-knowledge: this runs
/// on the client side; VaultMesh servers only ever call [`sha256_hex`].
///
/// [`sha256_hex`]: Cryptographer::sha256_hex
#[derive(Clone, Default)]
pub struct AesGcmCryptographer;

impl AesGcmCryptographer {
    pub fn new() -> Self {
        Self
    }
}

impl Cryptographer for AesGcmCryptographer {
    fn derive_key(&self, secret: &[u8], context: &[u8]) -> [u8; CONTENT_KEY_LEN] {
        // Per-context subkeys: a leak of one namespace's key can't touch another.
        let hk = Hkdf::<Sha256>::new(None, secret);
        let mut key = [0u8; CONTENT_KEY_LEN];
        hk.expand(context, &mut key)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        key
    }

    fn encrypt(&self, key: &[u8; CONTENT_KEY_LEN], plaintext: &[u8]) -> PortResult<Vec<u8>> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| PortError::Crypto(format!("aes-gcm encrypt: {e}")))?;
        // Wire layout: nonce || ciphertext||tag
        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    fn decrypt(&self, key: &[u8; CONTENT_KEY_LEN], blob: &[u8]) -> PortResult<Vec<u8>> {
        if blob.len() < NONCE_LEN {
            return Err(PortError::Crypto("ciphertext shorter than nonce".into()));
        }
        let (nonce_bytes, ct) = blob.split_at(NONCE_LEN);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
        cipher
            .decrypt(Nonce::from_slice(nonce_bytes), ct)
            .map_err(|e| PortError::Crypto(format!("aes-gcm decrypt: {e}")))
    }

    fn sha256_hex(&self, bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hex::encode(hasher.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_derives_stable_keys() {
        let c = AesGcmCryptographer::new();
        let k = c.derive_key(b"app-secret", b"ns-1");
        assert_eq!(k, c.derive_key(b"app-secret", b"ns-1"));
        assert_ne!(k, c.derive_key(b"app-secret", b"ns-2"));

        let msg = b"the quick brown fox";
        let blob = c.encrypt(&k, msg).unwrap();
        assert_ne!(&blob[12..], &msg[..]); // actually encrypted
        assert_eq!(c.decrypt(&k, &blob).unwrap(), msg);
    }

    #[test]
    fn wrong_key_fails_decrypt() {
        let c = AesGcmCryptographer::new();
        let blob = c.encrypt(&c.derive_key(b"s", b"a"), b"secret").unwrap();
        assert!(c.decrypt(&c.derive_key(b"s", b"b"), &blob).is_err());
    }
}
