//! Crypto ports: content encryption (client side), erasure coding, and
//! capability-token signing/verification. These are synchronous — they are CPU
//! work, not I/O.

use crate::error::PortResult;
use vault_domain::{CapabilityClaims, CapabilityToken, ErasureParams};

/// Length of a derived content key (AES-256 ⇒ 32 bytes).
pub const CONTENT_KEY_LEN: usize = 32;

/// Client-side content cryptography. VaultMesh servers never call `encrypt`/
/// `decrypt` on plaintext — this lives with the app / `vault-client`. `sha256`
/// is used server-side for shard integrity.
pub trait Cryptographer: Send + Sync {
    /// HKDF-derive a 32-byte content key from an app secret + context (e.g. the
    /// namespace id), so a leak of one namespace's key never affects another.
    fn derive_key(&self, secret: &[u8], context: &[u8]) -> [u8; CONTENT_KEY_LEN];

    /// AES-256-GCM encrypt. Returns `nonce || ciphertext || tag` as one blob.
    fn encrypt(&self, key: &[u8; CONTENT_KEY_LEN], plaintext: &[u8]) -> PortResult<Vec<u8>>;

    /// AES-256-GCM decrypt of a `nonce || ciphertext || tag` blob.
    fn decrypt(&self, key: &[u8; CONTENT_KEY_LEN], blob: &[u8]) -> PortResult<Vec<u8>>;

    /// Hex-encoded SHA-256 digest, for per-shard integrity.
    fn sha256_hex(&self, bytes: &[u8]) -> String;
}

/// Splits a blob into `n` shards of which any `k` reconstruct it. The P0
/// adapter is a passthrough (`k=n=1`); the P1 adapter is Reed-Solomon.
pub trait ErasureCoder: Send + Sync {
    /// Encode `data` into exactly `params.n` shards (each fixed-size / padded).
    fn encode(&self, data: &[u8], params: ErasureParams) -> PortResult<Vec<Vec<u8>>>;

    /// Reconstruct the original `data_len` bytes from shards, where a missing
    /// shard is `None`. Fails if fewer than `params.k` shards are present.
    fn decode(
        &self,
        shards: &[Option<Vec<u8>>],
        params: ErasureParams,
        data_len: usize,
    ) -> PortResult<Vec<u8>>;
}

/// Signs capability tokens (coordinator side). The signing key is held in an
/// HSM/KMS in production, an OS keystore for MVP — never on disk in plaintext.
pub trait CapabilitySigner: Send + Sync {
    fn sign(&self, claims: CapabilityClaims) -> PortResult<CapabilityToken>;
    /// The public key used to verify tokens this signer produces.
    fn public_key(&self) -> Vec<u8>;
}

/// Verifies a capability token's signature (node-agent side). Combined with the
/// domain's `CapabilityToken::authorize`, this is the full L2 check.
pub trait AuthVerifier: Send + Sync {
    fn verify_signature(&self, token: &CapabilityToken) -> PortResult<()>;
}
