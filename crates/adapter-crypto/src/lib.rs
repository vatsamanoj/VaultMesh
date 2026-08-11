//! Crypto + local-runtime adapters for VaultMesh.
//!
//! - [`AesGcmCryptographer`] — AES-256-GCM content encryption + HKDF key
//!   derivation + SHA-256 (implements `Cryptographer`).
//! - [`Ed25519Signer`] / [`Ed25519Verifier`] — capability-token signing and
//!   verification (implement `CapabilitySigner` / `AuthVerifier`).
//! - [`SystemClock`] / [`RandomIdSource`] — the local `Clock` / `IdSource`.

mod capability;
mod content;
mod runtime;

pub use capability::{Ed25519Signer, Ed25519Verifier};
pub use content::AesGcmCryptographer;
pub use runtime::{RandomIdSource, SystemClock};
