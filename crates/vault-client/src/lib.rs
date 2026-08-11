//! `vault-client` — the thin SDK an app links against. It depends only on the
//! Contract (`vault-proto`) + this SDK, never on VaultMesh internals.
//!
//! It offers three things:
//! - [`ContentCipher`] — client-side AES-256-GCM so the app encrypts *before*
//!   upload (zero-knowledge; VaultMesh never sees the key or plaintext),
//! - [`CoordinatorClient`] — control plane: register, create namespace, issue
//!   capability tokens,
//! - [`NodeAgentClient`] — data plane: put/get/list/delete ciphertext over the
//!   localhost sidecar.

mod codec;
mod content;
mod control_client;
mod data_client;
mod error;

pub use codec::{b64_decode, b64_encode};
pub use content::ContentCipher;
pub use control_client::CoordinatorClient;
pub use data_client::NodeAgentClient;
pub use error::ClientError;

pub type ClientResult<T> = Result<T, ClientError>;
