//! Base64 helpers for putting opaque bytes on the JSON wire.

use crate::error::ClientError;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;

pub fn b64_encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

pub fn b64_decode(s: &str) -> Result<Vec<u8>, ClientError> {
    STANDARD
        .decode(s)
        .map_err(|e| ClientError::Encoding(e.to_string()))
}
