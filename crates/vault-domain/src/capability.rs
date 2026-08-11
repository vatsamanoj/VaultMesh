//! Capability tokens (L2 auth). A short-TTL, signed grant scoped to
//! `{namespace, operation, nonce, expiry}`. The domain models the *claims* and
//! the authorization/expiry policy; the actual signing/verifying is a port
//! (`CapabilitySigner` / `AuthVerifier`) implemented by a crypto adapter.

use crate::error::DomainError;
use crate::ids::{AppId, NamespaceId, Nonce};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Milliseconds since the Unix epoch. Supplied by a `Clock` port, never read
/// from the system clock inside the domain (keeps policy testable).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Timestamp(pub u64);

impl Timestamp {
    pub const fn from_millis(ms: u64) -> Self {
        Self(ms)
    }
    pub const fn as_millis(self) -> u64 {
        self.0
    }
    /// A timestamp `secs` seconds after `self`.
    pub fn plus_secs(self, secs: u64) -> Self {
        Self(self.0.saturating_add(secs.saturating_mul(1000)))
    }
}

impl fmt::Debug for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Timestamp({}ms)", self.0)
    }
}

/// The operation a token authorizes. Deliberately single-op per token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operation {
    Put,
    Get,
    List,
    Delete,
}

impl Operation {
    pub fn as_str(self) -> &'static str {
        match self {
            Operation::Put => "put",
            Operation::Get => "get",
            Operation::List => "list",
            Operation::Delete => "delete",
        }
    }
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The signable payload of a capability token.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityClaims {
    pub app_id: AppId,
    pub namespace: NamespaceId,
    pub operation: Operation,
    pub nonce: Nonce,
    pub expires_at: Timestamp,
}

impl CapabilityClaims {
    pub fn new(
        app_id: AppId,
        namespace: NamespaceId,
        operation: Operation,
        nonce: Nonce,
        expires_at: Timestamp,
    ) -> Self {
        Self {
            app_id,
            namespace,
            operation,
            nonce,
            expires_at,
        }
    }

    /// Canonical byte encoding signed by the coordinator and verified by nodes.
    /// Field-tagged and length-free-ambiguity-free so it is stable across
    /// versions and cannot be confused between fields.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        format!(
            "vaultmesh.cap.v1\napp={}\nns={}\nop={}\nnonce={}\nexp={}\n",
            self.app_id,
            self.namespace,
            self.operation,
            self.nonce,
            self.expires_at.as_millis(),
        )
        .into_bytes()
    }
}

/// A capability token: claims + a detached signature over `canonical_bytes()`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityToken {
    pub claims: CapabilityClaims,
    /// Signature bytes (scheme defined by the signer adapter, e.g. ed25519).
    pub signature: Vec<u8>,
}

impl CapabilityToken {
    pub fn new(claims: CapabilityClaims, signature: Vec<u8>) -> Self {
        Self { claims, signature }
    }

    pub fn is_expired(&self, now: Timestamp) -> bool {
        now >= self.claims.expires_at
    }

    /// Domain-level authorization check (independent of signature validity,
    /// which the `AuthVerifier` port checks). Enforces scope + freshness.
    pub fn authorize(
        &self,
        app: &AppId,
        namespace: &NamespaceId,
        operation: Operation,
        now: Timestamp,
    ) -> Result<(), DomainError> {
        if self.is_expired(now) {
            return Err(DomainError::TokenExpired);
        }
        if &self.claims.app_id != app {
            return Err(DomainError::Unauthorized);
        }
        if &self.claims.namespace != namespace {
            return Err(DomainError::NamespaceMismatch);
        }
        if self.claims.operation != operation {
            return Err(DomainError::OperationNotPermitted {
                granted: self.claims.operation,
                requested: operation,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(op: Operation, exp: u64) -> CapabilityClaims {
        CapabilityClaims::new(
            AppId::new("app-a"),
            NamespaceId::new("ns-1"),
            op,
            Nonce::new("n-1"),
            Timestamp::from_millis(exp),
        )
    }

    #[test]
    fn authorizes_matching_scope() {
        let tok = CapabilityToken::new(claims(Operation::Put, 10_000), vec![]);
        assert!(tok
            .authorize(
                &AppId::new("app-a"),
                &NamespaceId::new("ns-1"),
                Operation::Put,
                Timestamp::from_millis(5_000)
            )
            .is_ok());
    }

    #[test]
    fn rejects_expired_wrong_ns_and_op() {
        let tok = CapabilityToken::new(claims(Operation::Put, 10_000), vec![]);
        let now = Timestamp::from_millis(5_000);
        assert!(matches!(
            tok.authorize(
                &AppId::new("app-a"),
                &NamespaceId::new("ns-1"),
                Operation::Put,
                Timestamp::from_millis(10_000)
            ),
            Err(DomainError::TokenExpired)
        ));
        assert!(matches!(
            tok.authorize(
                &AppId::new("app-a"),
                &NamespaceId::new("ns-2"),
                Operation::Put,
                now
            ),
            Err(DomainError::NamespaceMismatch)
        ));
        assert!(matches!(
            tok.authorize(
                &AppId::new("app-a"),
                &NamespaceId::new("ns-1"),
                Operation::Get,
                now
            ),
            Err(DomainError::OperationNotPermitted { .. })
        ));
    }

    #[test]
    fn canonical_bytes_are_field_stable() {
        let c = claims(Operation::Get, 42);
        let s = String::from_utf8(c.canonical_bytes()).unwrap();
        assert!(s.contains("op=get"));
        assert!(s.contains("exp=42"));
    }
}
