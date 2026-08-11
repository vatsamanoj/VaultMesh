//! Opaque identifiers. VaultMesh never encodes tenant identity into an id — all
//! ids are opaque, random-looking strings. The mapping `id -> real identity`
//! lives only inside the consuming app.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Declares a newtype string id with the common conversions and `Display`.
macro_rules! string_id {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        pub struct $name(String);

        impl $name {
            /// Wrap an already-opaque string as this id.
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            /// Borrow the underlying string.
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Consume into the underlying string.
            pub fn into_string(self) -> String {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), &self.0)
            }
        }

        impl From<String> for $name {
            fn from(v: String) -> Self {
                Self(v)
            }
        }

        impl From<&str> for $name {
            fn from(v: &str) -> Self {
                Self(v.to_owned())
            }
        }
    };
}

string_id!(
    /// Identifies a registered application (e.g. "LedgerFlow"). Opaque + random.
    AppId
);
string_id!(
    /// Identifies one tenant/install of an app. Opaque + random; VaultMesh never
    /// learns what it *is*.
    NamespaceId
);
string_id!(
    /// Content-addressed, random blob identifier. No filename, no label.
    BlobId
);
string_id!(
    /// Single-use random nonce carried by a capability token for replay defence.
    Nonce
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_string() {
        let id = AppId::new("app-123");
        assert_eq!(id.as_str(), "app-123");
        assert_eq!(id.clone().into_string(), "app-123");
        assert_eq!(format!("{id}"), "app-123");
    }

    #[test]
    fn serializes_as_bare_string() {
        let id = BlobId::new("blob-xyz");
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"blob-xyz\"");
        let back: BlobId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, id);
    }
}
