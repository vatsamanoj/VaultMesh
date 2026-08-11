//! A namespace: one opaque tenant/install slot under an app.

use crate::ids::{AppId, NamespaceId};
use serde::{Deserialize, Serialize};

/// A namespace belongs to exactly one app. VaultMesh stores only the opaque
/// ids — never who the tenant is.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Namespace {
    pub id: NamespaceId,
    pub app_id: AppId,
}

impl Namespace {
    pub fn new(id: NamespaceId, app_id: AppId) -> Self {
        Self { id, app_id }
    }

    /// Server-side ACL primitive (L3): does `app` own this namespace?
    pub fn owned_by(&self, app: &AppId) -> bool {
        &self.app_id == app
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ownership_check() {
        let ns = Namespace::new(NamespaceId::new("ns-1"), AppId::new("app-a"));
        assert!(ns.owned_by(&AppId::new("app-a")));
        assert!(!ns.owned_by(&AppId::new("app-b")));
    }
}
