# The VaultMesh Contract

The Contract is the **entire integration boundary** between VaultMesh and any
consuming app. An app depends on the `vault-client` SDK + this Contract, and on
**nothing else** inside VaultMesh.

## 1. App onboarding (out-of-band admin step)

An app registers once and receives:

- an **`AppId`** (opaque, random),
- an **app signing keypair** (the app proves control of its registration),
- a machine-readable **Contract document** describing:
  - `protocol_version` — the `vault-proto` version in force,
  - `namespace_quota` — per-namespace storage/object limits,
  - `retention` — retention policy,
  - `erasure` — `ErasureParams { k, n }`,
  - `encryption = client-side-only` — VaultMesh never holds content keys.

Registration is an admin operation on the **control plane**, never a runtime
coupling.

## 2. Namespaces

Multi-tenancy is `App → Namespace`. Each tenant/install of an app is a
**Namespace** under that app. Namespace ids are **opaque and random** — VaultMesh
never learns who a tenant *is*. The mapping `namespace → real identity` lives
**only inside the consuming app** (for LedgerFlow, the CA↔customer graph).

## 3. Per-request auth — capability tokens

Every data-plane request carries a short-lived **capability token**:

```
CapabilityToken {
    app_id:      AppId,
    namespace:   NamespaceId,
    operation:   Put | Get | List | Delete,
    nonce:       random, single-use,
    expires_at:  now + TTL (minutes),
    signature:   ed25519 over the above (coordinator key)
}
```

- Issued by the coordinator **only** to an authenticated app, **only** for its
  own namespaces.
- Scoped to one namespace + one operation.
- Replays are blocked by the signed `nonce + expires_at` freshness check.
- A stolen token is single-namespace, single-op, minutes-valid — tiny blast
  radius.

## 4. Wire protocol — `vault-proto`

`vault-proto` holds the **versioned** request/response types (serde) and is the
**only** shared surface between client and server. It carries a
`PROTOCOL_VERSION` (`major.minor`); a **minor** bump stays backward-compatible so
old `vault-client` builds keep interoperating.

Data-plane operations (localhost, app → node-agent):

| Op | Request | Response |
|----|---------|----------|
| `put` | `namespace`, `token`, `ciphertext` | `blob_id` |
| `get` | `namespace`, `token`, `blob_id` | `ciphertext` |
| `list` | `namespace`, `token` | `[blob_id]` |
| `delete` | `namespace`, `token`, `blob_id` | `ok` |

Control-plane operations (app/admin → coordinator): `register_app`,
`issue_capability`, plus admin-only `revoke`, `set_quota` (separate admin plane).

## 5. Keys & zero-knowledge

- **Content keys** are derived and held **entirely by the app** (HKDF from a
  secret only the app holds). VaultMesh never receives them.
- **Transport identity** is an mTLS cert from VaultMesh's own private CA.
- **Capability-signing key** is coordinator-side (HSM/KMS in production, OS
  keystore for MVP).

Because the app encrypts before upload, VaultMesh — even fully compromised —
yields only ciphertext.

## 6. Client integration recipe

```
# backup
ciphertext = app.encrypt(payload, app_content_key)
blob_id    = vault_client.put(namespace, token, ciphertext)
app.catalog[blob_id] = business_object   # app keeps its own id↔object map

# restore
ciphertext = vault_client.get(namespace, token, blob_id)
payload    = app.decrypt(ciphertext, app_content_key)   # byte-identical
```

VaultMesh returns only **opaque ids** on `list`; the app owns the
`blob_id ↔ business object` catalog and the `namespace → identity` mapping.
