# VaultMesh Architecture

VaultMesh follows **SOLID + hexagonal (ports & adapters)**. The domain core is
pure and depends only on **ports (traits)**; storage, transport, and crypto are
swappable **adapters**. Every file targets **≤500 lines**, enforced in CI.

## Layers

```
        ┌─────────────────────────────────────────────────────┐
        │  binaries: coordinator (control plane) · node-agent  │
        │            (per-machine sidecar)                     │
        └───────────────┬─────────────────────────────────────┘
                        │ wires
        ┌───────────────▼───────────────┐     ┌──────────────────────┐
        │  vault-app (use-cases)         │────►│  vault-ports (traits) │
        │  RegisterApp, IssueCapability, │     │  BlobAnchor,          │
        │  PutBackup, GetBackup, List... │     │  MetadataStore,       │
        └───────────────┬───────────────┘     │  Cryptographer,       │
                        │ depends on          │  ErasureCoder, Clock, │
        ┌───────────────▼───────────────┐     │  AuthVerifier, ...    │
        │  vault-domain (pure entities)  │     └──────────┬───────────┘
        │  no I/O, no tokio/sqlx/aws     │                │ implemented by
        └────────────────────────────────┘                ▼
                                              adapter-crypto / adapter-blob-fs
                                              adapter-memstore / adapter-erasure
                                              (later: adapter-rustfs, adapter-quic,
                                               adapter-postgres, adapter-ddns,
                                               adapter-rcgen-ca)
```

### Dependency rule (DIP)

- `vault-domain` imports **no** I/O crate. Verified in CI by grepping its
  `Cargo.toml` (see `docs/ROADMAP.md` → "Design-pattern check").
- `vault-app` depends on `vault-domain` + `vault-ports` **only** — never on a
  concrete adapter. This makes every use-case unit-testable with fakes.
- Adapters depend on ports and implement them (LSP): any adapter is
  substitutable behind its port, so a fake adapter passes the same use-case
  tests as the real one.

## Ports (traits)

| Port | Purpose | P0 adapter | Later adapter |
|------|---------|-----------|---------------|
| `BlobAnchor` | Authoritative full-set object store | `adapter-blob-fs` | `adapter-rustfs` |
| `MetadataStore` | Registry, namespaces, manifests | `adapter-memstore` | `adapter-postgres` |
| `Cryptographer` | AES-256-GCM + HKDF (client side) | `adapter-crypto` | HSM-backed |
| `ErasureCoder` | Shard / reconstruct | `adapter-erasure` (passthrough) | Reed-Solomon |
| `CapabilitySigner` / `AuthVerifier` | Sign/verify capability tokens | `adapter-crypto` (ed25519) | KMS/HSM signer |
| `Clock` | Testable time (TTL, nonce expiry) | system clock | — |
| `ShardTransport` | Peer mesh shard put/get | *(P2)* | `adapter-quic` |
| `NameResolver` | stable name → current IP (dynamic→static) | *(P3)* | `adapter-ddns` |
| `NatBroker` | hole-punch / coordinator relay | *(P2)* | `adapter-quic` |
| `CertAuthority` | issue/rotate/revoke certs | *(P3)* | `adapter-rcgen-ca` |

Ports for later phases are declared now (ISP: narrow, role-specific traits) so
the domain and use-cases are stable while adapters land phase by phase.

## Data plane vs control plane

- **node-agent** (sidecar) owns the localhost API an app calls. It receives
  already-encrypted ciphertext, erasure-codes it, writes shards to the
  `BlobAnchor`, and records a `Manifest`. On restore it fetches *K* shards,
  reconstructs, and returns the ciphertext. It connects **outbound only** to the
  coordinator, so a customer behind NAT needs no inbound port.
- **coordinator** (control plane) owns app registration, capability-token
  issuance, namespace ACLs, and (in the full system) the authoritative manifest
  store, placement, and repair scheduler.

In **P0** the node-agent holds a local `MetadataStore` + `BlobAnchor` so the
put/get loop runs without cross-service calls; the port boundaries are identical
to the full system, so the manifest store swaps to a coordinator-backed adapter
without touching the use-cases.

## Reliability model

- The **RustFS anchor** always holds the full shard set — restore is guaranteed
  from the anchor even with the entire peer mesh offline.
- The peer mesh is an **accelerator**: downloads prefer nearby peers and fall
  back to the anchor.
- **Reed-Solomon** erasure coding (P1) means any *K* of *N* shards reconstruct
  the blob. **Per-shard SHA-256** integrity catches tampering; a failed shard is
  repaired from the anchor.
