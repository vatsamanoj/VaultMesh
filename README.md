# VaultMesh

**A standalone, app-agnostic decentralized backup cloud — written in Rust.**

VaultMesh stores and restores *any files for any app*, flawlessly. It knows
nothing about accounting, health records, or any business domain: every payload
is an opaque, client-encrypted blob. Reliability of restore is priority #1.

VaultMesh is a **private, closed backend** — no public signup, no anonymous
access. Applications integrate through one formal **Contract** and never touch
VaultMesh internals. LedgerFlow is simply *one contracted app*.

> This repository is the VaultMesh product itself. It has **no dependency on any
> consuming app** and reaches into no client codebase. Apps depend on the
> `vault-client` SDK + the Contract — never the other way around.

---

## Why it exists

A consuming app (e.g. LedgerFlow) needs off-site **backup + restore-on-demand**
solved permanently. Local-disk-only backups die with the machine. VaultMesh is
the durable, zero-knowledge, self-sovereign off-site anchor — plus an optional
peer mesh for speed.

## Core principles

- **App-agnostic.** Multi-tenant by `App → Namespace`. VaultMesh never sees
  plaintext and never learns what a tenant *is*.
- **Contract-only integration.** App onboarding, capability tokens, and a
  stable versioned wire protocol (`vault-proto`) are the entire boundary.
- **Zero-knowledge.** Payloads are encrypted client-side with a key VaultMesh
  never holds. A full server compromise leaks zero plaintext.
- **Self-sovereign.** Own Root CA, own naming/rendezvous (dynamic→static), own
  NAT traversal. No public CA, no third-party DNS/STUN, no rented static IP.
- **Reliability-first.** RustFS anchor is the always-on authoritative full set;
  the peer mesh only accelerates. Reed-Solomon erasure coding + per-shard
  integrity means restore is guaranteed as long as any *K* shards survive.
- **SOLID + hexagonal.** A pure domain core depends only on ports (traits);
  storage/transport/crypto are swappable adapters. **≤500 lines per file**,
  enforced in CI.

## Architecture at a glance

```
 App (any language)  ──localhost HTTP + capability token──►  node-agent sidecar
                                                                   │  (Rust)
                                                                   ▼
                                          coordinator (control plane) ── RustFS anchor
                                                                   ▲   ▲
                                                            peer mesh (other namespaces)
```

Crate layout (a Cargo workspace of small, single-responsibility crates):

| Crate | Responsibility |
|-------|----------------|
| `vault-domain` | Pure entities + policies. **No I/O.** |
| `vault-ports` | Traits (ports): `BlobAnchor`, `ShardTransport`, `MetadataStore`, `Cryptographer`, `ErasureCoder`, `Clock`, `AuthVerifier`, `CapabilitySigner`, `NameResolver`, `NatBroker`, `CertAuthority`. |
| `vault-app` | Use-cases orchestrating ports: `RegisterApp`, `IssueCapability`, `PutBackup`, `GetBackup`, `ListBackups`. Depends on traits only. |
| `vault-proto` | Versioned wire contract types (serde). The only shared surface. |
| `adapter-crypto` | `Cryptographer` — AES-256-GCM + HKDF. |
| `adapter-blob-fs` | `BlobAnchor` — filesystem anchor (dev stand-in for RustFS). |
| `adapter-memstore` | `MetadataStore` — in-memory (P0/dev). |
| `adapter-erasure` | `ErasureCoder` — P0 passthrough (`k = 1`). |
| `adapter-reed-solomon` | `ErasureCoder` — P1 Reed-Solomon, any `k` of `n`. |
| `adapter-peer-http` | `ShardTransport` — P2 peer-mesh shard replication. |
| `vault-client` | Thin SDK apps link against (client-side encryption + sidecar calls). |
| `coordinator` (bin) | axum control plane: registry, capability tokens, manifests. |
| `node-agent` (bin) | Per-machine sidecar: localhost API, erasure, store/serve shards. |

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md),
[`docs/CONTRACT.md`](docs/CONTRACT.md), [`docs/SECURITY.md`](docs/SECURITY.md),
and [`docs/ROADMAP.md`](docs/ROADMAP.md).

## Status — P0 + P1 + P2 (anchor + erasure + peer mesh)

The workspace implements the **P0** slice: the Contract types, the pure domain
core, the ports, the use-cases (`RegisterApp`, `IssueCapability`, `PutBackup`,
`GetBackup`, `ListBackups`), real AES-256-GCM client-side encryption, a
filesystem blob anchor, an in-memory metadata store, a capability-token
signer/verifier (ed25519), and the `coordinator` + `node-agent` binaries wiring
it together.

**P1** adds **Reed-Solomon erasure coding** (`adapter-reed-solomon`, default
4-of-6) with per-shard SHA-256 verify-on-restore: any `k` of `n` shards
reconstruct a blob, and a corrupted shard is treated as an erasure so restore
survives it within the parity budget.

**P2** adds the **peer mesh** (`adapter-peer-http`): node-agents replicate and
serve shards for each other, restores prefer nearby peers, and the RustFS anchor
is always the authoritative fallback — so peers going offline never blocks a
restore. Configure peers with `VAULT_PEERS`.

**This alone is reliable, app-agnostic, off-site backup/restore.**

## Build & test

```sh
cargo build --workspace
cargo test  --workspace
./scripts/check-file-size.sh   # fails any Rust file > 500 lines
```

### Run the P0 loop locally

```sh
# 1. control plane
cargo run -p coordinator          # listens on 127.0.0.1:8787

# 2. per-machine sidecar
cargo run -p node-agent           # listens on 127.0.0.1:8790

# 3. app-agnostic proof (any client): see crates/vault-client/examples
cargo run -p vault-client --example roundtrip
```

## License

Proprietary — see [`LICENSE`](LICENSE). VaultMesh is a private, closed backend.
