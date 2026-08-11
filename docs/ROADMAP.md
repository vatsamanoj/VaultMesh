# VaultMesh Roadmap — reliability-first phasing

Ship durable value before mesh complexity.

## P0 — Contract + central-anchor MVP  ← this scaffold

`vault-proto` + `vault-domain`/`ports`/`app` skeleton, coordinator (app
registry, capability tokens), node-agent sidecar, a blob anchor. An app
registers, gets a namespace + token, and does `put`/`get` of a **whole encrypted
blob**. No mesh, no erasure yet.

**This alone is reliable, app-agnostic off-site backup/restore.**

Implemented here:
- pure `vault-domain` entities + policies (no I/O),
- `vault-ports` traits (incl. later-phase ports declared),
- `vault-app` use-cases: `RegisterApp`, `IssueCapability`, `PutBackup`,
  `GetBackup`, `ListBackups`,
- `adapter-crypto` (AES-256-GCM + HKDF, ed25519 capability signer/verifier),
- `adapter-blob-fs` (filesystem anchor — dev stand-in for RustFS),
- `adapter-memstore` (in-memory metadata store),
- `adapter-erasure` (P0 passthrough coder),
- `vault-client` SDK + `roundtrip` example,
- `coordinator` + `node-agent` axum binaries,
- integration tests + CI file-size gate.

## P1 — Erasure coding + integrity  ← implemented

Reed-Solomon shard onto the anchor; per-shard SHA-256 verify-on-restore. Proves
the shard/reassemble pipeline centrally.

Implemented here:
- `adapter-reed-solomon` (`ReedSolomonCoder`) — splits a blob into `k` data +
  `n − k` parity shards; **any `k` of `n`** reconstruct it. Fixed-size,
  zero-padded shards (uniform sizes leak nothing). Drops in behind the same
  `ErasureCoder` port — `node-agent` now defaults to Reed-Solomon 4-of-6
  (`ErasureParams::recommended()`); the P0 `adapter-erasure` passthrough remains
  for `k = 1`.
- Verify-on-restore treats a **corrupted** shard (SHA-256 mismatch) as an
  *erasure*, so Reed-Solomon reconstructs around it just like a lost shard, up
  to the `n − k` parity budget. Restore fails cleanly only when fewer than `k`
  valid shards remain.

Durability drills (in `crates/vault-app/tests/e2e.rs`): losing the full parity
budget still restores byte-identical; a corrupted-plus-missing pair within
budget is reconstructed; losing more than the parity budget fails with
`Unavailable`.

## P2 — Peer mesh acceleration + locality

Node-agents store/serve shards for peers; download prefers peers, anchor is
fallback. Placement policy uses an app-supplied **opaque** locality hint —
VaultMesh still knows nothing about tenants. Adds `adapter-quic`
(`ShardTransport` + `NatBroker`).

## P3 — Repair loop + health + quotas/billing + admin dashboard

Self-healing repair when nodes go dark; per-namespace quotas/billing; the
`ThreatResponder` + `IntrusionSink` perimeter; `adapter-ddns` (`NameResolver`)
and `adapter-rcgen-ca` (`CertAuthority`).

## P4 (optional) — direct P2P transport

QUIC hole-punching / libp2p to drop the coordinator relay, only if bandwidth
savings justify it.

---

## Verification drills (targets)

- **App-agnostic proof:** a throwaway non-LedgerFlow client registers, gets a
  token, backs up and restores arbitrary bytes → byte-identical.
- **Durability drill (P1+):** back up on A; take all peers + origin offline;
  restore on B from the anchor. Kill *K−1* shard-holders → erasure reconstructs.
  Corrupt a shard → integrity catches it, repair replaces it.
- **Isolation / zero-knowledge:** namespace A's token cannot read namespace B;
  on-disk shard is opaque; logs never contain plaintext.
- **Security drills:** no cert → handshake rejected; revoked cert rejected;
  expired/replayed token rejected; App-A cert+token denied App-B's namespace;
  RustFS unreachable from a public client; admin plane rejects an app cert.
- **Self-sovereignty drills:** change the coordinator IP → DDNS republishes,
  clients re-resolve with no config change; full loop runs air-gapped from any
  external CA/DNS/STUN; a leaf past its TTL auto-renews.
- **Contract stability:** bump `vault-proto` minor → old `vault-client` still
  interoperates.
- **File-size gate:** CI fails any Rust file > 500 lines.
- **Design-pattern check:** `vault-domain` has zero I/O-crate deps; every
  adapter is substitutable behind its port (a fake passes the same use-case
  tests).
