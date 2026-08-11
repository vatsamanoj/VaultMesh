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

## P2 — Peer mesh acceleration + locality  ← implemented

Node-agents store/serve shards for peers; download prefers peers, the anchor is
the fallback. Placement policy uses an app-supplied **opaque** locality hint —
VaultMesh still knows nothing about tenants.

Implemented here:
- `adapter-peer-http` (`PeerHttpTransport`) implements the `ShardTransport`
  port over HTTP; each node-agent exposes `/v1/peer/shards/{ns}/{blob}/{index}`
  (PUT to store a replica, GET to serve one) backed by its local anchor.
- `PutBackup` replicates each shard to configured peers after the authoritative
  anchor write, recording `ShardLocation::Peer` in the manifest. `GetBackup`
  prefers a shard's peer replicas, then falls back to the anchor — verifying
  SHA-256 from whichever source serves it.
- The anchor **always** holds the full set, so peers are a pure accelerator:
  peers offline never blocks a restore. Configure peers via `VAULT_PEERS`.

Drills (`crates/vault-app/tests/mesh.rs`): a put replicates every shard to the
peer and a restore is served from the peer even with the anchor copy deleted;
with peers offline the restore falls back to the anchor. A two-node smoke test
confirms real HTTP replication (both nodes hold all shards).

`NatBroker` (hole-punch / coordinator relay) remains declared; the outbound-only
HTTP transport needs no inbound port in dev, and direct QUIC transport is P4.

## P3 — Repair loop + health + quotas/billing + perimeter + self-sovereignty  ← implemented

Implemented here:
- **Repair loop** — `RepairShards` use-case reconstructs missing/corrupt shards
  on the anchor from the survivors (deterministic RS re-encode), re-replicating
  to peers. The node-agent exposes `POST /v1/maintenance/repair` and an optional
  background sweep (`VAULT_REPAIR_SECS`) over every known blob.
- **Active perimeter** — `adapter-perimeter`: a hash-chained, tamper-evident
  `IntrusionSink` (footprints) and an escalating `ThreatResponder`
  (allow → tarpit → block, keyed on fingerprint, backing a mesh-wide blocklist).
  Coordinator middleware records a footprint for every rejected request and
  blocks repeat offenders at the earliest layer. Admin views:
  `GET /v1/admin/intrusions`, `GET /v1/admin/status`.
- **Quotas/billing** — quotas enforced at `PutBackup`; `UsageReport` aggregates
  an app's namespaces into a statement (bytes, objects, quota headroom,
  estimated cost) at `GET /v1/usage/{app}`.
- **Self-signed CA** — `adapter-rcgen-ca` (`CertAuthority`): own Root CA,
  issue/rotate/revoke leaf certs, self-hosted revocation list. `GET /v1/ca/root`
  (pinned root), `POST /v1/admin/ca/leaf`.
- **Self-hosted naming** — `adapter-ddns` (`NameResolver`): the dynamic→static
  mechanism. `POST /v1/naming` (publish), `GET /v1/naming/{name}` (resolve).

Drills: `crates/vault-app/tests/repair.rs` (repair + unrepairable-beyond-parity)
plus each adapter's unit tests (tamper-evident chain, escalation, cert issuance,
name re-resolution). A live coordinator run exercises the perimeter, CA, naming,
and usage endpoints.

## P4 (optional) — direct P2P transport  ← implemented

Implemented here:
- `adapter-quic` (`QuicShardTransport` + `QuicShardServer`): node-agents transfer
  shards **directly over QUIC** (via `quinn`), dropping the coordinator-mediated
  hop of the P2 HTTP mesh. Peer↔peer transfers are end-to-end encrypted (TLS 1.3,
  forward secrecy) over VaultMesh's own self-signed, pinned trust — no public CA.
- `DirectNatBroker` (`NatBroker`): attempts a direct connection ("punch"); the
  coordinator relay remains the always-works fallback. No external STUN/TURN.
- The node-agent selects the transport at runtime (`VAULT_TRANSPORT=quic`) and
  starts a QUIC shard server (`VAULT_QUIC_ADDR`); the same use-cases drive it —
  only the adapter behind `ShardTransport` changes.

Drills (`crates/adapter-quic/tests/loopback.rs`): a real QUIC put→fetch round
trip, missing-shard → `NotFound`, and a NAT punch that succeeds against a live
peer and fails fast against a dead one. A live two-node run replicates all
shards over QUIC with byte-identical restore.

---

## Future consideration — high shard counts (Leopard / FFT Reed-Solomon)

**Not planned; documented so the future decision is informed.**

Our `adapter-reed-solomon` uses a classic **GF(2⁸)** coder
(`reed-solomon-erasure`), which is the right, simple choice for backup — but it
carries a hard mathematical ceiling: Reed-Solomon in GF(2⁸) has only 256 field
elements, so

```
data shards + parity shards ≤ 256
```

This is a non-issue for VaultMesh today: the default policy is **4-of-6** and
realistic policies are single/low-double digits — nowhere near the cap.

### When it would matter

Only under **extreme fan-out** — splitting a *large* object across *hundreds* of
independent nodes for maximum durability per byte stored. Two things change at
that scale:

- **The 256 ceiling** blocks `k + parity > 256` in GF(2⁸). Exceeding it requires
  a larger field, **GF(2¹⁶)** (up to 65,536 shards).
- **Speed.** Textbook Reed-Solomon is **O(n²)** (each parity shard combines all
  data shards); at hundreds/thousands of shards that is too slow. The
  **Leopard** algorithm computes RS with an FFT over the finite field, dropping
  encode/decode to **O(n log n)** while staying MDS (any `k` of `n`
  reconstruct). This is exactly what libraries like `klauspost/reedsolomon` do:
  classic GF(2⁸) for ≤256 shards, a Leopard GF(2¹⁶) engine above it.

### Why high shard counts are attractive (the payoff)

- **More durability at the *same* storage overhead.** Fix the parity/data ratio
  and raise `n`: `4-of-6` (33% overhead) survives 2 losses; `40-of-60` (same 33%)
  survives 20. Losses must cluster far more improbably to exceed the budget.
- **More independent failure domains** — a correlated outage takes out a smaller
  *fraction* of the shards.
- **Smaller shards** — more parallel transfer across peers and cheaper,
  finer-grained repair.

### Trade-offs (why it is not the default)

- Larger manifests (every shard's hash + location) and more placement
  coordination.
- No benefit for **small** objects — shards shrink until per-shard overhead
  (hashes, headers, round-trips) dominates. High shard counts pay off for large
  objects across many nodes only.
- FFT coders often want structured counts (padding toward powers of two).

### Upgrade path

Drop-in: implement a Leopard/FFT-based `ErasureCoder` (e.g. a GF(2¹⁶) coder)
and select it when `contract.erasure.n > 256`, keeping the GF(2⁸) coder for the
common small-`n` case. Because it sits behind the `ErasureCoder` port, **the
use-cases do not change** — same swap the rest of the system already relies on.

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
