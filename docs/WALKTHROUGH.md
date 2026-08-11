# VaultMesh — how it works (end-to-end walkthrough)

This is the whole system running end to end: a coordinator (control plane) plus
two QUIC-meshed node-agents, driven through one complete backup lifecycle and
every security layer.

## Run it yourself

```sh
./scripts/demo.sh
```

That builds the workspace, starts a coordinator + two node-agents (node A is the
origin; node B is a peer, connected over QUIC), runs a narrated walkthrough
(`scripts/demo.py`), then runs the real client-side-encryption roundtrip
example. Everything is torn down on exit. Requires `python3` and `curl`.

On **Windows** (PowerShell), run the equivalent:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\demo.ps1
```

Requires the Rust toolchain, `python` on `PATH`, and `curl.exe` (bundled with
Windows 10+). Prebuilt Windows binaries are also published on the
`windows-binaries` branch under `dist/windows-x86_64/`.

## The shape

An app talks **localhost** to a small Rust sidecar with a short-lived capability
token, and depends on nothing inside VaultMesh but the `vault-client` SDK. The
sidecar shards + stores to an always-on anchor, accelerated by a peer mesh.

```
 App (any language)  ──localhost HTTP + capability token──►  node-agent sidecar
                                                                   │  (Rust)
                                                                   ▼
                                          coordinator (control plane) ── RustFS anchor
                                                                   ▲   ▲
                                                     peer node-agents (QUIC mesh)
```

## What the walkthrough shows

Each step below is real output from a live run (`scripts/demo.sh`).

### 1–3 · The Contract boundary
An app registers once → an opaque `AppId` + a signed Contract
(`erasure 4-of-6`, `encryption = ClientSideOnly`). It creates an **opaque
namespace**, then asks the coordinator for a **capability token**: ed25519-signed,
scoped to `{namespace, Put, nonce, 300s}`. That is the entire integration
surface — the app never touches VaultMesh internals.

### 4 · Backup
The app hands over 4096 bytes of **ciphertext**. VaultMesh splits it
**Reed-Solomon 4-of-6** into six fixed-size 1024-byte shards on the anchor, and
replicates all six to peer node B **directly over QUIC**. Proof it is
zero-knowledge: `any shard == payload? → False`.

### 5 · Restore
Fetch K shards (preferring peers, anchor as fallback), verify each shard's
SHA-256, reconstruct → **byte-identical**.

### 6 · Durability
Delete 2 of 6 shards → the repair loop rebuilds them (`repaired 2`). Then delete
the origin's **entire** copy → the restore still succeeds, served from peer B
over QUIC. Restore is never a single point of failure.

### 7 · Active perimeter
An attacker fingerprint probing with a bogus AppId is tarpitted, then **blocked**
on the 3rd strike; the next request is refused before it reaches app logic. The
tamper-evident intrusion ledger records every footprint with a valid hash-chain.

### 8 · Self-sovereign
VaultMesh serves its own pinned Root CA (no public CA), issues a leaf cert, and
resolves a stable name to a floating IP — the dynamic→static mechanism.

### 9 · Billing, still zero-knowledge
Usage aggregates per opaque namespace; a full dump of the coordinator reveals
only random ids — **0 tenant identities**, no CA↔customer graph.

## Sample transcript

```
======================================================================
  1. APP ONBOARDING  —  the Contract (out-of-band admin step)
======================================================================
  AppId (opaque):            app-ac0b5482ae5b4d06a860e8b5bbda6d5b
  Erasure policy K/N:        4 of 6
  Encryption mode:           ClientSideOnly

======================================================================
  4. BACKUP  —  app encrypts client-side, hands opaque ciphertext to sidecar
======================================================================
  ciphertext size:           4096 bytes
  blob_id (content id):      blob-05287abe2cab47ad90d4184bf2988d78

  Reed-Solomon 4-of-6 sharding on the anchor (node A):
    00000.shard       1024 bytes
    00001.shard       1024 bytes
    00002.shard       1024 bytes
    00003.shard       1024 bytes
    00004.shard       1024 bytes
    00005.shard       1024 bytes
  shards on node A:          6 (4 data + 2 parity, fixed-size)
  shards on node B:          6 (replicated peer->peer over QUIC)
    shard 00000 first 16 bytes: bcdf70f6b6ba8b9050ccaad53c883305  <- opaque fragment
  any shard == payload?      False

======================================================================
  5. RESTORE  —  fetch K shards, reconstruct, return byte-identical ciphertext
======================================================================
  restored size:             4096 bytes
  byte-identical?:           True

======================================================================
  6. DURABILITY  —  self-healing repair + peer-served restore
======================================================================
  Deleted 2 of 6 shards on node A ...
  repair report:             checked=6 repaired=2 unrepairable=False
  Now DELETE node A's entire copy of the blob...
  restore still works?:      True
  -> reconstructed from peer node B's replicas over QUIC.

======================================================================
  7. ACTIVE PERIMETER  —  footprints stored, attackers escalated to blocked
======================================================================
    attempt 1: HTTP 403  (tarpit)
    attempt 2: HTTP 403  (tarpit)
    attempt 3: HTTP 403  (BLOCKED)
  4th request (any path):    HTTP 403  <- fingerprint now on mesh-wide blocklist
  intrusion ledger entries:  4
  ledger chain valid?:       True
  blocked fingerprints:      ['attacker-ja3']

======================================================================
  8. SELF-SOVEREIGN  —  own CA (no public CA) + own naming (dynamic->static)
======================================================================
  pinned Root CA:            -----BEGIN CERTIFICATE----- ... (self-signed)
  issued leaf cert:          -----BEGIN CERTIFICATE-----
  resolve stable name:       coordinator.vaultmesh -> 203.0.113.42 (floating IP hidden)

======================================================================
  9. QUOTAS / BILLING + ZERO-KNOWLEDGE STATUS
======================================================================
  coordinator knows:         1 opaque namespace id(s), 0 tenant identities

  BONUS: real client-side AES-256-GCM encrypt->put->get->decrypt path
  restore OK — byte-identical (57 bytes)
```

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the port/adapter map,
[`CONTRACT.md`](CONTRACT.md) for the integration boundary, [`SECURITY.md`](SECURITY.md)
for the full defense-in-depth model, and [`ROADMAP.md`](ROADMAP.md) for the
phase-by-phase build (P0–P4).
