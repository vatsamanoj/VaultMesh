# Using VaultMesh for real (beyond the demo)

The demo backs up random bytes. This shows how a **real app** connects, how
**nodes** connect, and how **files** are uploaded and downloaded — plus a ready
file-backup client (`scripts/vaultfile.py`).

## The pieces and how they connect

```
   your app  ──localhost HTTP──►  node-agent (sidecar)  ──outbound HTTP──►  coordinator
 (encrypts a file)                 :8790 on same box                        :8787 (control plane)
                                        │  shards + stores                      │  registry, tokens,
                                        ▼                                       ▼  authoritative metadata
                                    anchor (storage)                     (issues capability tokens,
                                        ▲                                 owns namespace ACLs)
                                        │  QUIC / HTTP
                                   peer node-agents (other machines)
```

- **coordinator** (one, port **8787**) — the control plane. Registers apps,
  allocates namespaces, issues capability tokens, holds the authoritative
  metadata. Runs on a server you control.
- **node-agent** (one per machine, port **8790**) — the sidecar your app talks
  to over localhost. It shards, stores to the anchor, and replicates to peers.
  It connects **outbound only** to the coordinator, so it needs no inbound port.
- **anchor** — where shards live. In this build it's a local directory
  (`VAULT_ANCHOR_ROOT`); in production it's the RustFS object store on a server.
- **peers** — other node-agents. A node replicates shards to the peers listed in
  `VAULT_PEERS`, over QUIC (`VAULT_TRANSPORT=quic`) or HTTP.

## How your app connects

Two planes, two endpoints:

1. **Control plane → coordinator (`:8787`)**, done once / occasionally:
   - `POST /v1/apps` → register, get an opaque `app_id` + a Contract.
   - `POST /v1/namespaces` → get an opaque `namespace` (one per tenant/install).
   - `POST /v1/capabilities` → get a short-lived, signed **capability token**
     scoped to `{namespace, operation}` (`Put`/`Get`/`List`/`Delete`).
2. **Data plane → local node-agent (`:8790`)**, per file:
   - `POST /v1/backups` `{namespace, token, ciphertext_b64}` → `blob_id`.
   - `POST /v1/backups/get` `{namespace, token, blob_id}` → `ciphertext_b64`.
   - `POST /v1/backups/delete` `{namespace, token, blob_id}`.

**Your app encrypts before upload and decrypts after download.** VaultMesh only
ever sees opaque ciphertext — it never holds your key or plaintext. Your app also
keeps its own `name → blob_id` catalog (VaultMesh returns only opaque ids).

## Upload / download flow (what happens to a file)

**Upload:** app reads file → AES-256-GCM encrypts it with a key only the app
holds → sends the ciphertext to the node-agent → node-agent splits it
Reed-Solomon 4-of-6 into shards → writes them to the anchor → replicates to peers
→ returns a `blob_id`. The app stores `filename → blob_id`.

**Download:** app sends `blob_id` → node-agent fetches K shards (nearest peer
first, anchor as fallback), verifies each shard's SHA-256, reconstructs the
ciphertext → app decrypts it back to the original file, byte-identical.

## vaultfile.py — a ready file-backup client

A genuine consuming app. Requires `pip install cryptography`.

```sh
pip install cryptography
set VAULT_PASSPHRASE=your-secret-content-key        # Windows: set / PowerShell: $env:VAULT_PASSPHRASE

python vaultfile.py init                     # register app + namespace -> vault.json
python vaultfile.py backup C:\path\report.pdf
python vaultfile.py list
python vaultfile.py restore report.pdf D:\restored\report.pdf
python vaultfile.py delete report.pdf
```

It encrypts client-side (AES-256-GCM, key derived from `VAULT_PASSPHRASE` via
scrypt), uploads the ciphertext to the local node-agent, and records the
`name → blob_id` catalog in `vault.json`. **Keep `vault.json` and your
passphrase safe** — without the passphrase, restore is impossible (that's the
zero-knowledge guarantee working as intended).

## Multi-machine setup

Run the coordinator on a server, a node-agent on each machine that has data:

```sh
# server (control plane + shared anchor)
VAULT_COORDINATOR_ADDR=0.0.0.0:8787  coordinator

# each customer machine (sidecar for the local app)
VAULT_NODE_ADDR=127.0.0.1:8790 \
VAULT_COORDINATOR_URL=http://SERVER_IP:8787 \
VAULT_ANCHOR_ROOT=/var/lib/vaultmesh/anchor \
VAULT_TRANSPORT=quic VAULT_QUIC_ADDR=0.0.0.0:8791 \
VAULT_PEERS=OTHER_NODE_IP:8791  node-agent
```

Open **8787** (coordinator) to the node-agents, and the **QUIC port** between
peers. The app always talks to its **local** node-agent on `127.0.0.1:8790`.

## Storage: RustFS (S3) or local filesystem

The anchor is selectable via `VAULT_ANCHOR`:

- **`fs`** (default) — a local directory (`VAULT_ANCHOR_ROOT`). Fine for a single
  machine or a quick start.
- **`rustfs`** (or `s3`) — the authoritative **RustFS** object store over its
  S3-compatible API. This is true off-site storage; because RustFS speaks S3,
  the same config also works against MinIO or AWS S3.

```sh
VAULT_ANCHOR=rustfs \
VAULT_S3_ENDPOINT=http://rustfs-host:9000 \
VAULT_S3_BUCKET=vaultmesh \
VAULT_S3_REGION=us-east-1 \
VAULT_S3_ACCESS_KEY=... \
VAULT_S3_SECRET_KEY=... \
VAULT_S3_ALLOW_HTTP=true   # set false / omit when the endpoint is HTTPS
  node-agent
```

Create the bucket once, then start the node-agent — each shard lands as an object
at `s3://<bucket>/<namespace>/<blob>/<index>.shard`. Verified end-to-end: a real
file backed up via `vaultfile.py` stored its six shards in the bucket (no
plaintext in any of them) and restored byte-identical.

## Remaining hardening (this reference build)

- The self-signed CA exists, but the HTTP ingress does **not yet require mTLS
  client certs** — so L1 (client-cert) isn't enforced on the wire in this build.
  L2 (capability tokens), L3 (namespace ACL), and L4 (client-side encryption)
  are enforced.
- Node-agents talk to RustFS directly; hardening to coordinator-issued,
  path-scoped **presigned URLs** (so the anchor is never reachable by clients) is
  a later step behind the same `BlobAnchor` port.
- The `x-vault-fingerprint` header stands in for a real TLS JA3/JA4 fingerprint.

The ports/adapters architecture is built so each of these is a drop-in swap.
