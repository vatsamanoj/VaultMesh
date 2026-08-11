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

- **`presigned`** — the node-agent holds **no** S3 credentials at all. For each
  shard it asks the coordinator (which holds the creds) for a short-lived,
  path-scoped **presigned URL**, then transfers the shard directly to the object
  store. The S3 keys live only on the coordinator; the anchor is never reachable
  without a coordinator-issued URL.

```sh
# coordinator holds the S3 creds and mints presigned URLs:
VAULT_S3_ENDPOINT=http://rustfs-host:9000 VAULT_S3_BUCKET=vaultmesh \
VAULT_S3_ACCESS_KEY=... VAULT_S3_SECRET_KEY=...  coordinator

# node-agent holds NO S3 creds — just points at the coordinator:
VAULT_ANCHOR=presigned VAULT_COORDINATOR_URL=http://coordinator:8787  node-agent
```

URLs are valid for a few minutes (long enough for one transfer). Delete-by-blob
runs on the coordinator (it needs the creds) via `/v1/anchor/delete-blob`.
Verified end-to-end against a live S3 server: with the node-agent holding no S3
keys, a file's six shards were written through presigned URLs, restored
byte-identical, and a delete cleared every shard from the bucket.

## mTLS (the L1 gate)

The coordinator can require every caller to present a **client certificate
signed by the VaultMesh CA** — no/invalid cert → the TLS handshake fails and the
request never reaches app code. It's opt-in via `VAULT_TLS_MODE=mtls`:

```sh
VAULT_TLS_MODE=mtls VAULT_CERT_DIR=./certs coordinator
```

On startup it emits, into `VAULT_CERT_DIR`, the pinned Root CA plus a bootstrap
client identity (mirroring "installers bake the root"):

- `ca-root.pem` — pin this to trust the coordinator's server cert.
- `client.pem` + `client.key` — a CA-signed client cert to present.

Then point the node-agent and app at HTTPS + those certs:

```sh
# node-agent
VAULT_COORDINATOR_URL=https://coordinator:8787 \
VAULT_CA_CERT=./certs/ca-root.pem \
VAULT_CLIENT_CERT=./certs/client.pem VAULT_CLIENT_KEY=./certs/client.key  node-agent

# vaultfile.py (the app)
$env:VAULT_COORDINATOR_URL="https://coordinator:8787"
$env:VAULT_CA_CERT="ca-root.pem"; $env:VAULT_CLIENT_CERT="client.pem"; $env:VAULT_CLIENT_KEY="client.key"
```

Verified: a valid client cert → `HTTP 200`; **no** client cert → handshake
rejected (`certificate required`); a **different-CA** client cert → rejected
(`certificate unknown`). Backup/restore works unchanged over the mTLS channel.

`VAULT_TLS_SANS` (default `localhost,127.0.0.1`) sets the server cert's names.

## Operator console (browser UI)

The coordinator serves a self-contained web console at `/` — no build step, no
external assets. From a browser you can:

- **Enroll a node** — one click registers an app, allocates a namespace, and
  issues a CA-signed mTLS client identity; download `client.pem`/`client.key`/
  `ca-root.pem` and copy the ready-to-run node-agent command.
- **Nodes & namespaces** — see every opaque namespace with its object/byte counts.
- **Files** — browse the backups in a namespace: blob id, ciphertext size, shard
  count, and timestamp (never plaintext or filenames — those stay client-side).

```sh
coordinator                       # then open http://127.0.0.1:8787/
```

Enrollment is one endpoint too: `POST /v1/admin/enroll {"label":"alice-laptop"}`
returns `{app_id, namespace, client_cert_pem, client_key_pem, ca_root_pem}`.

The console is an **admin-plane** surface: serve it over localhost or the private
overlay. Because a browser can't easily present a client cert, run the console
plane in plain HTTP behind the overlay (or before enabling `VAULT_TLS_MODE=mtls`
on a public bind) rather than exposing it publicly.

## Self-hosting on your own machine (public IP + router, no cloud)

You do **not** need a cloud host or a "public HTTPS" certificate. VaultMesh's own
CA + mTLS *is* the trust root, so the only thing a remote user needs is to be
able to **reach** your coordinator. If you have a high-speed connection with a
public IP and control of your router, one machine can be the whole backend —
coordinator **and** anchor — reachable at a stable name via port-forward +
dynamic DNS. Trust comes from your CA; the network just has to carry the bytes.

**What crosses the internet:** node-agent → coordinator (metadata, tokens,
presigned-URL requests) and node-agent → anchor (encrypted shards). Both are
authenticated by your CA; content stays client-side encrypted.

### 1. A stable name for a changing IP (dynamic DNS)

Home/business links usually have a *dynamic* public IP. Point a free dynamic-DNS
hostname at it and keep it current (DuckDNS shown; any provider works):

```sh
# cron, every 5 min — keeps vault.duckdns.org pointed at your current IP
*/5 * * * * curl -s "https://www.duckdns.org/update?domains=vault&token=YOUR_TOKEN&ip="
```

### 2. Forward two ports on your router

Forward these TCP ports to the machine's LAN address (e.g. `192.168.1.20`):

- **8787** → coordinator (control plane)
- **9000** → the object store (RustFS/MinIO), so presigned URLs are reachable

An open port is not open access: the coordinator's mTLS gate rejects the TLS
handshake for anyone without a client cert you issued.

### 3. Run the anchor + coordinator on the machine

```sh
# object store on the same box (RustFS or any S3-compatible server on :9000)
#   create the bucket once, e.g. `vaultmesh`.

# coordinator: mTLS on, server cert valid for your public hostname,
# and S3 creds so it can mint presigned URLs.
VAULT_COORDINATOR_ADDR=0.0.0.0:8787 \
VAULT_TLS_MODE=mtls VAULT_CERT_DIR=./certs \
VAULT_TLS_SANS=vault.duckdns.org,localhost,127.0.0.1 \
VAULT_S3_ENDPOINT=https://vault.duckdns.org:9000 \
VAULT_S3_BUCKET=vaultmesh VAULT_S3_ACCESS_KEY=... VAULT_S3_SECRET_KEY=... \
  coordinator
```

`VAULT_TLS_SANS` **must** include your public hostname or node-agents will
reject the server cert. `VAULT_S3_ENDPOINT` **must** be the reachable hostname
(not `127.0.0.1`) — presigned URLs embed it, and the remote node-agent connects
to whatever host the URL names.

### 4. Enroll a remote user (hand them three things)

From `VAULT_CERT_DIR` the coordinator emits `ca-root.pem` + a `client.pem` /
`client.key`. Give each remote user: your **hostname**, the **`ca-root.pem`** to
pin, and a **client cert**. (This reference build emits one bootstrap client
cert; per-user certs are the next step — see below.)

### 5. The remote user's node-agent (no S3 creds needed)

```sh
VAULT_COORDINATOR_URL=https://vault.duckdns.org:8787 \
VAULT_CA_CERT=ca-root.pem \
VAULT_CLIENT_CERT=client.pem VAULT_CLIENT_KEY=client.key \
VAULT_ANCHOR=presigned \
  node-agent
```

Their app (`vaultfile.py`) then talks to `127.0.0.1:8790` and backs up files —
encrypted on their machine, sharded, and pushed to your anchor through
coordinator-issued presigned URLs. You host the bytes; you never see plaintext.

## Self-sovereign overlay with Nebula (zero third-party dependency)

The port-forward setup above exposes the coordinator (`:8787`) and anchor
(`:9000`) to the raw internet. A stronger, fully self-hosted alternative is to
put every machine on a private overlay with [Nebula](https://github.com/slackhq/nebula)
(MIT-licensed). Nebula depends on **no** external service — you run your own CA
and your own *lighthouse* (discovery + NAT hole-punch helper), so nothing
phones home. It mirrors VaultMesh's own model: your CA, your rendezvous, Noise +
AES-256-GCM on the wire. Your public-IP machine is the lighthouse; the coordinator
and anchor bind the **overlay** address and become unreachable from the public
internet. The only inbound you forward is **one UDP port (4242)** for the lighthouse.

```
  YOUR MACHINE (public IP)                       REMOTE USER
 ┌───────────────────────────────┐             ┌──────────────────────────┐
 │ nebula lighthouse  UDP :4242  ◀┼──hole-punch─┼▶ nebula host             │
 │ overlay 192.168.100.1          │             │  overlay 192.168.100.5   │
 │ coordinator  :8787  ◀──mTLS────┼─────────────┼─ node-agent              │
 │ RustFS anchor :9000 ◀presigned─┼─────────────┼─ VAULT_ANCHOR=presigned  │
 └───────────────────────────────┘             └──────────────────────────┘
   forward ONLY UDP 4242; 8787 + 9000 bind the overlay — no public exposure.
```

### 1. Create your Nebula CA (once, on any trusted box)

```sh
nebula-cert ca -name "VaultMesh Overlay CA"
# → ca.crt (distribute) + ca.key (keep offline/secret)
```

### 2. Sign a cert per machine

```sh
# the lighthouse (your public-IP machine) — overlay IP .1
nebula-cert sign -name "lighthouse" -ip "192.168.100.1/24"
# each remote user — a unique overlay IP
nebula-cert sign -name "user-alice" -ip "192.168.100.5/24" -groups "users"
```

Each user gets three files: `ca.crt`, their `host.crt`, their `host.key`.

### 3. Lighthouse config (your machine) — `config.yml`

```yaml
pki:
  ca: /etc/nebula/ca.crt
  cert: /etc/nebula/lighthouse.crt
  key: /etc/nebula/lighthouse.key
static_host_map: {}
lighthouse:
  am_lighthouse: true
listen:
  host: 0.0.0.0
  port: 4242
firewall:
  inbound:
    - { port: any, proto: any, group: any }   # tighten in production
  outbound:
    - { port: any, proto: any, host: any }
```

Forward **UDP 4242** on your router to this machine, then `nebula -config config.yml`.

### 4. Remote host config — `config.yml`

```yaml
pki:
  ca: ca.crt
  cert: user-alice.crt
  key: user-alice.key
static_host_map:
  "192.168.100.1": ["YOUR_PUBLIC_IP_OR_DDNS:4242"]   # where the lighthouse lives
lighthouse:
  am_lighthouse: false
  hosts: ["192.168.100.1"]
firewall:
  inbound:  [{ port: any, proto: any, group: any }]
  outbound: [{ port: any, proto: any, host: any }]
```

Run `nebula -config config.yml`; the host joins the overlay and can reach
`192.168.100.1`.

### 5. Bind VaultMesh to the overlay

On your machine, bind the coordinator and point the anchor endpoint at the
**overlay** address (so presigned URLs resolve on the overlay, never publicly):

```sh
VAULT_COORDINATOR_ADDR=192.168.100.1:8787 \
VAULT_TLS_MODE=mtls VAULT_TLS_SANS=192.168.100.1,localhost \
VAULT_S3_ENDPOINT=http://192.168.100.1:9000 \
VAULT_S3_BUCKET=vaultmesh VAULT_S3_ACCESS_KEY=... VAULT_S3_SECRET_KEY=... \
  coordinator
```

The remote node-agent then targets the overlay coordinator:

```sh
VAULT_COORDINATOR_URL=https://192.168.100.1:8787 \
VAULT_CA_CERT=ca-root.pem \
VAULT_CLIENT_CERT=client.pem VAULT_CLIENT_KEY=client.key \
VAULT_ANCHOR=presigned \
  node-agent
```

You now have three self-owned layers with no third party anywhere: Nebula
(Noise, your Nebula CA) → VaultMesh mTLS (your rcgen CA) → client-side
AES-256-GCM. Trade-off: every user installs the Nebula client and holds a
Nebula host cert **in addition to** the VaultMesh client cert — trivial for your
own fleet, heavier onboarding for arbitrary public customers.

**Helper scripts:** `scripts/nebula-overlay/` automates all of the above —
`setup-ca.sh` (own CA + lighthouse), `run-lighthouse.sh`, `run-anchor.sh`
(MinIO/S3 on the overlay), `run-backend.sh` (coordinator bound to the overlay),
and `enroll-user.sh <name> <overlay-ip>` (signs a host cert and builds a
ready-to-hand-off bundle). See `scripts/nebula-overlay/README.md`.

## Remaining hardening (this reference build)

- The `x-vault-fingerprint` header stands in for a real TLS JA3/JA4 fingerprint.

The ports/adapters architecture is built so each of these is a drop-in swap.
