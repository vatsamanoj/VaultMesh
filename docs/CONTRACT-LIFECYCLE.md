# Contract lifecycle: set up, upload, download (with curl)

This walks the full path an application takes with VaultMesh: mint a **Contract**,
open a **namespace**, then **upload** and **download** — all with `curl`. Every
value is threaded through shell variables with `jq`, so you can paste the blocks
in order.

- **Control plane** — the coordinator (`:8787`): app registry, namespaces,
  capability tokens, authoritative metadata.
- **Data plane** — the node-agent (`:8790`): ciphertext in, ciphertext out.

The app encrypts **before** upload and decrypts **after** download; VaultMesh
only ever sees ciphertext (see `docs/SECURITY.md`). The examples below use plain
HTTP on localhost; for an mTLS deployment add the cert flags shown at the end.

```sh
CO=http://127.0.0.1:8787      # coordinator (control plane)
NODE=http://127.0.0.1:8790    # node-agent  (data plane)
```

## 1. Register the app → mint the Contract

The Contract is the machine-readable agreement: quota, erasure policy, retention,
and client-side-only encryption.

```sh
APP_JSON=$(curl -s -X POST "$CO/v1/apps" -H 'content-type: application/json' -d '{
  "label": "acme-backups",
  "quota":     { "max_bytes": 10737418240, "max_objects": 100000 },
  "retention": { "keep_versions": 3, "min_days": 30 },
  "erasure":   { "k": 4, "n": 6 }
}')
echo "$APP_JSON" | jq .
APP=$(echo "$APP_JSON" | jq -r '.app_id')
echo "app_id = $APP"
```

Response (shape):

```json
{
  "app_id": "app-1a2b…",
  "contract": {
    "app_id": "app-1a2b…",
    "protocol_version": { "major": 1, "minor": 0 },
    "quota":     { "max_bytes": 10737418240, "max_objects": 100000 },
    "retention": { "keep_versions": 3, "min_days": 30 },
    "erasure":   { "k": 4, "n": 6 },
    "encryption": "ClientSideOnly"
  },
  "app_signing_public_key_b64": "…"
}
```

- `label` is for operators only — never used for auth.
- `k`/`n` is the erasure policy: any **k** of **n** shards reconstruct a blob.
- `min_days` is a delete hold; `keep_versions` caps stored versions per file.

## 2. Open a namespace

One opaque namespace per tenant/install. VaultMesh never sees a tenant identity —
only this id.

```sh
NS=$(curl -s -X POST "$CO/v1/namespaces" -H 'content-type: application/json' \
       -d "{\"app_id\":\"$APP\"}" | jq -r '.namespace_id')
echo "namespace = $NS"
```

## 3. Read the Contract back (optional)

```sh
curl -s "$CO/v1/meta/contracts/$APP" | jq '.quota, .retention, .erasure'
```

## 4. Mint a capability token (per operation)

Every data-plane call carries a short-lived, coordinator-signed token scoped to
one `{namespace, operation}`. `operation` is one of `Put`, `Get`, `List`,
`Delete`.

```sh
mint() {  # usage: mint <Operation>  → prints the token JSON object
  curl -s -X POST "$CO/v1/capabilities" -H 'content-type: application/json' \
    -d "{\"app_id\":\"$APP\",\"namespace\":\"$NS\",\"operation\":\"$1\",\"ttl_secs\":300}" \
    | jq -c '.token'
}
```

A token is an object `{ "claims": {…}, "signature": [...] }`; the node-agent
verifies it against the coordinator's public key.

## 5. Upload (backup)

The app encrypts client-side, base64s the ciphertext, and POSTs it. **VaultMesh
treats the payload as opaque** — it shards and returns it verbatim, so for a
transport demo you can base64 any bytes; a real client sends its encrypted
envelope (see `scripts/vaultfile.py`, format `VMB1`).

Build the request body with `jq --rawfile` and post it from a file
(`--data @file`) — this keeps large payloads off the command line, which would
otherwise hit the shell's argument-length limit.

```sh
# demo "ciphertext" (a real app would encrypt first):
head -c 200000 /dev/urandom > /tmp/secret.bin
base64 -w0 < /tmp/secret.bin > /tmp/ct.b64

jq -n --arg ns "$NS" --argjson token "$(mint Put)" --rawfile ct /tmp/ct.b64 \
   '{namespace:$ns, token:$token, ciphertext_b64:($ct|rtrimstr("\n"))}' > /tmp/put.json

BLOB=$(curl -s -X POST "$NODE/v1/backups" -H 'content-type: application/json' \
        --data @/tmp/put.json | jq -r '.blob_id')
echo "blob_id = $BLOB"
```

On upload the node-agent verifies the token, checks the Contract **quota**,
erasure-codes the ciphertext into `n` shards (writing the full set to the anchor
and replicating to peers), and records a manifest on the coordinator. A blob that
would exceed quota is refused with `429 quota_exceeded`.

## 6. Inspect what's stored

```sh
# the app's own list (token-scoped, data plane):
curl -s -X POST "$NODE/v1/backups/list" -H 'content-type: application/json' \
  -d "{\"namespace\":\"$NS\",\"token\":$(mint List)}" | jq .

# metadata (control plane): shard count, ciphertext size, timestamp — never names:
curl -s "$CO/v1/meta/namespaces/$NS/manifests/$BLOB" | jq '{shards: (.shards|length), ciphertext_len, created_at}'

# namespace usage (bytes/objects billed):
curl -s "$CO/v1/meta/namespaces/$NS/usage" | jq .
```

## 7. Download (restore)

```sh
jq -n --arg ns "$NS" --argjson token "$(mint Get)" --arg blob "$BLOB" \
   '{namespace:$ns, token:$token, blob_id:$blob}' > /tmp/get.json

curl -s -X POST "$NODE/v1/backups/get" -H 'content-type: application/json' \
     --data @/tmp/get.json | jq -r '.ciphertext_b64' | base64 -d > /tmp/restored.bin

sha256sum /tmp/secret.bin /tmp/restored.bin   # identical
```

The node-agent fetches shards (peers preferred, anchor fallback), reconstructs
from any `k` of `n`, verifies each shard's SHA-256, and returns the ciphertext.
The app then decrypts it. Restore succeeds even if some shards or peers are gone.

## 8. Delete — and the retention hold

```sh
curl -s -o /dev/null -w '%{http_code}\n' -X POST "$NODE/v1/backups/delete" \
  -H 'content-type: application/json' \
  -d "{\"namespace\":\"$NS\",\"token\":$(mint Delete),\"blob_id\":\"$BLOB\"}"
```

With `min_days > 0`, a delete before the hold elapses is refused with
`403 retention_hold` (the blob's `created_at` + `min_days` hasn't passed). Set
`min_days: 0` in the Contract to allow immediate deletes.

## 9. Versions & pruning (`keep_versions`)

To let the server prune old versions without learning filenames, the client tags
each blob with an opaque `object_id = HMAC(index_key, filename)` where
`index_key = PBKDF2(passphrase, salt = namespace)` — stable across versions,
revealing nothing. It's published alongside the (encrypted) name:

```sh
# name_enc is a client-encrypted, length-padded filename (VMB1); object_id is the
# opaque version group. Both are opaque to the coordinator.
curl -s -X POST "$CO/v1/meta/namespaces/$NS/manifests/$BLOB/name" \
  -H 'content-type: application/json' \
  -d '{"name_enc":"<VMB1-base64>","object_id":"<hex-hmac>"}'

# prune older versions of that object beyond keep_versions (honors min_days):
curl -s -X POST "$NODE/v1/maintenance/prune" -H 'content-type: application/json' \
  -d "{\"namespace\":\"$NS\",\"object_id\":\"<hex-hmac>\"}" | jq .
# → { "object_id": "...", "versions": 4, "kept": 3, "pruned": 1, "held": 0 }
```

## 10. Maintenance: self-healing repair

```sh
curl -s -X POST "$NODE/v1/maintenance/repair" -H 'content-type: application/json' \
  -d "{\"namespace\":\"$NS\",\"blob_id\":\"$BLOB\"}" | jq .
# → { checked, healthy, repaired, still_bad, unrepairable }
```

Repair rebuilds missing/corrupt shards from the survivors (borrowing from peer
replicas when local survivors drop below `k`).

## What the Contract enforces, at a glance

| Contract field | Enforced on | Effect |
|---|---|---|
| `quota` | upload | reject over `max_bytes` / `max_objects` (`429`) |
| `erasure` `k`/`n` | upload | how each blob is sharded / how many losses it tolerates |
| `retention.min_days` | delete / prune | hold — no deletion until it elapses (`403`) |
| `retention.keep_versions` | prune | keep newest N versions of a file, delete older |
| `encryption` | always | `ClientSideOnly` — keys never reach VaultMesh |

## mTLS deployments

When the coordinator runs with `VAULT_TLS_MODE=mtls`, use `https://` and present
a CA-signed client cert on every call:

```sh
curl --cacert ca-root.pem --cert client.pem --key client.key \
     https://coordinator:8787/v1/meta/contracts/$APP
```

## The `vaultfile.py` equivalent

The reference client wraps this whole flow:

| Step | curl | `vaultfile.py` |
|---|---|---|
| 1–2 Contract + namespace | `/v1/apps`, `/v1/namespaces` | `init` |
| 5 upload | `/v1/backups` | `backup <file>` |
| 6 list | `/v1/backups/list` | `list` / `names` |
| 7 download | `/v1/backups/get` | `restore <name> <out>` |
| 8 delete | `/v1/backups/delete` | `delete <name>` |
| 9 versions | name publish + prune | done automatically on `backup` |
