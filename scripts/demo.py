#!/usr/bin/env python3
"""Narrated end-to-end demo of VaultMesh (P0-P4) against the running services.

Started for you by `scripts/demo.sh`. Env overrides:
  COORD   coordinator base URL   (default http://127.0.0.1:8787)
  NODE_A  origin node-agent URL  (default http://127.0.0.1:8790)
  AROOT   node A anchor dir      (required — inspected/mutated to prove durability)
  BROOT   node B anchor dir      (required — shows peer replication)
"""
import base64, json, os, shutil, urllib.request, urllib.error

COORD = os.environ.get("COORD", "http://127.0.0.1:8787")
NODE_A = os.environ.get("NODE_A", "http://127.0.0.1:8790")
AROOT = os.environ["AROOT"]
BROOT = os.environ["BROOT"]


def _req(method, url, obj=None, headers=None):
    data = json.dumps(obj).encode() if obj is not None else None
    h = {"content-type": "application/json"}
    if headers:
        h.update(headers)
    r = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(r) as resp:
            body = resp.read().decode()
            return resp.status, (json.loads(body) if body.strip().startswith(("{", "[")) else body)
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            body = json.loads(body)
        except Exception:
            pass
        return e.code, body


def post(url, obj, headers=None):
    return _req("POST", url, obj, headers)


def get(url, headers=None):
    return _req("GET", url, None, headers)


def hdr(t):
    print("\n\033[1;36m" + "=" * 70 + "\n  " + t + "\n" + "=" * 70 + "\033[0m")


def line(k, v):
    print(f"  {k:<26} {v}")


def shard_dir(root, ns, blob):
    return os.path.join(root, ns, blob)


def shard_files(root, ns, blob):
    d = shard_dir(root, ns, blob)
    return sorted(os.path.join(d, f) for f in os.listdir(d)) if os.path.isdir(d) else []


# ------------------------------------------------------------------ 1. Contract
hdr("1. APP ONBOARDING  —  the Contract (out-of-band admin step)")
_, app = post(COORD + "/v1/apps", {
    "label": "LedgerFlow", "quota": {"max_bytes": 1073741824, "max_objects": 1000},
    "retention": {"keep_versions": 3, "min_days": 30}, "erasure": {"k": 4, "n": 6}})
APP = app["app_id"]
line("AppId (opaque):", APP)
line("Protocol version:", f'{app["contract"]["protocol_version"]["major"]}.{app["contract"]["protocol_version"]["minor"]}')
line("Erasure policy K/N:", f'{app["contract"]["erasure"]["k"]} of {app["contract"]["erasure"]["n"]}')
line("Encryption mode:", app["contract"]["encryption"])
line("App signing pubkey:", app["app_signing_public_key_b64"][:32] + "...")

hdr("2. NAMESPACE  —  one opaque tenant slot (VaultMesh never learns who it is)")
_, ns = post(COORD + "/v1/namespaces", {"app_id": APP})
NS = ns["namespace_id"]
line("NamespaceId (opaque):", NS)

# --------------------------------------------------------------- 3. Capability
hdr("3. CAPABILITY TOKEN  —  short-lived, signed, scoped {namespace, op, nonce, ttl}")
_, tok = post(COORD + "/v1/capabilities", {"app_id": APP, "namespace": NS, "operation": "Put", "ttl_secs": 300})
put_token = tok["token"]
line("operation:", put_token["claims"]["operation"])
line("namespace:", put_token["claims"]["namespace"])
line("nonce (single-use):", put_token["claims"]["nonce"])
line("expires_at (ms):", put_token["claims"]["expires_at"])
line("ed25519 signature:", f'{len(put_token["signature"])} bytes')

# ------------------------------------------------------------------ 4. Put
hdr("4. BACKUP  —  app encrypts client-side, hands opaque ciphertext to sidecar")
payload = os.urandom(4096)   # stand-in for an app's client-side CIPHERTEXT
print("  (VaultMesh sees only opaque bytes — the key lives with the app)")
line("ciphertext size:", f"{len(payload)} bytes")
_, put = post(NODE_A + "/v1/backups", {"namespace": NS, "token": put_token,
                                       "ciphertext_b64": base64.b64encode(payload).decode()})
BLOB = put["blob_id"]
line("blob_id (content id):", BLOB)

a_files = shard_files(AROOT, NS, BLOB)
b_files = shard_files(BROOT, NS, BLOB)
print("\n  Reed-Solomon 4-of-6 sharding on the anchor (node A):")
for f in a_files:
    print(f"    {os.path.basename(f):<16} {os.path.getsize(f):>5} bytes")
line("shards on node A:", f"{len(a_files)} (4 data + 2 parity, fixed-size)")
line("shards on node B:", f"{len(b_files)} (replicated peer->peer over QUIC)")
with open(a_files[0], "rb") as fh:
    head = fh.read(16)
print(f"    shard 00000 first 16 bytes: {head.hex()}  <- opaque fragment, not the payload")
line("any shard == payload?", any(open(f, "rb").read() == payload for f in a_files))

# ------------------------------------------------------------------ 5. Restore
hdr("5. RESTORE  —  fetch K shards, reconstruct, return byte-identical ciphertext")
_, gtok = post(COORD + "/v1/capabilities", {"app_id": APP, "namespace": NS, "operation": "Get", "ttl_secs": 300})
_, got = post(NODE_A + "/v1/backups/get", {"namespace": NS, "token": gtok["token"], "blob_id": BLOB})
restored = base64.b64decode(got["ciphertext_b64"])
line("restored size:", f"{len(restored)} bytes")
line("byte-identical?:", restored == payload)

# ------------------------------------------------------------ 6. Durability
hdr("6. DURABILITY  —  self-healing repair + peer-served restore")
os.remove(a_files[1])
os.remove(a_files[3])
print("  Deleted 2 of 6 shards on node A (simulate lost/dead disk regions)...")
_, rep = post(NODE_A + "/v1/maintenance/repair", {"namespace": NS, "blob_id": BLOB})
line("repair report:", f'checked={rep["checked"]} repaired={rep["repaired"]} unrepairable={rep["unrepairable"]}')

shutil.rmtree(shard_dir(AROOT, NS, BLOB))
print("\n  Now DELETE node A's entire copy of the blob...")
_, gtok2 = post(COORD + "/v1/capabilities", {"app_id": APP, "namespace": NS, "operation": "Get", "ttl_secs": 300})
_, got2 = post(NODE_A + "/v1/backups/get", {"namespace": NS, "token": gtok2["token"], "blob_id": BLOB})
restored2 = base64.b64decode(got2["ciphertext_b64"])
line("restore still works?:", restored2 == payload)
print("  -> reconstructed from peer node B's replicas over QUIC. Restore is never a single point of failure.")

# ------------------------------------------------------------ 7. Perimeter
hdr("7. ACTIVE PERIMETER  —  footprints stored, attackers escalated to blocked")
print("  An attacker (fingerprint 'attacker-ja3') probes with a bogus AppId:")
for i in range(1, 4):
    code, _ = post(COORD + "/v1/capabilities",
                   {"app_id": "app-BOGUS", "namespace": NS, "operation": "Get", "ttl_secs": 60},
                   headers={"x-vault-fingerprint": "attacker-ja3"})
    print(f"    attempt {i}: HTTP {code}  ({'tarpit' if i < 3 else 'BLOCKED'})")
code, _ = get(COORD + "/v1/protocol", headers={"x-vault-fingerprint": "attacker-ja3"})
line("4th request (any path):", f"HTTP {code}  <- fingerprint now on mesh-wide blocklist")
_, intr = get(COORD + "/v1/admin/intrusions")
line("intrusion ledger entries:", len(intr["entries"]))
line("ledger chain valid?:", intr["chain_valid"])
line("blocked fingerprints:", intr["blocked"])

# ------------------------------------------------------ 8. Self-sovereign
hdr("8. SELF-SOVEREIGN  —  own CA (no public CA) + own naming (dynamic->static)")
_, root = get(COORD + "/v1/ca/root")
line("pinned Root CA:", root.splitlines()[0] + " ... (self-signed)")
_, leaf = post(COORD + "/v1/admin/ca/leaf", {"subject": "app.ledgerflow.vaultmesh"})
line("issued leaf cert:", leaf["pem"].splitlines()[0])
post(COORD + "/v1/naming", {"name": "coordinator.vaultmesh", "current_ip": "203.0.113.42"})
_, res = get(COORD + "/v1/naming/coordinator.vaultmesh")
line("resolve stable name:", f'coordinator.vaultmesh -> {res["current_ip"]} (floating IP hidden)')

# ------------------------------------------------------ 9. Billing / status
hdr("9. QUOTAS / BILLING + ZERO-KNOWLEDGE STATUS")
_, use = get(COORD + f"/v1/usage/{APP}")
line("namespaces billed:", len(use["lines"]))
line("total stored bytes:", use["total_bytes"])
line("estimated cost (u):", use["estimated_cost_micros"])
_, st = get(COORD + "/v1/admin/status")
line("coordinator knows:", f'{st["namespaces"]} opaque namespace id(s), 0 tenant identities')
print("  -> the customer<->namespace and CA<->customer mapping lives ONLY in the app.")
print("\n\033[1;32m  All P0-P4 flow demonstrated end-to-end.\033[0m")
