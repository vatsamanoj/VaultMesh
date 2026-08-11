#!/usr/bin/env python3
"""vaultfile.py - a real file backup/restore client for VaultMesh.

This is a genuine "consuming app": it encrypts a file CLIENT-SIDE with
AES-256-GCM (key derived from your passphrase), hands the opaque ciphertext to
the local node-agent, and keeps its own name -> blob_id catalog. VaultMesh never
sees the passphrase, the key, or the plaintext. Restore fetches the ciphertext,
decrypts it, and writes the file back byte-identical.

Requires:  pip install cryptography

Usage:
  python vaultfile.py init                       # register app + namespace (writes vault.json)
  python vaultfile.py backup <path> [name]       # encrypt + upload a real file
  python vaultfile.py list                        # list what you've stored
  python vaultfile.py restore <name> <out-path>  # download + decrypt
  python vaultfile.py delete <name>              # remove a stored file

Environment:
  VAULT_COORDINATOR_URL   control plane   (default http://127.0.0.1:8787)
  VAULT_SIDECAR_URL       local node-agent (default http://127.0.0.1:8790)
  VAULT_PASSPHRASE        your content key (required for backup/restore)
"""
import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.request

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

COORD = os.environ.get("VAULT_COORDINATOR_URL", "http://127.0.0.1:8787")
SIDECAR = os.environ.get("VAULT_SIDECAR_URL", "http://127.0.0.1:8790")
CONFIG = os.environ.get("VAULT_CONFIG", "vault.json")


def _tls_context():
    """mTLS client identity for an https coordinator (VAULT_CLIENT_CERT/KEY/CA)."""
    cert = os.environ.get("VAULT_CLIENT_CERT")
    if not cert:
        return None
    ca = os.environ.get("VAULT_CA_CERT")
    ctx = ssl.create_default_context(cafile=ca) if ca else ssl.create_default_context()
    ctx.load_cert_chain(certfile=cert, keyfile=os.environ.get("VAULT_CLIENT_KEY"))
    return ctx


_CTX = _tls_context()


def _post(url, obj):
    data = json.dumps(obj).encode()
    req = urllib.request.Request(url, data=data, headers={"content-type": "application/json"}, method="POST")
    ctx = _CTX if url.startswith("https") else None
    try:
        with urllib.request.urlopen(req, context=ctx) as resp:
            body = resp.read().decode()
            return json.loads(body) if body.strip() else {}
    except urllib.error.HTTPError as e:
        raise SystemExit(f"server error {e.code}: {e.read().decode()}")


def load_cfg():
    if not os.path.exists(CONFIG):
        raise SystemExit(f"no {CONFIG} - run 'python vaultfile.py init' first")
    with open(CONFIG) as f:
        return json.load(f)


def save_cfg(cfg):
    with open(CONFIG, "w") as f:
        json.dump(cfg, f, indent=2)


def content_key(cfg):
    pw = os.environ.get("VAULT_PASSPHRASE")
    if not pw:
        raise SystemExit("set VAULT_PASSPHRASE (your content key) first")
    salt = bytes.fromhex(cfg["kdf_salt"])
    return Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(pw.encode())


def token(cfg, op):
    r = _post(f"{COORD}/v1/capabilities",
              {"app_id": cfg["app_id"], "namespace": cfg["namespace"], "operation": op, "ttl_secs": 300})
    return r["token"]


def cmd_init():
    app = _post(f"{COORD}/v1/apps", {
        "label": "vaultfile", "quota": {"max_bytes": 10 * 1024**3, "max_objects": 100000},
        "retention": {"keep_versions": 3, "min_days": 30}, "erasure": {"k": 4, "n": 6}})
    ns = _post(f"{COORD}/v1/namespaces", {"app_id": app["app_id"]})
    cfg = {
        "coordinator": COORD, "sidecar": SIDECAR,
        "app_id": app["app_id"], "namespace": ns["namespace_id"],
        "kdf_salt": os.urandom(16).hex(), "catalog": {},
    }
    save_cfg(cfg)
    print(f"initialized. app={cfg['app_id']} namespace={cfg['namespace']}")
    print(f"catalog + config written to {CONFIG}. Keep it (and your passphrase) safe.")


def cmd_backup(path, name=None):
    cfg = load_cfg()
    name = name or os.path.basename(path)
    plaintext = open(path, "rb").read()

    # Client-side encrypt: nonce(12) || AES-256-GCM(ciphertext+tag).
    key = content_key(cfg)
    nonce = os.urandom(12)
    blob = nonce + AESGCM(key).encrypt(nonce, plaintext, None)

    r = _post(f"{SIDECAR}/v1/backups", {
        "namespace": cfg["namespace"], "token": token(cfg, "Put"),
        "ciphertext_b64": base64.b64encode(blob).decode()})
    cfg["catalog"][name] = {"blob_id": r["blob_id"], "size": len(plaintext)}
    save_cfg(cfg)
    print(f"backed up '{name}' ({len(plaintext)} bytes) -> {r['blob_id']}")


def cmd_list():
    cfg = load_cfg()
    if not cfg["catalog"]:
        print("(nothing stored yet)")
        return
    for name, e in cfg["catalog"].items():
        print(f"  {name:<32} {e['size']:>10} bytes   {e['blob_id']}")


def cmd_restore(name, out):
    cfg = load_cfg()
    entry = cfg["catalog"].get(name)
    if not entry:
        raise SystemExit(f"no such file '{name}' (see 'list')")
    r = _post(f"{SIDECAR}/v1/backups/get", {
        "namespace": cfg["namespace"], "token": token(cfg, "Get"), "blob_id": entry["blob_id"]})
    blob = base64.b64decode(r["ciphertext_b64"])
    nonce, ct = blob[:12], blob[12:]
    plaintext = AESGCM(content_key(cfg)).decrypt(nonce, ct, None)
    with open(out, "wb") as f:
        f.write(plaintext)
    print(f"restored '{name}' -> {out} ({len(plaintext)} bytes)")


def cmd_delete(name):
    cfg = load_cfg()
    entry = cfg["catalog"].pop(name, None)
    if not entry:
        raise SystemExit(f"no such file '{name}'")
    _post(f"{SIDECAR}/v1/backups/delete", {
        "namespace": cfg["namespace"], "token": token(cfg, "Delete"), "blob_id": entry["blob_id"]})
    save_cfg(cfg)
    print(f"deleted '{name}'")


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return
    cmd, rest = argv[1], argv[2:]
    if cmd == "init":
        cmd_init()
    elif cmd == "backup" and rest:
        cmd_backup(rest[0], rest[1] if len(rest) > 1 else None)
    elif cmd == "list":
        cmd_list()
    elif cmd == "restore" and len(rest) == 2:
        cmd_restore(rest[0], rest[1])
    elif cmd == "delete" and rest:
        cmd_delete(rest[0])
    else:
        print(__doc__)


if __name__ == "__main__":
    main(sys.argv)
