# VaultMesh over a self-sovereign Nebula overlay

Helper scripts to run the **entire VaultMesh backend on one public-IP machine**
behind a private [Nebula](https://github.com/slackhq/nebula) overlay — with
**zero third-party dependency**. You run your own CA and your own lighthouse;
nothing phones home. The coordinator and object store bind the overlay address,
so the only inbound you forward is **one UDP port** for the lighthouse. Ports
8787 (coordinator) and 9000 (anchor) never touch the public internet.

See `../../docs/USING.md` → "Self-sovereign overlay with Nebula" for the
architecture and the security rationale.

## Two separate identities (don't confuse them)

| Identity | Issued by | Purpose |
|---|---|---|
| Nebula host cert (`<name>.crt/.key`) | `nebula-cert` (this kit) | joins the **network** overlay |
| VaultMesh client cert (`client.pem/.key`) | the coordinator (`VAULT_TLS_MODE=mtls`) | passes the **app** mTLS gate |

A user needs both. This kit issues the first; `run-backend.sh` emits the second
into `certs/` for you to hand out.

## Prerequisites

- `nebula` and `nebula-cert` on PATH — https://github.com/slackhq/nebula/releases
- The VaultMesh coordinator built: `(cd ../.. && cargo build --release)`
- An S3-compatible store on the overlay (use `run-anchor.sh`, or your own RustFS)

## Quickstart (operator, on the public-IP machine)

```sh
cp env.example env && $EDITOR env      # set PUBLIC_ENDPOINT + S3 creds

./setup-ca.sh                          # 1. own CA + lighthouse cert/config
./run-lighthouse.sh                    # 2. start overlay (root; leave running)
                                       #    → forward UDP 4242 on your router
./run-anchor.sh                        # 3. (optional) MinIO anchor on the overlay
./run-backend.sh                       # 4. coordinator on 192.168.100.1:8787 (mTLS)

./enroll-user.sh alice 192.168.100.5   # 5. per user → out/alice.tar.gz
```

Give each user their `out/<name>.tar.gz` (Nebula bundle) **and** the VaultMesh
mTLS bundle from `certs/` (`ca-root.pem`, `client.pem`, `client.key`), over a
secure channel. Their `README.txt` explains the rest.

## Start order matters

`run-lighthouse.sh` creates the overlay TUN interface, which is what makes
`192.168.100.1` exist on the host. `run-anchor.sh` and `run-backend.sh` bind
that address, so they must start **after** the lighthouse is up.

## Files

| File | What it does |
|---|---|
| `lib.sh` | shared config + `render` helper (sourced by all) |
| `env.example` | config knobs — copy to `env` |
| `setup-ca.sh` | create CA (once) + lighthouse cert + config |
| `run-lighthouse.sh` | start the Nebula lighthouse |
| `run-anchor.sh` | optional MinIO/S3 anchor on the overlay |
| `run-backend.sh` | start the coordinator bound to the overlay |
| `enroll-user.sh` | sign a host cert + build a handoff bundle |
| `templates/` | `lighthouse.yml` + `host.yml` config templates |

Generated `pki/`, `out/`, `certs/`, and `env` stay local (git-ignored). The CA
private key (`pki/ca.key`) mints any overlay identity — keep it offline.
