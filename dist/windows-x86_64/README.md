# VaultMesh — prebuilt Windows binaries (x86_64)

Cross-compiled from source (`x86_64-pc-windows-gnu`, release/optimized). These are
console executables for 64-bit Windows.

| File | Role |
|------|------|
| `coordinator.exe` | Control plane — app registry, capability tokens, authoritative metadata, admin/CA/naming endpoints. |
| `node-agent.exe`  | Per-machine sidecar — localhost data-plane API, local blob anchor, peer mesh. |

Verify integrity against `SHA256SUMS.txt` (PowerShell):

```powershell
Get-FileHash .\coordinator.exe -Algorithm SHA256
Get-FileHash .\node-agent.exe  -Algorithm SHA256
```

> These binaries are **unsigned**, so Windows SmartScreen/Defender may warn on
> first run ("Windows protected your PC" → *More info* → *Run anyway*). That's
> expected for a self-built, unsigned executable — not a malware verdict.

## Run the P0–P4 loop (three PowerShell windows)

```powershell
# 1) Control plane (coordinator) on 127.0.0.1:8787
$env:VAULT_ANCHOR_ROOT = "$env:TEMP\vaultmesh\a"
.\coordinator.exe

# 2) Per-machine sidecar (node-agent) on 127.0.0.1:8790
$env:VAULT_NODE_ADDR   = "127.0.0.1:8790"
$env:VAULT_ANCHOR_ROOT = "$env:TEMP\vaultmesh\a"
.\node-agent.exe
# For direct QUIC peer transport instead of HTTP:
#   $env:VAULT_TRANSPORT = "quic"; $env:VAULT_QUIC_ADDR = "127.0.0.1:8791"
#   $env:VAULT_PEERS     = "127.0.0.1:<peer-quic-port>"
```

Then drive it from any client — e.g. the control plane over HTTP:

```powershell
# register an app
curl.exe -s -X POST http://127.0.0.1:8787/v1/apps `
  -H "content-type: application/json" `
  -d '{\"label\":\"demo\",\"quota\":{\"max_bytes\":1073741824,\"max_objects\":1000},\"retention\":{\"keep_versions\":3,\"min_days\":30},\"erasure\":{\"k\":4,\"n\":6}}'

# coordinator status / admin views
curl.exe -s http://127.0.0.1:8787/v1/admin/status
curl.exe -s http://127.0.0.1:8787/v1/ca/root
```

For the full narrated end-to-end walkthrough (register → token → backup →
Reed-Solomon shards → restore → repair → perimeter → CA/naming → billing), run
`scripts/demo.py` from the repository root against these two services:

```powershell
$env:AROOT = "$env:TEMP\vaultmesh\a"; $env:BROOT = "$env:TEMP\vaultmesh\b"
python scripts\demo.py
```

## Environment variables

| Var | Default | Meaning |
|-----|---------|---------|
| `VAULT_COORDINATOR_ADDR` | `127.0.0.1:8787` | coordinator bind address |
| `VAULT_NODE_ADDR` | `127.0.0.1:8790` | node-agent localhost API |
| `VAULT_COORDINATOR_URL` | `http://127.0.0.1:8787` | node-agent → coordinator |
| `VAULT_ANCHOR_ROOT` | `.\.vaultmesh\anchor` | local shard directory |
| `VAULT_PEERS` | *(empty)* | comma-separated peer addresses for the mesh |
| `VAULT_TRANSPORT` | `http` | `http` (P2) or `quic` (P4) |
| `VAULT_QUIC_ADDR` | `0.0.0.0:8791` | QUIC shard-server bind (when `quic`) |
| `VAULT_REPAIR_SECS` | `0` | background repair-sweep interval (0 disables) |

## Building it yourself on Windows

You don't need these prebuilt files — the source is on `main`. With the Rust
MSVC toolchain + Visual Studio C++ Build Tools installed:

```powershell
git clone https://github.com/vatsamanoj/VaultMesh
cd VaultMesh
cargo build --release
.\target\release\coordinator.exe
```

(Or use WSL2 and follow the Linux instructions in the top-level README.)
