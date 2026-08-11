#!/usr/bin/env bash
# Reproducible end-to-end demo of VaultMesh (P0-P4).
#
# Builds the workspace, starts a coordinator + two QUIC-meshed node-agents,
# runs a narrated walkthrough (scripts/demo.py) that exercises every layer, then
# runs the real client-side-encryption roundtrip example. Cleans up on exit.
#
# Usage:  ./scripts/demo.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

COORD_PORT=8787
A_HTTP=8790; A_QUIC=8791
B_HTTP=8792; B_QUIC=8893

echo "==> building coordinator + node-agent"
cargo build -q -p coordinator -p node-agent -p vault-client

# --- clean up any of our processes still listening (by cmdline, via PID) ---
kill_ours() {
  for p in $(ss -ltnp 2>/dev/null | grep -oE 'pid=[0-9]+' | grep -oE '[0-9]+' | sort -u); do
    cmd=$(tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null || true)
    case "$cmd" in *"/coordinator"*|*"/node-agent"*) kill "$p" 2>/dev/null || true;; esac
  done
}
kill_ours; sleep 1

AROOT="$(mktemp -d)/a"; BROOT="$(mktemp -d)/b"
export AROOT BROOT
PIDS=()
cleanup() { for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done; }
trap cleanup EXIT

wait_health() {
  local url="$1"
  for _ in $(seq 1 60); do
    curl -sf "$url/health" >/dev/null 2>&1 && return 0
    sleep 0.3
  done
  echo "timed out waiting for $url" >&2; exit 1
}

echo "==> starting coordinator on :$COORD_PORT"
VAULT_ANCHOR_ROOT="$AROOT" ./target/debug/coordinator >/tmp/vm-coord.log 2>&1 &
PIDS+=($!)
wait_health "http://127.0.0.1:$COORD_PORT"

echo "==> starting node B (peer)   http::$B_HTTP quic::$B_QUIC"
VAULT_NODE_ADDR="127.0.0.1:$B_HTTP" VAULT_ANCHOR_ROOT="$BROOT" \
  VAULT_TRANSPORT=quic VAULT_QUIC_ADDR="127.0.0.1:$B_QUIC" \
  ./target/debug/node-agent >/tmp/vm-nodeb.log 2>&1 &
PIDS+=($!)

echo "==> starting node A (origin) http::$A_HTTP quic::$A_QUIC  peers=[node B]"
VAULT_NODE_ADDR="127.0.0.1:$A_HTTP" VAULT_ANCHOR_ROOT="$AROOT" \
  VAULT_TRANSPORT=quic VAULT_QUIC_ADDR="127.0.0.1:$A_QUIC" \
  VAULT_PEERS="127.0.0.1:$B_QUIC" \
  ./target/debug/node-agent >/tmp/vm-nodea.log 2>&1 &
PIDS+=($!)
wait_health "http://127.0.0.1:$A_HTTP"
wait_health "http://127.0.0.1:$B_HTTP"

echo "==> running narrated walkthrough"
COORD="http://127.0.0.1:$COORD_PORT" NODE_A="http://127.0.0.1:$A_HTTP" \
  python3 "$ROOT/scripts/demo.py"

echo
echo "======================================================================"
echo "  BONUS: real client-side AES-256-GCM encrypt->put->get->decrypt path"
echo "======================================================================"
VAULT_SIDECAR_URL="http://127.0.0.1:$A_HTTP" \
  cargo run -q -p vault-client --example roundtrip

echo
echo "(demo complete — services stopped on exit)"
