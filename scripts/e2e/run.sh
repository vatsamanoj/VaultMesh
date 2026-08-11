#!/usr/bin/env bash
# Boot a coordinator + node-agent (local fs anchor) and run the browser
# tap-to-restore round-trip test against them, then tear everything down.
#
#   PYTHON=/path/to/venv/python PLAYWRIGHT_CHROME=/path/to/chrome ./run.sh
#
# PYTHON must have `playwright` installed; PLAYWRIGHT_CHROME (optional) points at
# a Chromium binary if Playwright's bundled one isn't installed.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
PY="${PYTHON:-python3}"
CO_PORT="${CO_PORT:-8787}"
NODE_PORT="${NODE_PORT:-8790}"

cd "$ROOT"
echo "== building coordinator + node-agent (release) =="
cargo build --release -p coordinator -p node-agent

WORK="$(mktemp -d)"
echo "== booting services (anchor=$WORK/anchor) =="
VAULT_COORDINATOR_ADDR="127.0.0.1:$CO_PORT" \
  ./target/release/coordinator >"$WORK/coord.log" 2>&1 &
CO_PID=$!
VAULT_NODE_ADDR="127.0.0.1:$NODE_PORT" \
VAULT_COORDINATOR_URL="http://127.0.0.1:$CO_PORT" \
VAULT_ANCHOR_ROOT="$WORK/anchor" \
  ./target/release/node-agent >"$WORK/node.log" 2>&1 &
NODE_PID=$!
cleanup() { kill "$CO_PID" "$NODE_PID" 2>/dev/null || true; }
trap cleanup EXIT
sleep 3

echo "== running browser round-trip =="
VAULT_COORDINATOR_URL="http://127.0.0.1:$CO_PORT" "$PY" "$HERE/roundtrip.py"
