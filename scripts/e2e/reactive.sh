#!/usr/bin/env bash
# Reactive-repair drill on real binaries (4-of-6 erasure). Proves that *reading*
# a degraded blob heals it on the anchor — with NO call to /v1/maintenance/repair.
# This is the "repair auto-runs before it hits the limit" behavior: active data
# is healed the moment it's touched, so it never drifts toward the k-shard cliff
# between scheduled sweeps.
#
#   PYTHON=/path/to/python-with-cryptography ./reactive.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
PY="${PYTHON:-python3}"
CO=127.0.0.1:8787; A=127.0.0.1:8790
# shellcheck source=lib.sh
. "$HERE/lib.sh"
cd "$ROOT"

echo "== preflight: ports 8787 8790 =="
require_free_ports 8787 8790
echo "== build =="
cargo build --release -p coordinator -p node-agent >/dev/null 2>&1
WORK="$(mktemp -d)"; ANCHOR_A="$WORK/anchorA"
export VAULT_PASSPHRASE="reactive drill key"
export VAULT_COORDINATOR_URL="http://$CO" VAULT_SIDECAR_URL="http://$A" VAULT_CONFIG="$WORK/vault.json"

echo "== boot coordinator + single node A (4-of-6) =="
VAULT_COORDINATOR_ADDR="$CO" ./target/release/coordinator >"$WORK/co.log" 2>&1 & COPID=$!
sleep 2
VAULT_NODE_ADDR="$A" VAULT_COORDINATOR_URL="http://$CO" VAULT_ANCHOR_ROOT="$ANCHOR_A" \
  ./target/release/node-agent >"$WORK/a.log" 2>&1 & APID=$!
cleanup(){ kill $COPID $APID 2>/dev/null || true; }
trap cleanup EXIT
sleep 3

echo "== back up a 200 KB file =="
head -c 200000 /dev/urandom > "$WORK/secret.bin"
WANT=$(sha256sum "$WORK/secret.bin" | awk '{print $1}')
"$PY" "$ROOT/scripts/vaultfile.py" init >/dev/null
"$PY" "$ROOT/scripts/vaultfile.py" backup "$WORK/secret.bin" secret.bin >/dev/null
read NS BLOB < <("$PY" - <<PY
import json
c=json.load(open("$VAULT_CONFIG")); print(c["namespace"], c["catalog"]["secret.bin"]["blob_id"])
PY
)
DIR_A="$ANCHOR_A/$NS/$BLOB"
shards(){ find "$1" -name '*.shard' 2>/dev/null | wc -l | tr -d ' '; }
restore_ok(){ "$PY" "$ROOT/scripts/vaultfile.py" restore secret.bin "$1" >/dev/null 2>&1 \
  && [ "$(sha256sum "$1" | awk '{print $1}')" = "$WANT" ]; }
echo "   anchor A: $(shards "$DIR_A")/6 shards"

FAIL=0
echo
echo "== degrade: delete 2 of 6 shards (still >= k=4, so the read still succeeds) =="
rm -f "$DIR_A/00001.shard" "$DIR_A/00004.shard"
echo "   anchor A now: $(shards "$DIR_A")/6"

echo
echo "== READ the file (plain restore — NO /maintenance/repair call) =="
if restore_ok "$WORK/out.bin"; then echo "   restore: OK, byte-identical"; else echo "   restore FAILED"; FAIL=1; fi

echo
echo "== wait for the background reactive repair to land =="
for _ in $(seq 1 20); do [ "$(shards "$DIR_A")" = "6" ] && break; sleep 0.5; done
echo "   anchor A after read: $(shards "$DIR_A")/6"
[ "$(shards "$DIR_A")" = "6" ] || { echo "   !! expected 6 — reactive repair did not heal"; FAIL=1; }

echo
echo "== confirm the healed shards are byte-correct (restore again) =="
if restore_ok "$WORK/out2.bin"; then echo "   restore after heal: OK, byte-identical"; else echo "   restore after heal FAILED"; FAIL=1; fi

echo
if [ "$FAIL" = "0" ]; then
  echo "REACTIVE REPAIR PASSED — a read healed the degraded blob with no explicit repair call."
else echo "REACTIVE REPAIR FAILED"; fi
exit $FAIL
