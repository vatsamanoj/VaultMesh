#!/usr/bin/env bash
# Durability drill on a 2-node mesh (4-of-6 erasure). Shows, on real binaries:
#   Part 1  erasure + self-heal : lose 2 shards on a node, restore still works,
#                                 repair rebuilds them from local survivors.
#   Part 2  mesh durability     : lose 3 shards (below k) on a node, restore
#                                 still works by fetching replicas from a peer.
#
#   PYTHON=/path/to/python-with-cryptography ./durability.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
PY="${PYTHON:-python3}"
CO=127.0.0.1:8787; A=127.0.0.1:8790; B=127.0.0.1:8791
# shellcheck source=lib.sh
. "$HERE/lib.sh"
cd "$ROOT"

echo "== preflight: ports 8787 8790 8791 =="
require_free_ports 8787 8790 8791
echo "== build =="
cargo build --release -p coordinator -p node-agent >/dev/null 2>&1
WORK="$(mktemp -d)"; ANCHOR_A="$WORK/anchorA"; ANCHOR_B="$WORK/anchorB"
export VAULT_PASSPHRASE="durability drill key"
export VAULT_COORDINATOR_URL="http://$CO" VAULT_SIDECAR_URL="http://$A" VAULT_CONFIG="$WORK/vault.json"

echo "== boot coordinator + 2-node mesh (A<->B, 4-of-6) =="
VAULT_COORDINATOR_ADDR="$CO" ./target/release/coordinator >"$WORK/co.log" 2>&1 & COPID=$!
sleep 2
VAULT_NODE_ADDR="$A" VAULT_COORDINATOR_URL="http://$CO" VAULT_ANCHOR_ROOT="$ANCHOR_A" \
  VAULT_PEERS="http://$B" ./target/release/node-agent >"$WORK/a.log" 2>&1 & APID=$!
VAULT_NODE_ADDR="$B" VAULT_COORDINATOR_URL="http://$CO" VAULT_ANCHOR_ROOT="$ANCHOR_B" \
  VAULT_PEERS="http://$A" ./target/release/node-agent >"$WORK/b.log" 2>&1 & BPID=$!
cleanup(){ kill $COPID $APID $BPID 2>/dev/null || true; }
trap cleanup EXIT
sleep 3

echo "== back up a 300 KB file via node A =="
head -c 300000 /dev/urandom > "$WORK/secret.bin"
WANT=$(sha256sum "$WORK/secret.bin" | awk '{print $1}')
"$PY" "$ROOT/scripts/vaultfile.py" init >/dev/null
"$PY" "$ROOT/scripts/vaultfile.py" backup "$WORK/secret.bin" secret.bin >/dev/null
read NS BLOB < <("$PY" - <<PY
import json
c=json.load(open("$VAULT_CONFIG")); print(c["namespace"], c["catalog"]["secret.bin"]["blob_id"])
PY
)
DIR_A="$ANCHOR_A/$NS/$BLOB"; DIR_B="$ANCHOR_B/$NS/$BLOB"
shards(){ find "$1" -name '*.shard' 2>/dev/null | wc -l | tr -d ' '; }
restore_ok(){ "$PY" "$ROOT/scripts/vaultfile.py" restore secret.bin "$WORK/out.bin" >/dev/null 2>&1 \
  && [ "$(sha256sum "$WORK/out.bin" | awk '{print $1}')" = "$WANT" ]; }
repair(){ curl -s -XPOST "http://$A/v1/maintenance/repair" -H 'content-type: application/json' \
  -d "{\"namespace\":\"$NS\",\"blob_id\":\"$BLOB\"}"; }

echo "   node A anchor: $(shards "$DIR_A") shards   node B anchor (peer replicas): $(shards "$DIR_B") shards"
FAIL=0

echo
echo "== PART 1: erasure + self-heal (peer B offline) =="
kill $BPID 2>/dev/null || true; sleep 1; echo "   (node B killed — only node A in play)"
rm -f "$DIR_A/00001.shard" "$DIR_A/00004.shard"
echo "   simulated disk loss: deleted 2 of 6 shards on A → now $(shards "$DIR_A")/6"
if restore_ok; then echo "   restore: OK, byte-identical (Reed-Solomon rebuilt from 4 local shards)"; else echo "   restore: FAILED"; FAIL=1; fi
echo "   repair report: $(repair)"
echo "   node A anchor after repair: $(shards "$DIR_A")/6"
[ "$(shards "$DIR_A")" = "6" ] || { echo "   !! expected 6"; FAIL=1; }
restore_ok && echo "   restore after repair: OK, byte-identical" || { echo "   restore after repair FAILED"; FAIL=1; }

echo
echo "== PART 2: mesh saves loss beyond single-node tolerance (peer B back) =="
VAULT_NODE_ADDR="$B" VAULT_COORDINATOR_URL="http://$CO" VAULT_ANCHOR_ROOT="$ANCHOR_B" \
  VAULT_PEERS="http://$A" ./target/release/node-agent >"$WORK/b2.log" 2>&1 & BPID=$!
sleep 2; echo "   (node B back online with its $(shards "$DIR_B") replicas)"
rm -f "$DIR_A/00000.shard" "$DIR_A/00002.shard" "$DIR_A/00003.shard"
echo "   catastrophic loss on A: deleted 3 of 6 → A has only $(shards "$DIR_A")/6 (below k=4)"
if restore_ok; then echo "   restore: OK, byte-identical (missing shards fetched from peer B)"; else echo "   restore: FAILED"; FAIL=1; fi

echo
echo "== PART 3: repair heals a below-k node by borrowing from peers =="
echo "   repair report: $(repair)"
echo "   node A anchor after repair: $(shards "$DIR_A")/6"
[ "$(shards "$DIR_A")" = "6" ] || { echo "   !! expected 6 after peer-assisted repair"; FAIL=1; }
kill $BPID 2>/dev/null || true; sleep 1
echo "   (peer B killed again — node A must now stand alone)"
if restore_ok; then echo "   restore from A alone: OK, byte-identical (node fully healed)"; else echo "   restore from A alone: FAILED"; FAIL=1; fi

echo
if [ "$FAIL" = "0" ]; then echo "DURABILITY DRILL PASSED — data survived shard loss and node-down, byte-identical throughout."; else echo "DURABILITY DRILL FAILED"; fi
exit $FAIL
