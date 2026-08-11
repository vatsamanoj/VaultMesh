#!/usr/bin/env bash
# Shared preflight helpers for the e2e scripts. Source this: `. "$HERE/lib.sh"`.

# port_busy PORT — return 0 if something is listening on 127.0.0.1:PORT.
port_busy() {
  (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && { exec 3>&- 3<&-; return 0; }
  return 1
}

# reap_vaultmesh — kill stale coordinator/node-agent processes we may have left
# from an earlier (timed-out or killed) run. Scoped to our own build outputs so
# it never touches unrelated processes.
reap_vaultmesh() {
  pkill -9 -f 'target/.*/coordinator' 2>/dev/null || true
  pkill -9 -f 'target/.*/node-agent' 2>/dev/null || true
}

# require_free_ports PORT... — ensure each port is free. If any is busy, reap our
# own stale servers once and re-check; fail loudly if a port is still occupied by
# something we don't own (so we never clobber an unrelated service).
require_free_ports() {
  local p busy=()
  for p in "$@"; do
    if port_busy "$p"; then busy+=("$p"); fi
  done
  if [ "${#busy[@]}" -gt 0 ]; then
    echo "preflight: port(s) ${busy[*]} busy — reaping stale VaultMesh servers…" >&2
    reap_vaultmesh
    sleep 2
    busy=()
    for p in "$@"; do
      if port_busy "$p"; then busy+=("$p"); fi
    done
  fi
  if [ "${#busy[@]}" -gt 0 ]; then
    echo "preflight: port(s) ${busy[*]} still in use by a non-VaultMesh process." >&2
    echo "  free them and retry (run.sh honors CO_PORT/NODE_PORT overrides)." >&2
    return 1
  fi
}
