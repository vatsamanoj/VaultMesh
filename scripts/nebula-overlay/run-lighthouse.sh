#!/usr/bin/env bash
# Start the Nebula lighthouse on this machine. Brings up the overlay TUN
# interface (needs root) so the coordinator/anchor can bind the overlay IP.
# Leave this running; forward UDP ${NEBULA_PORT} on your router to this host.
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

require_cmd nebula "Install Nebula: https://github.com/slackhq/nebula/releases"
[ -f "$PKI_DIR/lighthouse.yml" ] || { echo "run ./setup-ca.sh first" >&2; exit 1; }

if [ "${PUBLIC_ENDPOINT}" = "CHANGE_ME:4242" ]; then
  echo "warning: PUBLIC_ENDPOINT is unset — remote hosts won't find the lighthouse." >&2
  echo "         set it in ./env before enrolling users." >&2
fi

echo "starting nebula lighthouse (overlay ${LIGHTHOUSE_OVERLAY_IP}, UDP ${NEBULA_PORT})…"
SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"
exec $SUDO nebula -config "$PKI_DIR/lighthouse.yml"
