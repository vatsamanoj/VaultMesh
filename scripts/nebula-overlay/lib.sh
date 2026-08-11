#!/usr/bin/env bash
# Shared config + helpers for the VaultMesh Nebula overlay scripts.
# Sourced by every script here. Override any value in a local `env` file
# (copy from `env.example`) or via the environment.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load local overrides if present.
# shellcheck disable=SC1091
[ -f "$HERE/env" ] && . "$HERE/env"

# --- defaults (an unset value falls back to these) ---
: "${PKI_DIR:=$HERE/pki}"                       # certs + generated lighthouse config
: "${OUT_DIR:=$HERE/out}"                       # per-user handoff bundles
: "${CA_NAME:=VaultMesh Overlay CA}"
: "${OVERLAY_CIDR:=192.168.100.0/24}"           # the private overlay range
: "${LIGHTHOUSE_OVERLAY_IP:=192.168.100.1}"     # coordinator + anchor bind here
: "${NEBULA_PORT:=4242}"                        # UDP; the only port you forward
: "${PUBLIC_ENDPOINT:=CHANGE_ME:4242}"          # public IP / DDNS remote hosts dial

# Netmask bits (e.g. 24) parsed from OVERLAY_CIDR for `nebula-cert -ip`.
MASK="${OVERLAY_CIDR##*/}"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERROR: '$1' not found on PATH. ${2:-}" >&2
    exit 1
  }
}

# render <template> — substitute __TOKENS__ and print to stdout.
# CA_PATH / CERT_PATH / KEY_PATH are supplied by the caller (they differ per
# machine); the rest come from config above.
render() {
  sed \
    -e "s|__CA_PATH__|${CA_PATH:-}|g" \
    -e "s|__CERT_PATH__|${CERT_PATH:-}|g" \
    -e "s|__KEY_PATH__|${KEY_PATH:-}|g" \
    -e "s|__LH_IP__|${LIGHTHOUSE_OVERLAY_IP}|g" \
    -e "s|__PUBLIC_ENDPOINT__|${PUBLIC_ENDPOINT}|g" \
    -e "s|__NEBULA_PORT__|${NEBULA_PORT}|g" \
    "$1"
}
