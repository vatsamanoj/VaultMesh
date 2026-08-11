#!/usr/bin/env bash
# Start the VaultMesh coordinator bound to the overlay IP, with mTLS on and the
# S3 creds it needs to mint presigned URLs. Run AFTER the lighthouse is up
# (the overlay IP must already exist on this host) and the anchor is reachable.
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

COORD_BIN="${COORD_BIN:-$HERE/../../target/release/coordinator}"
[ -x "$COORD_BIN" ] || {
  echo "coordinator binary not found at $COORD_BIN" >&2
  echo "build it first:  (cd $HERE/../.. && cargo build --release)" >&2
  exit 1
}

: "${VAULT_S3_ACCESS_KEY:?set VAULT_S3_ACCESS_KEY in ./env}"
: "${VAULT_S3_SECRET_KEY:?set VAULT_S3_SECRET_KEY in ./env}"

# Overlay-bound control plane + anchor endpoint (never public).
export VAULT_COORDINATOR_ADDR="${LIGHTHOUSE_OVERLAY_IP}:8787"
export VAULT_TLS_MODE=mtls
export VAULT_TLS_SANS="${LIGHTHOUSE_OVERLAY_IP},localhost,127.0.0.1"
export VAULT_CERT_DIR="${VAULT_CERT_DIR:-$HERE/certs}"
export VAULT_S3_ENDPOINT="${VAULT_S3_ENDPOINT:-http://${LIGHTHOUSE_OVERLAY_IP}:9000}"
export VAULT_S3_BUCKET="${VAULT_S3_BUCKET:-vaultmesh}"
export VAULT_S3_ACCESS_KEY VAULT_S3_SECRET_KEY

mkdir -p "$VAULT_CERT_DIR"
echo "coordinator → https://${LIGHTHOUSE_OVERLAY_IP}:8787 (mTLS)"
echo "anchor      → ${VAULT_S3_ENDPOINT} (bucket ${VAULT_S3_BUCKET})"
echo "mTLS bundle → ${VAULT_CERT_DIR}/{ca-root.pem,client.pem,client.key} (hand these to users)"
exec "$COORD_BIN"
