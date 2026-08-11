#!/usr/bin/env bash
# Create the overlay CA (once) and the lighthouse cert + config.
# Idempotent: existing CA / lighthouse cert are reused, never overwritten.
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

require_cmd nebula-cert "Install Nebula: https://github.com/slackhq/nebula/releases"

mkdir -p "$PKI_DIR"

if [ -f "$PKI_DIR/ca.crt" ]; then
  echo "CA already exists at $PKI_DIR/ca.crt — reusing."
else
  ( cd "$PKI_DIR" && nebula-cert ca -name "$CA_NAME" )
  echo "created CA: $PKI_DIR/ca.{crt,key}"
  echo ">>> keep ca.key OFFLINE and secret — it can mint any overlay identity."
fi

if [ -f "$PKI_DIR/lighthouse.crt" ]; then
  echo "lighthouse cert already exists — reusing."
else
  ( cd "$PKI_DIR" && nebula-cert sign -name "lighthouse" \
      -ip "${LIGHTHOUSE_OVERLAY_IP}/${MASK}" )
  echo "signed lighthouse cert for ${LIGHTHOUSE_OVERLAY_IP}"
fi

CA_PATH="$PKI_DIR/ca.crt" CERT_PATH="$PKI_DIR/lighthouse.crt" KEY_PATH="$PKI_DIR/lighthouse.key" \
  render "$HERE/templates/lighthouse.yml" > "$PKI_DIR/lighthouse.yml"
echo "wrote $PKI_DIR/lighthouse.yml"
echo
echo "next: ./run-lighthouse.sh   (and forward UDP ${NEBULA_PORT} to this machine)"
