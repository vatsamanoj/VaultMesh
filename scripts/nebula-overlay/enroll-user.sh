#!/usr/bin/env bash
# Sign a Nebula host cert for one remote user and build a handoff bundle:
#   out/<name>/  = ca.crt, <name>.crt, <name>.key, config.yml, README.txt
#   out/<name>.tar.gz
# Usage: ./enroll-user.sh <name> <overlay-ip> [groups]
#   ./enroll-user.sh alice 192.168.100.5
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

require_cmd nebula-cert "Install Nebula: https://github.com/slackhq/nebula/releases"

NAME="${1:-}"; IP="${2:-}"; GROUPS="${3:-users}"
if [ -z "$NAME" ] || [ -z "$IP" ]; then
  echo "usage: $0 <name> <overlay-ip> [groups]" >&2
  exit 1
fi
[ -f "$PKI_DIR/ca.key" ] || { echo "no CA yet — run ./setup-ca.sh first" >&2; exit 1; }

( cd "$PKI_DIR" && nebula-cert sign -name "$NAME" -ip "${IP}/${MASK}" -groups "$GROUPS" )

DEST="$OUT_DIR/$NAME"
mkdir -p "$DEST"
cp "$PKI_DIR/ca.crt"      "$DEST/ca.crt"
cp "$PKI_DIR/$NAME.crt"   "$DEST/$NAME.crt"
cp "$PKI_DIR/$NAME.key"   "$DEST/$NAME.key"

CA_PATH="ca.crt" CERT_PATH="$NAME.crt" KEY_PATH="$NAME.key" \
  render "$HERE/templates/host.yml" > "$DEST/config.yml"

cat > "$DEST/README.txt" <<EOF
VaultMesh overlay bundle for: $NAME  (overlay IP ${IP})

This joins you to the private Nebula overlay. It is the NETWORK identity only.
You also need your VaultMesh app client cert (client.pem/client.key + ca-root.pem)
for the coordinator's mTLS gate — those are separate and come from the operator.

1. Install Nebula:  https://github.com/slackhq/nebula/releases
2. Join the overlay (keep it running; needs root for the TUN device):
     sudo nebula -config config.yml
3. Verify you can reach the coordinator:
     ping ${LIGHTHOUSE_OVERLAY_IP}
4. Start your node-agent (holds NO S3 creds):
     VAULT_COORDINATOR_URL=https://${LIGHTHOUSE_OVERLAY_IP}:8787 \\
     VAULT_CA_CERT=ca-root.pem \\
     VAULT_CLIENT_CERT=client.pem VAULT_CLIENT_KEY=client.key \\
     VAULT_ANCHOR=presigned \\
       node-agent
5. Point your app (vaultfile.py) at 127.0.0.1:8790 and back up files.

Keep $NAME.key private — it is your overlay identity.
EOF

( cd "$OUT_DIR" && tar czf "$NAME.tar.gz" "$NAME" )
echo "enrolled '$NAME' at ${IP}"
echo "bundle:  $OUT_DIR/$NAME.tar.gz   (hand this to the user over a secure channel)"
