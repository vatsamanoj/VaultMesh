#!/usr/bin/env bash
# Optional: run an S3-compatible object store (MinIO) bound to the overlay IP,
# so coordinator-minted presigned URLs resolve on the overlay and never
# publicly. RustFS is a drop-in (both speak S3) — swap the image if you prefer.
# Requires the lighthouse to be up first (the overlay IP must exist on the host).
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

require_cmd docker "Install Docker, or run RustFS/MinIO yourself on ${LIGHTHOUSE_OVERLAY_IP}:9000"
: "${VAULT_S3_ACCESS_KEY:?set VAULT_S3_ACCESS_KEY in ./env}"
: "${VAULT_S3_SECRET_KEY:?set VAULT_S3_SECRET_KEY in ./env (>= 8 chars)}"
: "${VAULT_S3_BUCKET:=vaultmesh}"

echo "starting MinIO anchor on ${LIGHTHOUSE_OVERLAY_IP}:9000 (bucket '${VAULT_S3_BUCKET}')…"
echo "note: create the bucket once, e.g. with 'mc mb local/${VAULT_S3_BUCKET}'."
exec docker run --rm --name vaultmesh-anchor \
  -p "${LIGHTHOUSE_OVERLAY_IP}:9000:9000" \
  -e "MINIO_ROOT_USER=${VAULT_S3_ACCESS_KEY}" \
  -e "MINIO_ROOT_PASSWORD=${VAULT_S3_SECRET_KEY}" \
  -v vaultmesh-anchor-data:/data \
  minio/minio server /data --address ":9000"
