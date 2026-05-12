#!/bin/sh
# trino-svc-bootstrap.sh — Create the Polaris ``trino_svc`` principal for
# local dev (docker-compose). Run as an init container that depends on
# Polaris being healthy.
#
# Idempotent: principal create is 200/201/409-tolerant. Credential reset
# is destructive on every run; that's the point — MMS reads the rotated
# value from the shared volume on every startup. Both the principal and
# its assigned ``service_admin`` role mirror what the production-only
# ``bootstrap_trino_global_identity.ipynb`` notebook does, so behavior is
# uniform across local dev and prod.
#
# Outputs (written into ${SHARED_DIR}, default /shared-trino-svc):
#   polaris_client_id.txt      — the rotated Polaris OAuth client_id
#   polaris_client_secret.txt  — the rotated Polaris OAuth client_secret
#
# MMS reads them via ``TRINO_GLOBAL_POLARIS_CLIENT_ID_FILE`` /
# ``TRINO_GLOBAL_POLARIS_CLIENT_SECRET_FILE`` (see ``_read_env_or_file``
# in src/trino_integration/reconciler.py).
set -e

POLARIS_HOST="${POLARIS_HOST:-http://polaris:8181}"
POLARIS_REALM="${POLARIS_REALM:-POLARIS}"
ROOT_CLIENT_ID="${POLARIS_ROOT_CLIENT_ID:-root}"
ROOT_CLIENT_SECRET="${POLARIS_ROOT_CLIENT_SECRET:-s3cr3t}"
TRINO_PRINCIPAL="${TRINO_SERVICE_PRINCIPAL:-trino_svc}"
TRINO_PRINCIPAL_ROLE="${TRINO_SERVICE_PRINCIPAL_ROLE:-service_admin}"
SHARED_DIR="${SHARED_DIR:-/shared-trino-svc}"
CLIENT_ID_FILE="${SHARED_DIR}/polaris_client_id.txt"
CLIENT_SECRET_FILE="${SHARED_DIR}/polaris_client_secret.txt"

mkdir -p "${SHARED_DIR}"

MGMT="${POLARIS_HOST}/api/management/v1"

echo "Getting OAuth root token from Polaris..."
TOKEN_RESPONSE=$(curl -sf -X POST "${POLARIS_HOST}/api/catalog/v1/oauth/tokens" \
  -u "${ROOT_CLIENT_ID}:${ROOT_CLIENT_SECRET}" \
  -H "Polaris-Realm: ${POLARIS_REALM}" \
  -d "grant_type=client_credentials&scope=PRINCIPAL_ROLE:ALL")

# Extract access_token via shell builtins (no jq in curlimages/curl).
TOKEN="${TOKEN_RESPONSE#*\"access_token\":\"}"
TOKEN="${TOKEN%%\"*}"
if [ -z "${TOKEN}" ] || [ "${TOKEN}" = "${TOKEN_RESPONSE}" ]; then
  echo "ERROR: Failed to get OAuth root token. Response: ${TOKEN_RESPONSE}" >&2
  exit 1
fi

AUTH="Authorization: Bearer ${TOKEN}"
CT="Content-Type: application/json"
RH="Polaris-Realm: ${POLARIS_REALM}"

echo "Creating principal '${TRINO_PRINCIPAL}'..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${MGMT}/principals" \
  -H "${AUTH}" -H "${CT}" -H "${RH}" \
  -d "{\"principal\":{\"name\":\"${TRINO_PRINCIPAL}\",\"type\":\"USER\",\"properties\":{}}}")
case "${HTTP_CODE}" in
  200|201) echo "  -> created" ;;
  409)     echo "  -> already exists (OK)" ;;
  *)       echo "ERROR: principal create returned ${HTTP_CODE}" >&2; exit 1 ;;
esac

echo "Assigning principal role '${TRINO_PRINCIPAL_ROLE}' to '${TRINO_PRINCIPAL}'..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
  "${MGMT}/principals/${TRINO_PRINCIPAL}/principal-roles" \
  -H "${AUTH}" -H "${CT}" -H "${RH}" \
  -d "{\"principalRole\":{\"name\":\"${TRINO_PRINCIPAL_ROLE}\"}}")
case "${HTTP_CODE}" in
  200|201) echo "  -> assigned" ;;
  409)     echo "  -> already assigned (OK)" ;;
  *)       echo "ERROR: principal-role assign returned ${HTTP_CODE}" >&2; exit 1 ;;
esac

echo "Resetting credentials for '${TRINO_PRINCIPAL}'..."
RESET_BODY=$(curl -sf -X POST "${MGMT}/principals/${TRINO_PRINCIPAL}/reset" \
  -H "${AUTH}" -H "${CT}" -H "${RH}" \
  -d "{}")

CLIENT_ID="${RESET_BODY#*\"clientId\":\"}"
CLIENT_ID="${CLIENT_ID%%\"*}"
CLIENT_SECRET="${RESET_BODY#*\"clientSecret\":\"}"
CLIENT_SECRET="${CLIENT_SECRET%%\"*}"

if [ -z "${CLIENT_ID}" ] || [ "${CLIENT_ID}" = "${RESET_BODY}" ]; then
  echo "ERROR: failed to parse clientId from reset response: ${RESET_BODY}" >&2
  exit 1
fi
if [ -z "${CLIENT_SECRET}" ] || [ "${CLIENT_SECRET}" = "${RESET_BODY}" ]; then
  echo "ERROR: failed to parse clientSecret from reset response: ${RESET_BODY}" >&2
  exit 1
fi

# printf '%s' avoids trailing newline so MMS's _read_env_or_file().strip()
# works the same on both sides — no whitespace surprises.
printf '%s' "${CLIENT_ID}" > "${CLIENT_ID_FILE}"
printf '%s' "${CLIENT_SECRET}" > "${CLIENT_SECRET_FILE}"

echo "Wrote ${CLIENT_ID_FILE} and ${CLIENT_SECRET_FILE}"
echo "trino_svc Polaris credentials rotated."
