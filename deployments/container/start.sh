#!/bin/sh
set -eu

TLS_DIR="/etc/nginx/tls"
TLS_SOURCE_DIR="${TLS_SOURCE_DIR:-/var/run/clawreef-tls}"
TLS_CERT="${TLS_DIR}/tls.crt"
TLS_KEY="${TLS_DIR}/tls.key"
SOURCE_CERT="${TLS_SOURCE_DIR}/tls.crt"
SOURCE_KEY="${TLS_SOURCE_DIR}/tls.key"

mkdir -p "${TLS_DIR}"

if [ -f "${SOURCE_CERT}" ] && [ -f "${SOURCE_KEY}" ]; then
  cp "${SOURCE_CERT}" "${TLS_CERT}"
  cp "${SOURCE_KEY}" "${TLS_KEY}"
elif [ ! -f "${TLS_CERT}" ] || [ ! -f "${TLS_KEY}" ]; then
  echo "TLS certificate not found, generating a self-signed certificate for bootstrap use."
  openssl req \
    -x509 \
    -nodes \
    -days 365 \
    -newkey rsa:2048 \
    -subj "/CN=clawreef.local" \
    -keyout "${TLS_KEY}" \
    -out "${TLS_CERT}"
fi

export SERVER_ADDRESS="${SERVER_ADDRESS:-:9001}"
export SERVER_MODE="${SERVER_MODE:-release}"

# Render ksec-bridge upstream into nginx.conf. The vars ${KSEC_BRIDGE_HOST} and
# ${KSEC_BRIDGE_PORT} are placeholders embedded in deployments/nginx/nginx.conf;
# K8s injects KSEC_BRIDGE_HOST via Downward API (status.hostIP). For local docker
# runs without these vars, fall back to 127.0.0.1:9101 so nginx still starts.
export KSEC_BRIDGE_HOST="${KSEC_BRIDGE_HOST:-127.0.0.1}"
export KSEC_BRIDGE_PORT="${KSEC_BRIDGE_PORT:-9101}"
if command -v envsubst >/dev/null 2>&1; then
  NGX_TPL=/etc/nginx/nginx.conf
  NGX_TMP="$(mktemp)"
  # Whitelist substitution — DO NOT replace $http_upgrade / $host / $remote_addr etc.
  envsubst '${KSEC_BRIDGE_HOST} ${KSEC_BRIDGE_PORT}' < "${NGX_TPL}" > "${NGX_TMP}"
  mv "${NGX_TMP}" "${NGX_TPL}"
else
  echo "WARN: envsubst not found; nginx.conf placeholders left unrendered." >&2
fi

/usr/local/bin/clawreef-server &
backend_pid=$!

nginx -g 'daemon off;' &
nginx_pid=$!

shutdown() {
  kill "${backend_pid}" 2>/dev/null || true
  kill "${nginx_pid}" 2>/dev/null || true
  wait "${backend_pid}" 2>/dev/null || true
  wait "${nginx_pid}" 2>/dev/null || true
}

trap shutdown INT TERM

while kill -0 "${backend_pid}" 2>/dev/null && kill -0 "${nginx_pid}" 2>/dev/null; do
  sleep 2
done

shutdown
