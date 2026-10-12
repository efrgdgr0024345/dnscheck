#!/usr/bin/env bash
# Modified for dnscheck, 2026-10-12. Original project: Brian Shea / addr.tools.
set -euo pipefail
: "${DNSCHECK_DATA_DIR:?Set DNSCHECK_DATA_DIR to a directory owned by UID/GID 10001 containing config.json}"
[[ -d "$DNSCHECK_DATA_DIR" && -f "$DNSCHECK_DATA_DIR/config.json" ]] || { echo "Data directory/config.json is missing" >&2; exit 1; }
data_dir="$(cd -- "$DNSCHECK_DATA_DIR" && pwd)"
args=(run --name "${DNSCHECK_CONTAINER:-dnscheck}" --restart unless-stopped
  --read-only --cap-drop ALL --cap-add NET_BIND_SERVICE
  --security-opt no-new-privileges --user 10001:10001
  --memory "${DNSCHECK_MEMORY:-256m}" --cpus "${DNSCHECK_CPUS:-2}" --pids-limit 128
  --network "${DNSCHECK_NETWORK:-bridge}"
  --publish 53:53/udp --publish 53:53/tcp --publish 853:853/udp --publish 853:853/tcp
  --mount "type=bind,src=$data_dir,dst=/data"
  --mount "type=bind,src=$data_dir/config.json,dst=/data/config.json,readonly")
if [[ -n "${DNSCHECK_TLS_CERT:-}" || -n "${DNSCHECK_TLS_KEY:-}" ]]; then
  : "${DNSCHECK_TLS_CERT:?Set both certificate and key paths}"
  : "${DNSCHECK_TLS_KEY:?Set both certificate and key paths}"
  args+=(--mount "type=bind,src=$DNSCHECK_TLS_CERT,dst=/certificates/fullchain.pem,readonly"
         --mount "type=bind,src=$DNSCHECK_TLS_KEY,dst=/certificates/privkey.pem,readonly")
fi
if [[ -n "${DNSCHECK_VALKEY_SOCKET_DIR:-}" ]]; then
  args+=(--mount "type=bind,src=$DNSCHECK_VALKEY_SOCKET_DIR,dst=/run/valkey,readonly")
fi
# Existing containers are not stopped or deleted implicitly.
exec docker "${args[@]}" -d "${DNSCHECK_IMAGE:-dnscheck:addrd}" -c /data/config.json
