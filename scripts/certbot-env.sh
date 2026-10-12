#!/usr/bin/env bash
# Shared configuration. Secrets remain in mounted files, never shell hook text.
set -euo pipefail
: "${DNSCHECK_CHALLENGE_URL:?Set your own HTTPS challenge API endpoint}"
: "${DNSCHECK_SECRET_FILE:?Set the absolute path of your private generated token file}"
: "${DNSCHECK_CERT_DIR:?Set the absolute certificate storage directory}"
[[ "$DNSCHECK_CHALLENGE_URL" == https://* ]] || { echo "Challenge URL must use HTTPS" >&2; exit 1; }
[[ "$DNSCHECK_SECRET_FILE" == /* && -f "$DNSCHECK_SECRET_FILE" && "$DNSCHECK_CERT_DIR" == /* && -d "$DNSCHECK_CERT_DIR" ]] || { echo "Absolute existing token/certificate paths are required" >&2; exit 1; }
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
certbot_image="${DNSCHECK_CERTBOT_IMAGE:-certbot/certbot@sha256:f70ad0adbb7e117f0fe42a63c553f28ea451edabc0148757b6efcd9735acaa20}"
certbot_uid="${DNSCHECK_CERTBOT_UID:-$(id -u)}"
certbot_gid="${DNSCHECK_CERTBOT_GID:-$(id -g)}"
[[ "$certbot_uid" =~ ^[0-9]+$ && "$certbot_gid" =~ ^[0-9]+$ ]] || { echo "Certbot UID/GID must be numeric" >&2; exit 1; }
certbot_args=(run --rm --read-only --cap-drop ALL --security-opt no-new-privileges
  --user "$certbot_uid:$certbot_gid"
  --tmpfs "/tmp:rw,noexec,nosuid,nodev,size=32m,mode=0700,uid=$certbot_uid,gid=$certbot_gid"
  --tmpfs "/var/lib/letsencrypt:rw,noexec,nosuid,nodev,size=32m,mode=0700,uid=$certbot_uid,gid=$certbot_gid"
  --tmpfs "/var/log/letsencrypt:rw,noexec,nosuid,nodev,size=32m,mode=0700,uid=$certbot_uid,gid=$certbot_gid"
  --mount "type=bind,src=$DNSCHECK_CERT_DIR,dst=/etc/letsencrypt"
  --mount "type=bind,src=$DNSCHECK_SECRET_FILE,dst=/run/secrets/dnscheck-token,readonly"
  --mount "type=bind,src=$script_dir/certbot-hook.py,dst=/opt/dnscheck/certbot-hook.py,readonly"
  --env "DNSCHECK_CHALLENGE_URL=$DNSCHECK_CHALLENGE_URL"
  --env DNSCHECK_SECRET_FILE=/run/secrets/dnscheck-token
  --env "DNSCHECK_PROPAGATION_SECONDS=${DNSCHECK_PROPAGATION_SECONDS:-10}")
