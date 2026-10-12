#!/usr/bin/env bash
# Modified for dnscheck, 2026-10-12. Original project: Brian Shea / addr.tools.
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/certbot-env.sh"
: "${ACME_EMAIL:?Set the email for your own ACME account}"
[[ $# -gt 0 ]] || { echo "Pass your own domains: --cert-name example.com -d example.com" >&2; exit 1; }
exec docker "${certbot_args[@]}" "$certbot_image" certonly --manual --preferred-challenges dns \
  --manual-auth-hook '/opt/dnscheck/certbot-hook.py auth' \
  --manual-cleanup-hook '/opt/dnscheck/certbot-hook.py cleanup' \
  --non-interactive --agree-tos --email "$ACME_EMAIL" "$@"
