#!/usr/bin/env bash
# Modified for dnscheck, 2026-10-12. Original project: Brian Shea / addr.tools.
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/certbot-env.sh"
exec docker "${certbot_args[@]}" "$certbot_image" renew --non-interactive "$@"
