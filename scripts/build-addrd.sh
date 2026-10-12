#!/usr/bin/env bash
# Modified for dnscheck, 2026-10-12. Original project: Brian Shea / addr.tools.
set -euo pipefail
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
revision="$(git -C "$project_dir" rev-parse HEAD 2>/dev/null || true)"
revision="${revision:-source-archive}"
if [[ -n "$(git -C "$project_dir" status --porcelain 2>/dev/null || true)" ]]; then revision="${revision}-dirty"; fi
docker build --build-arg "SOURCE_REVISION=$revision" -f "$project_dir/Dockerfile.addrd" \
  -t "${DNSCHECK_IMAGE:-dnscheck:addrd}" "$project_dir"
