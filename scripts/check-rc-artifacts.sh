#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
artifacts="$root/dist/release-artifacts"
for artifact in \
  exposureguard_0.1.0-rc1_darwin_arm64_full.tar.gz \
  exposureguard_0.1.0-rc1_darwin_arm64_core.tar.gz \
  exposureguard_0.1.0-rc1_linux_amd64_full.tar.gz \
  exposureguard_0.1.0-rc1_linux_amd64_core.tar.gz; do
  if [ ! -f "$artifacts/$artifact" ]; then
    echo "missing RC artifact: $artifacts/$artifact" >&2
    exit 1
  fi
done
