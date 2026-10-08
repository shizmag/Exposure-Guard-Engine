#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARTIFACT_DIR="${ARTIFACT_DIR:-${ROOT}/dist}"
RC_VERSION="${RC_VERSION:-0.1.0-rc1}"

smoke_distribution() {
  local directory="$1" full="$2"
  local binary="$directory/bin/exposureguard"
  [ -x "$binary" ] || { echo "packaged Engine binary missing: $binary" >&2; exit 1; }
  export EXPOSUREGUARD_HOME="$directory"
  go run ./cmd/build-distribution --root "$directory" --schema "$directory/schemas/distribution-manifest.schema.json" --check
  "$binary" version --json >"$directory/version.json"
  "$binary" doctor --format json >"$directory/doctor.json"
  "$binary" profiles list >/dev/null
  "$binary" integrations list >/dev/null
  "$binary" checks list >/dev/null
  "$binary" scan https://example.com --profile standard --plan >/dev/null
  printf '%s\n' '{"batch_protocol_version":"1","batch_id":"b1000000-0000-4000-8000-000000000001","scans":[{"schema_version":"1","scan_id":"c1000000-0000-4000-8000-000000000001","target":"https://example.com","mode":"public","profile":"deep"}]}' | "$binary" batch --request-json - --format jsonl >"$directory/batch-smoke.jsonl"
  if [ "$full" = true ]; then
    "$binary" snapshot hash "$ROOT/testdata/snapshots/snapshot_v1_expected.json" >/dev/null
    "$binary" diff "$ROOT/testdata/snapshots/diff_source_map_old.json" "$ROOT/testdata/snapshots/diff_source_map_new.json" >/dev/null
  fi
}
for platform in darwin_arm64 linux_amd64; do
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  for kind in core full; do
    archive="$ARTIFACT_DIR/release-artifacts/exposureguard_${RC_VERSION}_${platform}_$kind.tar.gz"
    [ -f "$archive" ] || { echo "packaged artifact missing: $archive" >&2; exit 1; }
    extract="$tmp/$kind"
    mkdir -p "$extract"
    tar -xzf "$archive" -C "$extract"
    if [ "$kind" = full ] && [ "$platform" = darwin_arm64 ]; then
      smoke_distribution "$extract" true
    elif [ "$kind" = core ] && [ "$platform" = darwin_arm64 ]; then
      smoke_distribution "$extract" false
    else
      go run ./cmd/build-distribution --root "$extract" --schema "$extract/schemas/distribution-manifest.schema.json" --check
    fi
  done
  rm -rf "$tmp"
  trap - EXIT
done
echo "Packaged v${RC_VERSION} core/full release smoke passed"
