#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${RC_VERSION:-0.1.0-rc1}"
COMMIT="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
DIST="$ROOT/dist"
mkdir -p "$DIST/rc-bin" "$DIST/package" "$DIST/release-artifacts"
RC_WORK="$ROOT/.dev/rc-work"
rm -rf "$RC_WORK"
mkdir -p "$RC_WORK"
for target in darwin_arm64 linux_amd64; do
  GOOS="${target%_*}"
  GOARCH="${target#*_}"
  BINARY="$RC_WORK/bin/$target/exposureguard"
  mkdir -p "$(dirname "$BINARY")"
  (cd "$ROOT" && CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" go build \
    -ldflags "-s -w -X github.com/exposureguard/exposureguard/internal/buildinfo.Version=$VERSION -X github.com/exposureguard/exposureguard/internal/buildinfo.GitCommit=$COMMIT -X github.com/exposureguard/exposureguard/internal/buildinfo.BuildDate=$BUILD_DATE" \
    -o "$BINARY" ./cmd/exposureguard)
  for mode in core full; do
    package="$RC_WORK/package/${mode}-${target}"
    "$ROOT/scripts/build-release-distribution.sh" "$package" "$BINARY" "$GOOS" "$GOARCH" "$VERSION" "$COMMIT" "$BUILD_DATE" "$mode"
    archive="$DIST/release-artifacts/exposureguard_${VERSION}_${GOOS}_${GOARCH}_${mode}"
    tar -czf "${archive}.tar.gz" -C "$package" .
    if [ "$mode" = full ]; then cp "$archive.tar.gz" "$DIST/Exposure-Guard-Engine_${VERSION}_${GOOS}_${GOARCH}.tar.gz"; else cp "$archive.tar.gz" "$DIST/Exposure-Guard-Engine_${VERSION}_${GOOS}_${GOARCH}_core.tar.gz"; fi
    extracted="$RC_WORK/package/${mode}-${target}-inspect"
    rm -rf "$extracted"
    mkdir -p "$extracted"
    tar -xzf "${archive}.tar.gz" -C "$extracted"
    go run "$ROOT/cmd/build-distribution" --root "$extracted" --schema "$extracted/schemas/distribution-manifest.schema.json" --check
    expected_type="$mode"
    [ "$mode" != core ] || expected_type=engine-only
    if [ "$(jq -r '.distribution_type' "$extracted/distribution-manifest.json")" != "$expected_type" ]; then echo "artifact type mismatch for $mode $target" >&2; exit 1; fi
    rm -rf "$extracted"
  done
done
rm -rf "$RC_WORK"
printf 'Built local %s packages for darwin/arm64 and linux/amd64\n' "$VERSION"
