#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
_OUTPUT_DIR="${1:?dist dir required}"
case "$_OUTPUT_DIR" in /*) OUTPUT_DIR="$_OUTPUT_DIR" ;; *) OUTPUT_DIR="${ROOT}/$_OUTPUT_DIR" ;; esac
BINARY="${2:?binary path required}"
GOOS="${3:?os required}"
GOARCH="${4:?arch required}"
VERSION="${5:?version required}"
COMMIT="${6:?commit required}"
DATE="${7:?date required}"
MODE="${8:-full}"
case "$GOARCH" in
  arm64_v8.0) GOARCH=arm64 ;;
  amd64_v1) GOARCH=amd64 ;;
esac
PLATFORM="${GOOS}_${GOARCH}"
ARTIFACT_ROOT="${ROOT}/dist"
CORE="${ARTIFACT_ROOT}/package/core-${GOOS}_${GOARCH}"
FULL="${ARTIFACT_ROOT}/package/${GOOS}_${GOARCH}"
if [ "$MODE" = core ]; then CORE="$OUTPUT_DIR"; else FULL="$OUTPUT_DIR"; fi
case "$MODE" in
  full) ;;
  core) ;;
  *) echo "mode must be core or full" >&2; exit 2 ;;
esac
hash_file() { if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'; else sha256sum "$1" | awk '{print $1}'; fi; }
prepare_layout() {
  local root="$1" binary_name=exposureguard
  [ "$GOOS" != windows ] || binary_name=exposureguard.exe
  rm -rf "$root"
  mkdir -p "$root/bin" "$root/profiles/nuclei/v1" "$root/schemas"
  cp "$BINARY" "$root/bin/$binary_name"
  cp tools.lock.json "$root/tools.lock.json"
  cp schemas/distribution-manifest.schema.json "$root/schemas/distribution-manifest.schema.json"
  cp profiles/nuclei/v1/* "$root/profiles/nuclei/v1/"
}
if [ "$MODE" = core ]; then
  prepare_layout "$CORE"
  (cd "$ROOT" && go run ./cmd/build-distribution --root "$CORE" --schema "$CORE/schemas/distribution-manifest.schema.json" --version "$VERSION" --commit "$COMMIT")
  archive_dir="$ARTIFACT_ROOT/release-artifacts"
  mkdir -p "$archive_dir"
  if [ "$GOOS" = windows ]; then archive="$archive_dir/exposureguard_${VERSION}_${GOOS}_${GOARCH}_core.zip"; (cd "$CORE" && zip -qr "${ROOT}/${archive#${ROOT}/}" .); else archive="$archive_dir/exposureguard_${VERSION}_${GOOS}_${GOARCH}_core.tar.gz"; tar -czf "${ROOT}/${archive#${ROOT}/}" -C "$CORE" .; fi
  exit 0
fi
if [ "$GOOS" = windows ]; then echo "full distribution unavailable for Windows"; exit 0; fi
command -v curl >/dev/null 2>&1 && command -v unzip >/dev/null 2>&1 && command -v jq >/dev/null 2>&1 || { echo "curl, unzip and jq required for full release distribution" >&2; exit 1; }
CACHE="${EXPOSUREGUARD_CACHE:-${ROOT}/.dev/cache/${PLATFORM}}"
prepare_layout "$FULL"
mkdir -p "$CACHE"
fetch_archive() {
  local name="$1" archive expected version path
  version="$(jq -r ".tools[\"$name\"].version" tools.lock.json)"
  archive="$(jq -r ".tools[\"$name\"].checksums[\"${PLATFORM}\"].archive" tools.lock.json)"
  expected="$(jq -r ".tools[\"$name\"].checksums[\"${PLATFORM}\"].sha256" tools.lock.json)"
  if [ -z "$archive" ] || [ "$archive" = null ] || [ -z "$expected" ] || [ "$expected" = null ]; then echo "No pinned $name archive for $PLATFORM" >&2; exit 1; fi
  path="$CACHE/$archive"
  if [ ! -f "$path" ] || [ "$(hash_file "$path")" != "$expected" ]; then curl -fsSL --retry 3 "https://github.com/projectdiscovery/${name}/releases/download/v${version}/${archive}" -o "$path"; fi
  if [ "$(hash_file "$path")" != "$expected" ]; then echo "SHA-256 mismatch for $archive" >&2; exit 1; fi
  printf '%s\n' "$path"
}
for tool in subfinder httpx katana nuclei; do
  archive_path="$(fetch_archive "$tool")"
  unzip -p "$archive_path" "$tool" >"$FULL/bin/$tool"
  chmod 755 "$FULL/bin/$tool"
done
tpl_version="$(jq -r '.tools["nuclei-templates"].version' tools.lock.json)"
tpl_archive="v${tpl_version}.zip"
tpl_sha="$(jq -r '.tools["nuclei-templates"].sha256' tools.lock.json)"
tpl_path="$CACHE/$tpl_archive"
if [ ! -f "$tpl_path" ] || [ "$(hash_file "$tpl_path")" != "$tpl_sha" ]; then curl -fsSL --retry 3 "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/${tpl_archive}" -o "$tpl_path"; fi
if [ "$(hash_file "$tpl_path")" != "$tpl_sha" ]; then echo "SHA-256 mismatch for $tpl_archive" >&2; exit 1; fi
mkdir -p "$CACHE/templates-$tpl_version" "$FULL/share/nuclei-templates"
unzip -oq "$tpl_path" -d "$CACHE/templates-$tpl_version"
cp -R "$CACHE/templates-$tpl_version"/nuclei-templates-*/* "$FULL/share/nuclei-templates/"
printf '%s\n' "$tpl_version" > "$FULL/share/nuclei-templates/.nuclei-templates-version"
(cd "$ROOT" && go run ./cmd/build-distribution --root "$FULL" --schema "$FULL/schemas/distribution-manifest.schema.json" --version "$VERSION" --commit "$COMMIT")
archive_dir="$ARTIFACT_ROOT/release-artifacts"
mkdir -p "$archive_dir"
archive="$archive_dir/exposureguard_${VERSION}_${GOOS}_${GOARCH}_full.tar.gz"
tar -czf "${ROOT}/${archive#${ROOT}/}" -C "$FULL" .
