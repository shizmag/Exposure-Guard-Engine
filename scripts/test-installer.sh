#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEST_ROOT="$(mktemp -d -t eg-installer-test-XXXXXX)"
trap 'if [ "$(readlink "$HOME/.local/bin/exposureguard" 2>/dev/null || true)" = "$HOME/.local/share/exposureguard/bin/exposureguard" ]; then rm -f "$HOME/.local/bin/exposureguard"; fi; chmod -R u+w "$TEST_ROOT" 2>/dev/null || true; rm -rf "$TEST_ROOT"' EXIT
export HOME="$TEST_ROOT/home"
export GOMODCACHE="$(go env GOMODCACHE)"
mkdir -p "$HOME/.local/bin"
if [ -e "$HOME/.local/bin/exposureguard" ] || [ -L "$HOME/.local/bin/exposureguard" ]; then echo "test HOME unexpectedly has an Engine symlink" >&2; exit 1; fi

"$ROOT/install.sh" --engine-only --version 0.1.0-dev
ENGINE="$HOME/.local/share/exposureguard"
[ -L "$HOME/.local/bin/exposureguard" ] || { echo "expected isolated persistent-prefix symlink" >&2; exit 1; }
[ "$(readlink "$HOME/.local/bin/exposureguard")" = "$ENGINE/bin/exposureguard" ] || { echo "symlink does not target persistent prefix" >&2; exit 1; }
"$ROOT/install.sh" --engine-only --version 0.1.0-dev
EXPOSUREGUARD_HOME="$ENGINE" "$ENGINE/bin/exposureguard" doctor --format json >"$TEST_ROOT/engine-doctor.json"
jq -e '.all_ready == true and .distribution_type == "engine-only"' "$TEST_ROOT/engine-doctor.json" >/dev/null
EXPOSUREGUARD_HOME="$ENGINE" "$ENGINE/bin/exposureguard" version --json | jq -e '.identity_algorithm_version == "1"' >/dev/null

FULL="$TEST_ROOT/full"
EXPOSUREGUARD_CACHE="$ROOT/.dev/cache/$(go env GOOS)_$(go env GOARCH)" "$ROOT/install.sh" --with-tools --prefix "$FULL" --version 0.1.0-dev
EXPOSUREGUARD_HOME="$FULL" "$FULL/bin/exposureguard" doctor --format json >"$TEST_ROOT/full-doctor.json"
jq -e '.all_ready == true and .distribution_type == "full" and ([.integrations[].status] | all(. == "PASS"))' "$TEST_ROOT/full-doctor.json" >/dev/null
EXPOSUREGUARD_HOME="$FULL" "$FULL/bin/exposureguard" version --json | jq -e '.identity_algorithm_version == "1" and .distribution_manifest.distribution_type == "full"' >/dev/null
EXPOSUREGUARD_CACHE="$ROOT/.dev/cache/$(go env GOOS)_$(go env GOARCH)" "$ROOT/install.sh" --with-tools --prefix "$FULL" --version 0.1.0-dev
[ "$(readlink "$HOME/.local/bin/exposureguard")" = "$ENGINE/bin/exposureguard" ] || { echo "full custom-prefix install changed isolated symlink" >&2; exit 1; }
echo "Installer engine-only/full/repeat/symlink checks passed"
