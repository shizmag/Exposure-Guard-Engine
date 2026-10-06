#!/usr/bin/env bash
# ExposureGuard Engine & Toolchain Installer
# Safe, idempotent, non-root, pinned version installer with cryptographic checksum verification.

set -euo pipefail

MODE="with-tools"
CUSTOM_PREFIX=""
CHECK_ONLY=0

show_help() {
    cat << EOF
ExposureGuard Installer

Usage:
  ./install.sh [options]

Options:
  --with-tools      Install ExposureGuard and all pinned external tools (default)
  --engine-only     Build and install ExposureGuard binary only
  --check           Dry-run check: verify host prerequisites and report readiness
  --prefix <path>   Set custom installation prefix (default: \$HOME/.local/share/exposureguard)
  -h, --help        Show this help message
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --engine-only)
            MODE="engine-only"
            shift
            ;;
        --with-tools)
            MODE="with-tools"
            shift
            ;;
        --check)
            CHECK_ONLY=1
            shift
            ;;
        --prefix)
            if [ -z "${2:-}" ]; then
                echo "Error: --prefix requires a directory path" >&2
                exit 1
            fi
            CUSTOM_PREFIX="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            show_help
            exit 1
            ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -f "tools.lock.json" ]; then
    echo "Error: tools.lock.json not found in $SCRIPT_DIR" >&2
    exit 1
fi

# Detect OS and Architecture
OS_TYPE="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH_TYPE="$(uname -m)"

case "$OS_TYPE" in
    darwin) PLATFORM_OS="darwin" ;;
    linux)  PLATFORM_OS="linux" ;;
    *)
        echo "Error: Unsupported operating system: $OS_TYPE" >&2
        exit 1
        ;;
esac

case "$ARCH_TYPE" in
    x86_64|amd64)   PLATFORM_ARCH="amd64" ;;
    arm64|aarch64)  PLATFORM_ARCH="arm64" ;;
    *)
        echo "Error: Unsupported CPU architecture: $ARCH_TYPE" >&2
        exit 1
        ;;
esac

PLATFORM_KEY="${PLATFORM_OS}_${PLATFORM_ARCH}"

echo "=========================================================="
echo "ExposureGuard Engine Installer"
echo "Target Platform: ${PLATFORM_KEY} (${OS_TYPE}/${ARCH_TYPE})"
echo "=========================================================="

# Check host utilities
require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "Error: Required command '$1' is missing." >&2
        exit 1
    fi
}

require_cmd go
if [ "$MODE" = "with-tools" ] && [ "$CHECK_ONLY" -eq 0 ]; then
    require_cmd curl
    require_cmd unzip
fi

# Determine SHA256 utility
sha256_file() {
    local target="$1"
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$target" | awk '{print $1}'
    elif command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$target" | awk '{print $1}'
    else
        echo "Error: Neither shasum nor sha256sum found." >&2
        exit 1
    fi
}

# Read field from tools.lock.json
get_lock_field() {
    local tool="$1"
    local field="$2"
    if command -v python3 >/dev/null 2>&1; then
        python3 -c "import json, sys
m = json.load(open('tools.lock.json'))
t = m.get('tools', {}).get('$tool', {})
if '$field' == 'version':
    sys.stdout.write(t.get('version', ''))
elif '$field' == 'archive':
    sys.stdout.write(t.get('checksums', {}).get('$PLATFORM_KEY', {}).get('archive', ''))
elif '$field' == 'sha256':
    sys.stdout.write(t.get('checksums', {}).get('$PLATFORM_KEY', {}).get('sha256', ''))
elif '$field' == 'templates_archive':
    sys.stdout.write(t.get('archive', ''))
elif '$field' == 'templates_sha256':
    sys.stdout.write(t.get('sha256', ''))
"
    elif command -v jq >/dev/null 2>&1; then
        case "$field" in
            version)
                jq -r ".tools[\"$tool\"].version // empty" tools.lock.json
                ;;
            archive)
                jq -r ".tools[\"$tool\"].checksums[\"$PLATFORM_KEY\"].archive // empty" tools.lock.json
                ;;
            sha256)
                jq -r ".tools[\"$tool\"].checksums[\"$PLATFORM_KEY\"].sha256 // empty" tools.lock.json
                ;;
            templates_archive)
                jq -r ".tools[\"$tool\"].archive // empty" tools.lock.json
                ;;
            templates_sha256)
                jq -r ".tools[\"$tool\"].sha256 // empty" tools.lock.json
                ;;
        esac
    fi
}

# Resolve target installation paths
if [ -n "$CUSTOM_PREFIX" ]; then
    INSTALL_PREFIX="$CUSTOM_PREFIX"
elif [ -n "${EXPOSUREGUARD_HOME:-}" ]; then
    INSTALL_PREFIX="$EXPOSUREGUARD_HOME"
else
    INSTALL_PREFIX="${HOME}/.local/share/exposureguard"
fi

BIN_DIR="${INSTALL_PREFIX}/bin"
TOOLS_DIR="${INSTALL_PREFIX}/tools"
TEMPLATES_DIR="${TOOLS_DIR}/nuclei/templates"

echo "Installation Directory: ${INSTALL_PREFIX}"
echo "Binaries Directory:     ${BIN_DIR}"
echo ""

if [ "$CHECK_ONLY" -eq 1 ]; then
    echo "Check mode: inspecting current environment..."
    if [ -x "${BIN_DIR}/exposureguard" ]; then
        "${BIN_DIR}/exposureguard" doctor
    elif command -v exposureguard >/dev/null 2>&1; then
        exposureguard doctor
    else
        echo "ExposureGuard binary not found in ${BIN_DIR} or PATH."
    fi
    exit 0
fi

# Ensure target directories exist
mkdir -p "${BIN_DIR}" "${TOOLS_DIR}"

TMP_DIR="$(mktemp -d -t eg-install-XXXXXX)"
cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

# 1. Build and install ExposureGuard CLI
echo "==> Building ExposureGuard engine..."
go build -ldflags "-s -w" -o "${BIN_DIR}/exposureguard" ./cmd/exposureguard
chmod 755 "${BIN_DIR}/exposureguard"
echo "✓ Installed ${BIN_DIR}/exposureguard"

# Create symlink in ~/.local/bin if directory exists and is writable
USER_LOCAL_BIN="${HOME}/.local/bin"
if [ -d "$USER_LOCAL_BIN" ] && [ -w "$USER_LOCAL_BIN" ] && [ "$BIN_DIR" != "$USER_LOCAL_BIN" ]; then
    ln -sf "${BIN_DIR}/exposureguard" "${USER_LOCAL_BIN}/exposureguard" 2>/dev/null || true
    echo "✓ Linked ${USER_LOCAL_BIN}/exposureguard -> ${BIN_DIR}/exposureguard"
fi

# 2. Install pinned tools if requested
if [ "$MODE" = "with-tools" ]; then
    TOOLS=("subfinder" "httpx" "katana" "nuclei")

    for tool in "${TOOLS[@]}"; do
        VERSION="$(get_lock_field "$tool" "version")"
        ARCHIVE="$(get_lock_field "$tool" "archive")"
        EXPECTED_SHA="$(get_lock_field "$tool" "sha256")"

        if [ -z "$ARCHIVE" ] || [ -z "$EXPECTED_SHA" ]; then
            echo "Error: Missing lock information for $tool on $PLATFORM_KEY" >&2
            exit 1
        fi

        echo ""
        echo "==> Installing $tool v${VERSION}..."
        DOWNLOAD_URL="https://github.com/projectdiscovery/${tool}/releases/download/v${VERSION}/${ARCHIVE}"
        ARCHIVE_PATH="${TMP_DIR}/${ARCHIVE}"

        echo "    Downloading: $DOWNLOAD_URL"
        curl -sSL --fail --retry 3 --retry-delay 2 "$DOWNLOAD_URL" -o "$ARCHIVE_PATH"

        echo "    Verifying SHA-256 checksum..."
        ACTUAL_SHA="$(sha256_file "$ARCHIVE_PATH")"
        if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
            echo "Error: Cryptographic checksum mismatch for $tool!" >&2
            echo "  Expected: $EXPECTED_SHA" >&2
            echo "  Actual:   $ACTUAL_SHA" >&2
            exit 1
        fi
        echo "    ✓ Checksum verified ($ACTUAL_SHA)"

        EXTRACT_DIR="${TMP_DIR}/ext_${tool}"
        mkdir -p "$EXTRACT_DIR"
        unzip -q -o "$ARCHIVE_PATH" -d "$EXTRACT_DIR"

        if [ -f "${EXTRACT_DIR}/${tool}" ]; then
            mv "${EXTRACT_DIR}/${tool}" "${BIN_DIR}/${tool}"
        elif [ -f "${EXTRACT_DIR}/${tool}.exe" ]; then
            mv "${EXTRACT_DIR}/${tool}.exe" "${BIN_DIR}/${tool}.exe"
        else
            # Search inside subdirectories if nested
            FOUND="$(find "$EXTRACT_DIR" -type f -name "$tool" | head -n1)"
            if [ -n "$FOUND" ]; then
                mv "$FOUND" "${BIN_DIR}/${tool}"
            else
                echo "Error: Binary '$tool' not found in archive $ARCHIVE" >&2
                exit 1
            fi
        fi
        chmod 755 "${BIN_DIR}/${tool}"
        echo "    ✓ Installed ${BIN_DIR}/${tool}"
    done

    # 3. Install pinned nuclei-templates
    echo ""
    echo "==> Installing pinned Nuclei templates..."
    TPL_VERSION="$(get_lock_field "nuclei-templates" "version")"
    TPL_ARCHIVE="$(get_lock_field "nuclei-templates" "templates_archive")"
    TPL_SHA="$(get_lock_field "nuclei-templates" "templates_sha256")"

    TPL_URL="https://github.com/projectdiscovery/nuclei-templates/releases/download/v${TPL_VERSION}/${TPL_ARCHIVE}"
    TPL_FILE="${TMP_DIR}/${TPL_ARCHIVE}"

    echo "    Downloading: $TPL_URL"
    curl -sSL --fail --retry 3 --retry-delay 2 "$TPL_URL" -o "$TPL_FILE"

    echo "    Verifying SHA-256 checksum..."
    ACTUAL_TPL_SHA="$(sha256_file "$TPL_FILE")"
    if [ "$ACTUAL_TPL_SHA" != "$TPL_SHA" ]; then
        echo "Error: Cryptographic checksum mismatch for nuclei-templates!" >&2
        echo "  Expected: $TPL_SHA" >&2
        echo "  Actual:   $ACTUAL_TPL_SHA" >&2
        exit 1
    fi
    echo "    ✓ Checksum verified ($ACTUAL_TPL_SHA)"

    mkdir -p "${TEMPLATES_DIR}"
    unzip -q -o "$TPL_FILE" -d "${TEMPLATES_DIR}"
    echo "    ✓ Nuclei templates installed at ${TEMPLATES_DIR}"
fi

echo ""
echo "=========================================================="
echo "Running ExposureGuard Doctor Verification..."
echo "=========================================================="

export PATH="${BIN_DIR}:${PATH}"
"${BIN_DIR}/exposureguard" doctor || true

echo ""
echo "=========================================================="
echo "Installation complete!"
echo "=========================================================="
echo "To use ExposureGuard, ensure the binary directory is in your PATH:"
echo ""
echo "    export PATH=\"${BIN_DIR}:\$PATH\""
echo ""
echo "Try running:"
echo "    exposureguard doctor"
echo "    exposureguard scan example.com"
echo "=========================================================="
