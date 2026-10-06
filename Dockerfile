# syntax=docker/dockerfile:1

# Stage 1: Build exposureguard engine binary
FROM golang:1.24-alpine3.21 AS builder

WORKDIR /src
RUN apk add --no-cache git make ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 make build

# Stage 2: Download and cryptographically verify pinned tools
FROM alpine:3.21 AS tool-fetcher

RUN apk add --no-cache curl unzip ca-certificates python3

WORKDIR /dist
COPY tools.lock.json /dist/

ARG TARGETARCH

# Download and extract pinned binaries based on TARGETARCH
RUN set -eu; \
    ARCH="${TARGETARCH:-arm64}"; \
    case "$ARCH" in \
        amd64|x86_64) ARCH="amd64" ;; \
        arm64|aarch64) ARCH="arm64" ;; \
    esac; \
    PLATFORM="linux_${ARCH}"; \
    mkdir -p /dist/bin /dist/templates; \
    \
    download_tool() { \
        local tool="$1"; \
        local version=$(python3 -c "import json; m=json.load(open('tools.lock.json')); print(m['tools']['$tool']['version'])"); \
        local archive=$(python3 -c "import json; m=json.load(open('tools.lock.json')); print(m['tools']['$tool']['checksums']['$PLATFORM']['archive'])"); \
        local expected_sha=$(python3 -c "import json; m=json.load(open('tools.lock.json')); print(m['tools']['$tool']['checksums']['$PLATFORM']['sha256'])"); \
        local url="https://github.com/projectdiscovery/${tool}/releases/download/v${version}/${archive}"; \
        echo "Fetching ${tool} v${version} for ${PLATFORM}..."; \
        curl -sSL --fail --retry 3 "${url}" -o "/tmp/${archive}"; \
        echo "${expected_sha}  /tmp/${archive}" | sha256sum -c -; \
        mkdir -p "/tmp/ext_${tool}"; \
        unzip -q "/tmp/${archive}" -d "/tmp/ext_${tool}"; \
        mv "/tmp/ext_${tool}/${tool}" "/dist/bin/${tool}"; \
        chmod 755 "/dist/bin/${tool}"; \
        rm -rf "/tmp/${archive}" "/tmp/ext_${tool}"; \
    }; \
    \
    download_tool "subfinder"; \
    download_tool "httpx"; \
    download_tool "katana"; \
    download_tool "nuclei"; \
    \
    # Fetch pinned nuclei-templates
    tpl_ver=$(python3 -c "import json; m=json.load(open('tools.lock.json')); print(m['tools']['nuclei-templates']['version'])"); \
    tpl_archive="v${tpl_ver}.zip"; \
    tpl_sha=$(python3 -c "import json; m=json.load(open('tools.lock.json')); print(m['tools']['nuclei-templates']['sha256'])"); \
    tpl_url="https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/${tpl_archive}"; \
    echo "Fetching nuclei-templates v${tpl_ver}..."; \
    curl -sSL --fail --retry 3 "${tpl_url}" -o "/tmp/${tpl_archive}"; \
    echo "${tpl_sha}  /tmp/${tpl_archive}" | sha256sum -c -; \
    mkdir -p /tmp/tpl_ext; \
    unzip -q "/tmp/${tpl_archive}" -d /tmp/tpl_ext; \
    cp -r /tmp/tpl_ext/nuclei-templates-*/* /dist/templates/; \
    rm -rf "/tmp/${tpl_archive}" /tmp/tpl_ext

# Stage 3: Minimal, secure non-root runtime image
FROM alpine:3.21 AS runtime

RUN apk add --no-cache ca-certificates bind-tools tzdata \
    && addgroup -g 10001 -S exposureguard \
    && adduser -u 10001 -S -G exposureguard -h /home/exposureguard exposureguard \
    && mkdir -p /opt/exposureguard/nuclei-templates /opt/exposureguard/bin /opt/exposureguard/tools /tmp/exposureguard \
    && chown -R exposureguard:exposureguard /opt/exposureguard /tmp/exposureguard

# Copy exposureguard binary
COPY --from=builder /src/bin/exposureguard /usr/local/bin/exposureguard

# Copy external discovery tools
COPY --from=tool-fetcher /dist/bin/* /usr/local/bin/

# Copy pinned nuclei templates
COPY --from=tool-fetcher /dist/templates/ /opt/exposureguard/nuclei-templates/

ENV PATH="/usr/local/bin:${PATH}" \
    EXPOSUREGUARD_HOME="/opt/exposureguard" \
    EXPOSUREGUARD_NUCLEI_TEMPLATES="/opt/exposureguard/nuclei-templates" \
    TMPDIR="/tmp/exposureguard"

USER 10001:10001
WORKDIR /home/exposureguard

ENTRYPOINT ["/usr/local/bin/exposureguard"]
CMD ["--help"]
