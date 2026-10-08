# syntax=docker/dockerfile:1

FROM golang:1.27.0-alpine3.23 AS builder
WORKDIR /src
RUN apk add --no-cache git make ca-certificates
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG ENGINE_VERSION=0.1.0-cloud-contract
ARG ENGINE_COMMIT=cloud-contract
ARG BUILD_DATE=2026-10-07T00:00:00Z
RUN CGO_ENABLED=0 make build VERSION="${ENGINE_VERSION}" COMMIT="${ENGINE_COMMIT}" BUILD_DATE="${BUILD_DATE}" && \
    mkdir -p /dist/bin && cp bin/exposureguard /dist/bin/exposureguard && \
    cp tools.lock.json /dist/tools.lock.json && \
    cp schemas/distribution-manifest.schema.json /dist/distribution-manifest.schema.json && \
    mkdir -p /dist/profiles/nuclei/v1 && cp profiles/nuclei/v1/* /dist/profiles/nuclei/v1/ && \
    go run ./cmd/build-distribution --root /dist --schema /dist/distribution-manifest.schema.json --version "${ENGINE_VERSION}" --commit "${ENGINE_COMMIT}"

FROM golang:1.27.0-alpine3.23 AS tool-fetcher
RUN apk add --no-cache curl unzip ca-certificates python3
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
WORKDIR /dist
COPY tools.lock.json /dist/
ARG TARGETARCH
RUN set -eu; \
    ARCH="${TARGETARCH:-arm64}"; \
    case "$ARCH" in amd64|x86_64) ARCH="amd64" ;; arm64|aarch64) ARCH="arm64" ;; esac; \
    PLATFORM="linux_${ARCH}"; mkdir -p /dist/bin /dist/share/nuclei-templates /dist/profiles/nuclei/v1 /dist/schemas; \
    download_tool() { \
      tool="$1"; \
      version=$(python3 -c "import json; m=json.load(open('tools.lock.json')); print(m['tools']['$tool']['version'])"); \
      archive=$(python3 -c "import json; m=json.load(open('tools.lock.json')); print(m['tools']['$tool']['checksums']['$PLATFORM']['archive'])"); \
      expected=$(python3 -c "import json; m=json.load(open('tools.lock.json')); print(m['tools']['$tool']['checksums']['$PLATFORM']['sha256'])"); \
      curl -fsSL --retry 3 "https://github.com/projectdiscovery/${tool}/releases/download/v${version}/${archive}" -o "/tmp/${archive}"; \
      echo "${expected}  /tmp/${archive}" | sha256sum -c -; \
      mkdir -p "/tmp/ext_${tool}"; unzip -q "/tmp/${archive}" -d "/tmp/ext_${tool}"; \
      mv "/tmp/ext_${tool}/${tool}" "/dist/bin/${tool}"; chmod 755 "/dist/bin/${tool}"; rm -rf "/tmp/${archive}" "/tmp/ext_${tool}"; \
    }; \
    download_tool subfinder; download_tool httpx; download_tool katana; download_tool nuclei; \
    tpl_ver=$(python3 -c "import json; m=json.load(open('tools.lock.json')); print(m['tools']['nuclei-templates']['version'])"); \
    tpl_sha=$(python3 -c "import json; m=json.load(open('tools.lock.json')); print(m['tools']['nuclei-templates']['sha256'])"); \
    tpl_archive="v${tpl_ver}.zip"; \
    curl -fsSL --retry 3 "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/${tpl_archive}" -o "/tmp/${tpl_archive}"; \
    echo "${tpl_sha}  /tmp/${tpl_archive}" | sha256sum -c -; \
    mkdir -p /tmp/tpl_ext; unzip -q "/tmp/${tpl_archive}" -d /tmp/tpl_ext; \
    cp -r /tmp/tpl_ext/nuclei-templates-*/* /dist/share/nuclei-templates/; \
    printf '%s\n' "$tpl_ver" > /dist/share/nuclei-templates/.nuclei-templates-version; \
    rm -rf "/tmp/${tpl_archive}" /tmp/tpl_ext

COPY --from=builder /dist/ /dist/
ARG ENGINE_VERSION=0.1.0-cloud-contract
ARG ENGINE_COMMIT=cloud-contract
RUN cd /src && go run ./cmd/build-distribution --root /dist --schema /dist/distribution-manifest.schema.json --version "${ENGINE_VERSION}" --commit "${ENGINE_COMMIT}"


FROM alpine:3.21 AS runtime
RUN apk add --no-cache ca-certificates bind-tools tzdata \
    && addgroup -g 10001 -S exposureguard \
    && adduser -u 10001 -S -G exposureguard -h /home/exposureguard exposureguard \
    && mkdir -p /opt/exposureguard/share/nuclei-templates /opt/exposureguard/bin /opt/exposureguard/profiles/nuclei/v1 /tmp/exposureguard \
    && chown -R exposureguard:exposureguard /opt/exposureguard /tmp/exposureguard
COPY --from=tool-fetcher /dist/bin/ /opt/exposureguard/bin/
COPY --from=tool-fetcher /dist/share/nuclei-templates/ /opt/exposureguard/share/nuclei-templates/
COPY --from=tool-fetcher /dist/profiles/ /opt/exposureguard/profiles/
COPY --from=tool-fetcher /dist/distribution-manifest.json /opt/exposureguard/distribution-manifest.json
COPY --from=tool-fetcher /dist/tools.lock.json /opt/exposureguard/tools.lock.json
COPY schemas/distribution-manifest.schema.json /opt/exposureguard/distribution-manifest.schema.json
ENV PATH="/opt/exposureguard/bin:${PATH}" \
    EXPOSUREGUARD_HOME="/opt/exposureguard" \
    EXPOSUREGUARD_NUCLEI_TEMPLATES="/opt/exposureguard/share/nuclei-templates" \
    TMPDIR="/tmp/exposureguard"
USER 10001:10001
WORKDIR /home/exposureguard
ENTRYPOINT ["/opt/exposureguard/bin/exposureguard"]
CMD ["--help"]
