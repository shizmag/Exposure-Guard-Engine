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
RUN CGO_ENABLED=0 make build VERSION="${ENGINE_VERSION}" COMMIT="${ENGINE_COMMIT}" BUILD_DATE="${BUILD_DATE}"

FROM alpine:3.21 AS tool-fetcher
RUN apk add --no-cache curl unzip ca-certificates python3
WORKDIR /dist
COPY tools.lock.json /dist/
ARG TARGETARCH
RUN set -eu; \
    ARCH="${TARGETARCH:-arm64}"; \
    case "$ARCH" in amd64|x86_64) ARCH="amd64" ;; arm64|aarch64) ARCH="arm64" ;; esac; \
    PLATFORM="linux_${ARCH}"; mkdir -p /dist/bin /dist/templates; \
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
    cp -r /tmp/tpl_ext/nuclei-templates-*/* /dist/templates/; \
    printf '%s\n' "$tpl_ver" > /dist/templates/.nuclei-templates-version; \
    printf '%s\n' "$tpl_sha" > /dist/templates/.nuclei-templates-archive.sha256; \
    rm -rf "/tmp/${tpl_archive}" /tmp/tpl_ext

COPY --from=builder /src/bin/exposureguard /dist/bin/exposureguard
COPY profiles/nuclei/v1/ /dist/profiles/nuclei/v1/
COPY tools.lock.json /dist/tools.lock.json
COPY schemas/distribution-manifest.schema.json /dist/distribution-manifest.schema.json
ARG ENGINE_VERSION=0.1.0-cloud-contract
ARG ENGINE_COMMIT=cloud-contract
ENV ENGINE_VERSION=${ENGINE_VERSION} ENGINE_COMMIT=${ENGINE_COMMIT}
RUN python3 - <<'PY'
import hashlib, json, os, pathlib
root=pathlib.Path('/dist')
lock_path=root/'tools.lock.json'
lock=json.loads(lock_path.read_text())
sha=lambda p: hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
manifest={
 'distribution_schema_version':'1','engine':'exposureguard','engine_version':os.environ['ENGINE_VERSION'],'engine_commit':os.environ['ENGINE_COMMIT'],
 'engine_binary_sha256':sha(root/'bin/exposureguard'),'protocol_version':'1','batch_protocol_version':'1','snapshot_schema_version':'1','identity_algorithm_version':'1',
 'toolchain_manifest_sha256':sha(lock_path),
 'tools':{name:{'version':lock['tools'][name]['version'],'binary_sha256':sha(root/'bin'/name)} for name in ('subfinder','httpx','katana','nuclei')},
 'nuclei_templates_version':lock['tools']['nuclei-templates']['version'],'nuclei_templates_sha256':(root/'templates/.nuclei-templates-archive.sha256').read_text().strip(),
 'nuclei_ruleset_version':'v1.0-defensive','nuclei_ruleset_sha256':sha(root/'profiles/nuclei/v1/manifest.json')}
schema=json.loads((root/'distribution-manifest.schema.json').read_text())
required=schema['required']
assert all(key in manifest for key in required)
assert all(len(manifest[key]) == 64 for key in ('engine_binary_sha256','toolchain_manifest_sha256','nuclei_templates_sha256','nuclei_ruleset_sha256'))
(root/'distribution-manifest.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
PY


FROM alpine:3.21 AS runtime
RUN apk add --no-cache ca-certificates bind-tools tzdata \
    && addgroup -g 10001 -S exposureguard \
    && adduser -u 10001 -S -G exposureguard -h /home/exposureguard exposureguard \
    && mkdir -p /opt/exposureguard/share/nuclei-templates /opt/exposureguard/bin /opt/exposureguard/profiles/nuclei/v1 /tmp/exposureguard \
    && chown -R exposureguard:exposureguard /opt/exposureguard /tmp/exposureguard
COPY --from=tool-fetcher /dist/bin/ /opt/exposureguard/bin/
COPY --from=tool-fetcher /dist/templates/ /opt/exposureguard/share/nuclei-templates/
COPY --from=tool-fetcher /dist/profiles/ /opt/exposureguard/profiles/
COPY --from=tool-fetcher /dist/distribution-manifest.json /opt/exposureguard/distribution-manifest.json
COPY --from=tool-fetcher /dist/tools.lock.json /opt/exposureguard/tools.lock.json
ENV PATH="/opt/exposureguard/bin:${PATH}" \
    EXPOSUREGUARD_HOME="/opt/exposureguard" \
    EXPOSUREGUARD_NUCLEI_TEMPLATES="/opt/exposureguard/share/nuclei-templates" \
    TMPDIR="/tmp/exposureguard"
USER 10001:10001
WORKDIR /home/exposureguard
ENTRYPOINT ["/opt/exposureguard/bin/exposureguard"]
CMD ["--help"]
