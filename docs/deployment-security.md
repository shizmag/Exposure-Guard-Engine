# ExposureGuard Deployment & Egress Security

ExposureGuard Engine is an ephemeral stateless execution unit. Cloud invokes a local subprocess; it does not require an Engine service. Cloud owns authorization, persistence, scheduling and retries.

## Egress boundary

Native Go clients use netguard, rejecting loopback, private, link-local, multicast, unspecified, reserved and metadata destinations by default. `httpx`, Katana and Nuclei use independent network stacks and bypass Go netguard. Subfinder uses upstream passive sources. Batch does not change these boundaries.

Production Cloud worker MUST enforce host/container egress isolation for all external processes, including DNS and IPv4/IPv6 private/metadata networks. Apply `deploy/security/iptables.example.sh` or nftables equivalent. Network policy should also restrict/monitor DNS and prevent metadata service access. `--allow-private` is for controlled local tests only; never set it in production.

## Immutable distribution and runtime

Official runtime image uses `/opt/exposureguard` as `EXPOSUREGUARD_HOME`, with core and pinned tool binaries in `bin/`, templates in `share/nuclei-templates/`, curated rules under `profiles/nuclei/v1/`, and `distribution-manifest.json`. Build-time acquisition verifies locked SHA-256 hashes. Runtime performs no dependency/template downloads or updates. Pin Cloud deployment to an immutable image digest (tags `0.1.0`, `0.1`, `sha-<git>` are discovery aliases; `latest` is not a production pin).

Host installation uses `install.sh --with-tools`, pinned `tools.lock.json`, and writes a distribution manifest. Run `exposureguard doctor` to verify tools, profiles, permissions and distribution fingerprint. `exposureguard version --json` reports protocol, Snapshot, identity, toolchain, ruleset, distribution-manifest and core-binary fingerprints. Doctor never updates dependencies.

## Container controls

Run as non-root UID 10001. Keep filesystem writable only for configured temp/work directories; provide adequate temp budget for scan and Batch output. Allocate CPU/memory according to batch concurrency; Batch defaults to at most 4 active scans, 4 external children, 256 MiB temporary data, and 64 MiB event output. Each individual scan caps native HTTP/crawler concurrency at 2 and rate at 1 request/second/host. External process slots are shared globally and never exceed the configured limit. Batch limits do not replace cgroups, egress rules or process monitoring. On SIGTERM, allow a bounded grace period before SIGKILL; Engine terminates managed child process groups and removes temporary scan work.

Cloud Dockerfiles may consume Engine distribution without starting a service:

```Dockerfile
ARG ENGINE_IMAGE
FROM ${ENGINE_IMAGE} AS engine
FROM node-runtime
COPY --from=engine /opt/exposureguard /opt/exposureguard
```

Cloud worker still calls `/opt/exposureguard/bin/exposureguard batch ...` with local `spawn()` and streams stdout/stderr.
