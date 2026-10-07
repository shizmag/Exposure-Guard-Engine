# ExposureGuard Engine

[![CI](https://github.com/exposureguard/exposureguard/actions/workflows/ci.yml/badge.svg)](https://github.com/exposureguard/exposureguard/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/exposureguard/exposureguard)](https://goreportcard.com/report/github.com/exposureguard/exposureguard)

**ExposureGuard Engine** is an open-source, defensive outside-in scanner and inventory engine for web applications.

It continuously observes what your internet-facing assets expose to the outside world and detects meaningful state drift over time without intrusive exploits.

---

## 30-Second Demo: Tracking Exposure Drift

The true power of ExposureGuard is detecting **what changed**:

```bash
# Day 1: Save baseline snapshot
exposureguard scan https://example.com --snapshot-out baseline.json

# Day 2: Deploy new release and compare against baseline
exposureguard scan https://example.com --previous-snapshot baseline.json
```

```text
ExposureGuard

Target
  https://example.com

Surface
  4 hostnames
  18 pages
  27 JavaScript assets
  6 endpoint candidates

TLS
  ✓ Valid (expires in 54 days)

Findings
  · 1 medium
  · 2 low

  · [medium] Public JavaScript Source Map Detected (frontend.public_source_map)
    Asset: https://example.com/static/app.js.map
    Preview: //# sourceMappingURL=app.js.map

Changes
  + Public source map appeared in production
  ~ Security header content_security_policy was removed
  + New asset staging.example.com (hostname) discovered

Scan completed in 2.1s
```

---

## Installation

### Automated Installer (Recommended)
Installs the standalone engine binary and pinned discovery tools (`subfinder`, `httpx`, `katana`, `nuclei`):
```bash
./install.sh
exposureguard doctor
```

### Build from Source
```bash
git clone https://github.com/exposureguard/exposureguard.git
cd exposureguard
make build
./bin/exposureguard doctor
```

### Shell Completion
```bash
exposureguard completion zsh > "${fpath[1]}/_exposureguard"
# or for bash:
exposureguard completion bash > /etc/bash_completion.d/exposureguard
```

---

## Running Scans

```bash
# Standard scan (bounded crawl + passive discovery)
exposureguard scan https://example.com

# Fast current-state check (no crawl, no external tools)
exposureguard scan https://example.com --profile quick

# Preview scan plan without network requests
exposureguard scan https://example.com --profile standard --plan

# Summary-only output
exposureguard scan https://example.com --quiet
```

---

## Comparing Two Snapshots

```bash
# Compute deterministic state difference between any two snapshots
exposureguard diff yesterday.json today.json

# Verify canonical SHA-256 fingerprint of a snapshot
exposureguard snapshot hash today.json
```

---

## Scan Profiles

ExposureGuard provides three centrally governed scan profiles:

| Profile | Target Intent | Native Modules | External Integrations | Authorization Mode |
| :--- | :--- | :--- | :--- | :---: |
| **`quick`** | Fast current-state health check | DNS, TLS, HTTP root | None | Any (`public` or `owned`) |
| **`standard`** | Default outside-in scan | DNS, TLS, HTTP, Crawl, JS, Source Maps | Subfinder (passive) | Any (`public` or `owned`) |
| **`deep`** | Comprehensive authorized scan | All standard modules | Subfinder, httpx, Katana, Nuclei | **`owned`** only |

Inspect profiles directly in the CLI:
```bash
exposureguard profiles list
exposureguard profiles show standard
```

---

## Machine Usage (Protocol v1)

### Structured JSON Result
```bash
exposureguard scan https://example.com --format json
```

### Real-time Streaming JSONL
Single scan JSONL stays compatible with existing Scan Protocol v1 consumers:
```bash
exposureguard scan \
  --request-json - \
  --format jsonl < request.json
```

For scheduled background work, submit a bounded Batch Protocol v1 request:
```bash
exposureguard batch --request-json - --format jsonl < batch-request.json
```
Use `scan` for manual/latency-sensitive requests; Cloud schedules/retries/persists and uses `batch` for monitoring. Batch limits workload count separately from concurrency (default 4 active, max 4; max 20 workloads). See [docs/batch-protocol-v1.md](docs/batch-protocol-v1.md), [docs/protocol-v1.md](docs/protocol-v1.md), and [docs/cloud-integration.md](docs/cloud-integration.md).

---

## Docker

ExposureGuard runs as an unprivileged, read-only compatible container:

```bash
docker run --rm \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  ghcr.io/exposureguard/exposureguard:0.1.0 \
  scan https://example.com --format json
```

---

## Security Model & Explicit Limitations

- **Defensive by Design**: ExposureGuard discovers assets and identifies misconfigurations. It is **not** an automated pentest tool and **not** an offensive exploit framework.
- **Authorization Responsibility**: Passing `--mode owned` declares authorization for active crawling and probing; it does **not** prove legal target ownership.
- **Egress Isolation Obligation**: While the native Go engine strictly enforces SSRF protection via `netguard`, external subprocesses (`httpx`, `katana`, `nuclei`) interact directly with the operating system network stack. Production deployments **must** enforce network egress firewalls blocking private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and cloud metadata (`169.254.169.254`). Reference rules are provided in `deploy/security/`.
- **No Guarantee of Complete Security**: Zero findings means no tested exposures were identified; it is not a certificate of invulnerability.

See [docs/security-model.md](docs/security-model.md) and [docs/deployment-security.md](docs/deployment-security.md).

---

## Relationship to ExposureGuard Cloud

The ExposureGuard Engine is a stateless, single-binary execution worker. 

**ExposureGuard Cloud** acts as the orchestration, notification, and temporal storage layer:
- Schedules recurring scans.
- Verifies domain ownership via DNS/HTTP challenges before authorizing `owned` mode.
- Ingests engine snapshots, calculates historical diffs, and sends alerts (Telegram, Slack, Email).

---

## Community & Contributing

- Documentation Navigation: **[docs/README.md](docs/README.md)**
- Finding Rules Philosophy: **[docs/finding-philosophy.md](docs/finding-philosophy.md)**
- Security Checks Catalog: **[docs/checks.md](docs/checks.md)**
- Contributing Checks: **[docs/contributing-checks.md](docs/contributing-checks.md)**
- Third-Party Licenses: **[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)**

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
