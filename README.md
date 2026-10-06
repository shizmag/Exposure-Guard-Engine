# ExposureGuard Engine

[![CI](https://github.com/exposureguard/exposureguard/actions/workflows/ci.yml/badge.svg)](https://github.com/exposureguard/exposureguard/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/exposureguard/exposureguard)](https://goreportcard.com/report/github.com/exposureguard/exposureguard)

**ExposureGuard Engine** is an open-source, defensive outside-in scanner and inventory engine for web applications.

It answers one fundamental question:

> **What does your public website or web application expose to the outside world, and what meaningful changes occurred between today and yesterday?**

---

## Quick Start

### 1. Installation

#### Automated Installer (Local)
Installs ExposureGuard engine and all pinned external discovery tools (`subfinder`, `httpx`, `katana`, `nuclei`):
```bash
./install.sh
exposureguard doctor
```

#### Build from Source
```bash
make build
./bin/exposureguard doctor
```

### 2. Run a Scan
```bash
exposureguard scan https://example.com
```

### 3. External Toolchain & Integrations
```bash
# Verify health of engine and discovery integrations
exposureguard doctor

# List registered integrations
exposureguard integrations list

# Run with specific discovery tools
exposureguard scan example.com --integrations subfinder,httpx

# Deep scan for owned domains
exposureguard scan example.com --mode owned --profile deep
```

### Example Output:
```text
ExposureGuard

Target: https://example.com/

DNS
  ✓ resolved (IPs: 93.184.216.34)

TLS
  ✓ certificate valid (expires in 68 days)

HTTP
  ✓ response status 200
  ⚠ Content-Security-Policy absent

Frontend
  14 JavaScript assets discovered
  ⚠ 1 public source map(s) detected

Summary
  2 findings total (0 critical, 0 high, 1 medium, 1 low)
  Duration: 1.2s

Findings:
  [MEDIUM] Public Source Map Accessible (frontend.public_source_map)
      Asset: https://example.com/static/app.js.map
  [LOW] Missing Strict-Transport-Security Header (http.missing_hsts)
      Asset: https://example.com/
```

---

## What It Is vs What It Is NOT

| What ExposureGuard Is | What ExposureGuard Is NOT |
|---|---|
| Safe outside-in asset discovery & state inventory | Not an offensive penetration testing tool |
| Passive DNS, TLS, HTTP, and static JS inspection | No exploit payloads, SQLi, or XSS fuzzing |
| Referenced source-map detection and validation | No brute-force directory or port scanning |
| Deterministic snapshots and state diffing over time | No form submissions or authentication attempts |
| Single static binary CLI and Cloud worker process | No multi-tenant database, billing, or UI dashboard |

---

## Machine & Cloud Integration

### JSON Snapshot Mode
```bash
exposureguard scan https://example.com --format json
```

### Streaming JSONL Protocol
For integration into worker queues, CI/CD, or ExposureGuard Cloud:
```bash
exposureguard scan \
  --request-json - \
  --format jsonl < request.json
```
Output streams real-time line-delimited JSON events:
```json
{"schema_version":"1","seq":1,"timestamp":"2026-10-06T12:00:00Z","scan_id":"019...","type":"scan.started","data":{"target":"https://example.com/"}}
{"schema_version":"1","seq":2,"timestamp":"2026-10-06T12:00:01Z","scan_id":"019...","type":"stage.started","data":{"stage":"dns"}}
...
{"schema_version":"1","seq":18,"timestamp":"2026-10-06T12:00:03Z","scan_id":"019...","type":"scan.completed","data":{"status":"complete","findings":2}}
```

See [docs/cloud-integration.md](docs/cloud-integration.md) for full protocol specifications.

---

## Snapshot Diffing

Compare yesterday's state with today's state:

```bash
exposureguard diff previous_snapshot.json latest_snapshot.json
```

Or detect changes during a live scan:

```bash
exposureguard scan https://example.com \
  --previous-snapshot previous.json \
  --snapshot-out today.json
```

---

## Docker

Run as an isolated, unprivileged container:

```bash
docker run --rm ghcr.io/exposureguard/exposureguard:latest scan https://example.com --format json
```

---

## Security Model

ExposureGuard assumes all targets and redirects are untrusted:
- **Strict SSRF Protection**: Prohibits connections to loopback (`127.0.0.0/8`, `::1`), private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), cloud metadata (`169.254.169.254`), and CGNAT.
- **DNS Rebinding Prevention**: Validates candidate IPs before dialing and connects only to the validated IP literal.
- **Strict Resource Bounds**: Crawl depth, page counts, response body size, and concurrency are strictly capped.
- **Zero Secret Leakage**: Credential matches in bundles are masked and fingerprinted; plaintext values are never output.

Read [docs/security-model.md](docs/security-model.md) for details.

---

## Relationship with ExposureGuard Cloud

ExposureGuard Engine is 100% open source under Apache 2.0. It functions completely standalone on developer laptops and in CI.

**ExposureGuard Cloud** is the managed SaaS platform that orchestrates scheduled scans, historical dashboards, notifications, and team collaboration by running this engine as its core worker process.

---

## Contributing

We welcome community contributions! See:
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [docs/contributing-checks.md](docs/contributing-checks.md)
- [SECURITY.md](SECURITY.md)

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
