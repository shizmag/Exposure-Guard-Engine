# ExposureGuard Integrations Architecture

ExposureGuard Engine incorporates a modular integration and adapter layer designed to orchestrate third-party security and discovery tools (Subfinder, httpx, Katana, Nuclei) without treating them as the domain model.

External tools act as replaceable probe providers that feed into ExposureGuard's normalized control plane.

```text
               ExposureGuard Engine
                       │
              Orchestration Layer
                       │
          ┌────────────┴────────────┐
          │                         │
    Native scanners          External adapters
          │                         │
          │             ┌───────────┼───────────┐
          │             │           │           │
          │        Subfinder      httpx       Katana
          │                                     │
          │                                   Nuclei
          │
          └────────────┬────────────────────────┘
                       │
                       ▼
                 Normalization
                       │
             Asset / Observation
                       │
                    Finding
                       │
                    Snapshot
                       │
                      Diff
```

---

## 1. Core Principles

1. **Native Engine Independence**: ExposureGuard remains fully operational without external tools. Target parsing, network safety, DNS, TLS, root HTTP, crawling, JS lexical analysis, snapshots, and diffs work standalone.
2. **Decoupled Process Lifecycle**: Individual adapters do NOT invoke `os/exec`. The centralized `Runner` owns process supervision, bounded stdout/stderr, timeouts, process group signal propagation (`SIGTERM` -> grace period -> `SIGKILL`), and isolated temporary directories.
3. **Canonical Normalization**: Tool-specific JSON/JSONL outputs are normalized into canonical `Asset`, `Observation`, and `Finding` types. No raw JSON bloat enters `Snapshot`.
4. **Stable Identity & Deduplication**: Discovered assets share deterministic identity keys (`ComputeAssetID`). Overlapping native and external entities are deduplicated and merged with combined source provenance.
5. **Strict Safety Boundaries**: External tools must not bypass `netguard`. All targets undergo scope validation, scheme validation, and SSRF/private-network rejection before delegation.
6. **Failure Isolation**: If an external tool exits abnormally or times out, the scan transitions to `partial` status while preserving all native and other integration findings. If an integration is flagged `--require-integration <id>`, absence or failure causes an immediate exit code failure.

---

## 2. Capability Model

Engine stages orchestrate by capability rather than coupling to specific tool binary names:

| Capability | Description | Implementing Tools |
| :--- | :--- | :--- |
| `asset-discovery` | Passive subdomain / host discovery | Subfinder |
| `http-probe` | HTTP reachability & port verification | httpx |
| `asset-enrichment` | Web server & technology fingerprinting | httpx |
| `crawler` | Deep recursive link and endpoint discovery | Katana, Native Crawler |
| `endpoint-discovery` | API route and URL extraction | Katana |
| `security-check` | Defensive policy-curated security inspection | Nuclei |

---

## 3. Scan Profiles and Access Policies

| Profile | Allowed Modes | Integrations Activated | Notes |
| :--- | :--- | :--- | :--- |
| `quick` | `public`, `owned` | None (native only) | Fast DNS/TLS/HTTP inspection |
| `standard` | `public`, `owned` | Subfinder (passive) | Safe outside-in reconnaissance |
| `deep` | `owned` (strict) | Subfinder, httpx, Katana, Nuclei | Requires ownership verification |

### Mode Enforcement
* **`public`**: Only passive OSINT discovery (`subfinder`) is permitted. Active probes (`httpx`, `katana`, `nuclei`) are rejected with `policy-denied`.
* **`owned`**: All approved adapters are permitted in accordance with configured scan boundaries and rate limits.

---

## 4. CLI Controls

```bash
# Verify system readiness and installed integrations
exposureguard doctor
exposureguard doctor --format json

# Inspect registered integrations
exposureguard integrations list
exposureguard integrations info nuclei

# Run with custom integration selection
exposureguard scan example.com --integrations subfinder,httpx
exposureguard scan example.com --integrations none
exposureguard scan example.com --disable-integration nuclei
exposureguard scan example.com --require-integration subfinder
```
