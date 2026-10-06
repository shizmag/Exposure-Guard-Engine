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
| `standard` | `public`, `owned` | Subfinder (passive in public; +httpx in owned) | Safe outside-in reconnaissance |
| `deep` | `owned` (strict) | Subfinder, httpx, Katana, Nuclei | Extended active discovery |

### Mode Enforcement and Authorization Semantics

* **`mode=public`**: Default mode. Strictly restricted to non-intrusive operations: native DNS/TLS/HTTP/crawling and passive OSINT discovery (`subfinder`). Active probing tools (`httpx`, `katana`, `nuclei`) are blocked. Explicitly requesting active tools via `--integrations` or `--require-integration` in public mode triggers an immediate `integration policy violation` error.
* **`mode=owned`**: Enables extended active discovery tools (`httpx`, `katana`, `nuclei`) within configured rate limits and boundaries.
* **Authorization Responsibility**:
  > Specifying `--mode owned` on the CLI represents an **authorization declaration by the caller**. The standalone OSS CLI physically cannot prove domain ownership on its own.
  >
  > **ExposureGuard Cloud and orchestrators MUST complete authoritative proof-of-ownership** (such as DNS TXT record challenge or HTTP token verification) before dispatching any scan with `mode=owned` to an engine worker. The engine never assumes ownership verification occurred unless orchestrated by Cloud.

---

## 4. CLI Controls

```bash
# Verify system readiness and installed integrations
exposureguard doctor
exposureguard doctor --format json

# Inspect registered integrations
exposureguard integrations list
exposureguard integrations info nuclei

# Run with custom integration selection (mode=owned required when selecting active tools)
exposureguard scan example.com --mode owned --integrations subfinder,httpx
exposureguard scan example.com --integrations none
exposureguard scan example.com --disable-integration nuclei
exposureguard scan example.com --require-integration subfinder
```
