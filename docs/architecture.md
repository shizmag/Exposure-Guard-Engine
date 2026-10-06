# ExposureGuard Engine Architecture & Specification

## 1. Mission and Boundaries

ExposureGuard Engine is a standalone, defensive outside-in scanner and inventory engine for web applications.

### What it is
- Standalone CLI (`exposureguard`) with self-contained core engine and Docker distribution.
- Safe, outside-in inspection of public websites and internet-facing assets.
- Produces normalized deterministic **Snapshots** (`Observation`, `Asset`, `Finding`).
- Detects meaningful state drift across time (**Changes** / Diff engine).
- Zero-dependency worker process for ExposureGuard Cloud (communicates via stdin ScanRequest / stdout JSONL).
- Enhanced discovery profiles (`standard`, `deep`) orchestrate pinned external discovery tools (`subfinder`, `httpx`, `katana`, `nuclei`).

### What it is NOT
- Not a generic penetration testing or exploitation tool (no SQLi, XSS fuzzing, exploit payloads).
- Not a multi-tenant backend (no billing, users, databases, queues, dashboards).
- Not an unconstrained crawler or aggressive directory brute-forcer.

---

## 2. Core Concepts: Observation vs Finding vs Change

1. **Observation**: Verified normalized fact about an asset.
   - *Example*: `GET /` returns `200 OK`, `HSTS` header present, certificate expires on `2026-11-01`.
2. **Finding**: Conservative defensive conclusion with actionable remediation guidance.
   - *Example*: `frontend.public_source_map` detected at `/static/app.js.map`, exposing production source paths.
3. **Change**: Difference between two normalized Snapshots.
   - *Example*: `frontend.source_map_appeared`, `http.security_header_removed`.

---

## 3. Package Architecture

```text
exposureguard/
├── cmd/exposureguard/             # Main executable entrypoint
├── internal/
│   ├── buildinfo/                 # Version, Git commit, build time, protocol versions
│   └── config/                    # Koanf configuration loader (defaults, file, env, flags)
├── pkg/
│   ├── model/                     # Core domain models (Target, Asset, Observation, Finding, Change, Snapshot)
│   ├── protocol/                  # JSONL streaming events (Envelope, monotonic seq, request decoding)
│   ├── netguard/                  # Hardened network layer (SSRF protection, safe DNS resolver, safe dialer, transport)
│   ├── target/                    # URL canonicalization, normalization, scope filters
│   ├── policy/                    # Execution mode policies (public vs owned)
│   ├── checks/                    # Modular defensive check implementations
│   │   ├── dns/                   # A, AAAA, CNAME, MX, TXT, NS, CAA inspection
│   │   ├── tls/                   # TLS handshake, cert chain, expiration, SAN, cipher inspection
│   │   ├── http/                  # Root HTTP inspection, redirects, status, metadata
│   │   ├── headers/               # Security headers analysis (CSP, HSTS, X-Frame-Options, etc.)
│   │   ├── cookies/               # Set-Cookie security attributes (Secure, HttpOnly, SameSite; no values)
│   │   ├── javascript/            # JS bundle discovery, static parsing, endpoint extraction
│   │   └── sourcemaps/            # Explicit //# sourceMappingURL and fallback .map validation
│   ├── crawl/                     # Bounded same-host HTTP crawler, HTML asset extraction
│   ├── static/                    # Pure AST / lexical analysis for JS (tdewolff/parse/v2/js)
│   ├── redact/                    # Secret masking, fingerprinting (zero plaintext leakage)
│   ├── snapshot/                  # Deterministic snapshot builder, stable hash IDs, sorting
│   ├── diff/                      # Snapshot comparison and change classification
│   └── render/                    # Output formatters (human ANSI, JSON, streaming JSONL)
```

---

## 4. Security & Network Model (`pkg/netguard`)

Hostile target assumption: Every target URL and redirect is untrusted.

1. **SSRF & Private Network Guard**:
   - Prohibit connections to loopback (`127.0.0.0/8`, `::1`), private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local / cloud metadata (`169.254.0.0/16`, `fe80::/10`), CGNAT (`100.64.0.0/10`), multicast, broadcast, and IPv4-mapped IPv6 representations.
2. **DNS Rebinding Prevention**:
   - `SafeDialer` resolves hostname directly before connection.
   - Evaluates every resolved IP against `NetworkPolicy`.
   - Connects only to validated IP using target IP in `net.Dialer` while preserving original hostname in `tls.Config.ServerName` and HTTP `Host` header.
3. **Redirect Enforcement**:
   - Maximum 8 redirects by default.
   - Schemes restricted to `http` and `https`.
   - Every redirect target URL and its resolved IPs are re-validated against network policy.
4. **Controlled Environment**:
   - Check modules do not create raw HTTP clients or dialers. All requests use `env.HTTPClient` and `env.DNSResolver`.

---

## 5. Stable Identity & Diffing

Snapshots are fully deterministic:
- All arrays (`assets`, `observations`, `findings`, `changes`, `records`) are sorted by stable keys.
- Stable IDs computed via `sha256(kind + ":" + normalized_key)`.
- Volatile fields (response dates, session cookie values, nonces, TTLs, request IDs) are excluded from identity hashes and diff calculation.

---

## 6. Pinned Dependencies & Versions

| Package | Version | Purpose |
|---|---|---|
| `Go` | `1.27.0` (toolchain auto-managed) | Language baseline |
| `github.com/spf13/cobra` | `v1.10.2` | CLI command parsing |
| `github.com/knadh/koanf/v2` | `v2.3.7` | Layered configuration |
| `github.com/knadh/koanf/parsers/yaml` | `v1.1.1` | YAML config parser |
| `github.com/knadh/koanf/providers/file` | `v1.2.1` | File config provider |
| `github.com/knadh/koanf/providers/env` | `v1.1.0` | Environment variable provider |
| `github.com/miekg/dns` | `v1.1.73` | Structured DNS records querying |
| `github.com/PuerkitoBio/goquery` | `v1.13.0` | HTML document DOM traversal |
| `github.com/tdewolff/parse/v2` | `v2.8.16` | Fast JavaScript lexical parser |
| `golang.org/x/net` | `v0.59.0` | Public suffix list & HTML tokenizing |
| `golang.org/x/sync` | `v0.23.0` | Bounded concurrency (errgroup) |
| `golang.org/x/time` | `v0.16.0` | Per-host rate limiting |
| `github.com/stretchr/testify` | `v1.12.1` | Unit & integration assertions |

---

## 7. Assumptions & Safety Constraints

1. **No offensive attacks**: Form submission, authentication attempts, POST/PUT/DELETE, and exploit payloads are strictly forbidden.
2. **Safe Crawling**: Exact hostname crawl only. External links are recorded as passive asset references but never crawled.
3. **Bounded consumption**: Hard limits enforced for max depth (2), pages (100), assets (500), body size (4 MiB), JS size (8 MiB), source map size (10 MiB), and total scan download (50 MiB).
4. **Zero secret leakage**: Discovered credentials in JS/maps are masked and fingerprinted; plaintext values are never output in logs, snapshots, or JSONL events.
5. **Pure Go / CGO_ENABLED=0**: Cross-platform portability across Linux, macOS, and Windows.
