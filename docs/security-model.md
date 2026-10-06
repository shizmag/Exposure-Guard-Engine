# ExposureGuard Security Model & Threat Boundary

ExposureGuard Engine operates under the explicit assumption that **the scan target is completely hostile**.

---

## 1. Threat Mitigation Objectives

1. Prevent Server-Side Request Forgery (SSRF) into cloud provider metadata services (`169.254.169.254`), internal VPC networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and container loopback (`127.0.0.0/8`, `::1`).
2. Defend against DNS rebinding attacks that attempt to bypass initial validation by switching DNS answers between lookup and connection time.
3. Prevent denial-of-service or memory exhaustion through response size limits, total download quotas, and rate limiting.
4. Prevent secret leakage in output artifacts, logs, or JSONL events.

---

## 2. Network Boundary Enforcement (`pkg/netguard`)

### Blocked Destinations
- IPv4 Loopback (`127.0.0.0/8`) & Current Network (`0.0.0.0/8`)
- RFC 1918 Private Ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
- Link-Local & Cloud Metadata (`169.254.0.0/16`)
- Shared CGNAT (`100.64.0.0/10`)
- Multicast & Reserved (`224.0.0.0/4`, `240.0.0.0/4`)
- IPv6 Loopback (`::1/128`), Unspecified (`::/128`), ULA (`fc00::/7`), Link-Local (`fe80::/10`)
- IPv4-Mapped IPv6 representations of all forbidden ranges (e.g. `::ffff:127.0.0.1`)
- Restricted hostnames (`localhost`, `*.localhost`, `metadata.google.internal`, `instance-data`)

### DNS Rebinding Defense
Traditional HTTP clients resolve a hostname and connect via OS sockets. If an attacker's DNS server returns a public IP during initial inspection and then returns `127.0.0.1` during connection, naive scanners connect to localhost.

ExposureGuard's `SafeDialer`:
1. Intercepts `DialContext`.
2. Resolves candidate IPs directly before dialing using `SafeResolver`.
3. Verifies every candidate IP against `NetworkPolicy`.
4. Connects **directly to the validated IP literal** via `net.Dialer`.
5. Retains the original domain name in `tls.Config.ServerName` and HTTP `Host` headers.

### Redirect Policy
- Max 8 hops by default.
- Only `http` and `https` schemes permitted (`file:`, `ftp:`, `gopher:`, `unix:` rejected).
- Target hostname and resolved IPs re-validated at every redirect hop.

---

## 3. Resource Bounds & Safeguards

- Single response body limit: 4 MiB (JS: 8 MiB, Source Maps: 10 MiB).
- Total scan download budget: 50 MiB.
- Crawl scope: Exact same-host only. Third-party domains and subdomains are recorded passively but never crawled.
- Static analysis only: Pure lexical parsing (`tdewolff/parse/v2/js`). No JavaScript execution or DOM runtime execution.

---

## 4. Subprocess Network Boundaries & Target Authorization

### Subprocess Network Model
Native Go checks are governed by `netguard.SafeDialer`. However, external discovery adapters (`httpx`, `katana`, `nuclei`) execute as standalone OS subprocesses with their own networking libraries.
- In production cloud environments, container network egress filtering (iptables / nftables dropping RFC 1918 and `169.254.0.0/16` metadata) and cloud provider IMDSv2 hop-limit=1 are mandatory.
- See [docs/deployment-security.md](deployment-security.md) for full deployment firewall and network namespace specifications.

### Target Authorization & Owned Mode
- Specifying `--mode owned` on the CLI represents an authorization declaration by the caller. Standalone OSS CLI cannot independently prove domain ownership.
- ExposureGuard Cloud and SaaS orchestrators **MUST** complete authoritative proof-of-ownership (such as DNS TXT record challenge or HTTP token validation) before dispatching any scan with `mode=owned` to an engine worker.
