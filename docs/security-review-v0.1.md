# ExposureGuard Engine — Security Review (v0.1.0)

**Date**: March 2025  
**Review Target**: v0.1.0-rc1  
**Scope**: Factual assessment of threats, mitigations, remaining risks, and mandatory deployment requirements.

---

## Threat Matrix & Safeguards

### 1. Server-Side Request Forgery (SSRF) to Cloud Metadata & RFC 1918 (Native Engine)
- **Threat**: Attacker supplies targets or HTTP redirects pointing to `169.254.169.254` (cloud metadata), `127.0.0.1`, or internal VPC services (`10.0.0.0/8`).
- **Mitigation**: `pkg/netguard` SafeDialer intercepts all network connections at IP level, verifies candidate IPs, rejects private/loopback/link-local/metadata ranges, and dials IP literals directly to defeat DNS rebinding attacks.
- **Remaining Risk**: None for native Go checks (`dns`, `tls`, `http`, `crawl`, `javascript`).
- **Deployment Requirement**: None for native checks.

---

### 2. Subprocess Network Egress (External Tools)
- **Threat**: External tools (`subfinder`, `httpx`, `katana`, `nuclei`) execute as child OS processes and make network calls via their own network stacks, bypassing Go `netguard`.
- **Mitigation**: 
  - External tools are restricted to `--mode owned` only (except passive Subfinder in public mode).
  - Curated Nuclei profile locks templates to 15 non-destructive checks.
- **Remaining Risk**: If an untrusted caller runs `--mode owned` inside an un-firewalled VPC, external tools can reach RFC1918 hosts.
- **Deployment Requirement**: **MANDATORY**. Production worker environments (Docker, Kubernetes, VM) **MUST** apply platform-level egress firewall rules (e.g., `deploy/security/iptables.example.sh` or `deploy/security/nftables.example.nft`) blocking `169.254.169.254` and RFC 1918 ranges.

---

### 3. Credential Leakage in Telemetry & Outputs
- **Threat**: Discovered API keys, database connection strings, or URL credentials leak in plaintext into logs, JSONL events, Snapshots, or human reports.
- **Mitigation**: 
  - `pkg/redact` masks secret previews and calculates SHA-256 fingerprints. Plaintext is never stored in `Finding` or `Observation`.
  - `pkg/redact/url.go` strips user passwords and masks sensitive query parameters (`token`, `key`, `secret`, `password`) in discovered URLs.
  - End-to-end regression test (`test/e2e/secret_leak_test.go`) validates zero plaintext leakage.
- **Remaining Risk**: Novel esoteric token formats not matching curated regex patterns.
- **Deployment Requirement**: Treat raw scan outputs with standard operational confidentiality.

---

### 4. Temporary File Leftovers & Disk Exhaustion
- **Threat**: Repeated scans or unexpected timeouts leave artifacts in `/tmp/exposureguard/*`, causing container disk exhaustion.
- **Mitigation**:
  - `pkg/engine` registers defer cleanup for `/tmp/exposureguard/<scanID>`.
  - Each integration runs inside isolated ephemeral subdirectories deleted upon stage completion.
  - Tested via cancellation soak suite (`test/e2e/cancellation_soak_test.go`).
- **Remaining Risk**: Hard SIGKILL (`kill -9`) issued by external OS supervisor prevents defer execution.
- **Deployment Requirement**: Mount `/tmp` as a `tmpfs` in Docker with a size limit (e.g. `--tmpfs /tmp:rw,noexec,nosuid,size=64m`).

---

### 5. Development Escape Hatch (`--allow-private`)
- **Threat**: Developer or operator inadvertently runs with `--allow-private` in production, exposing internal infrastructure to scanning.
- **Mitigation**:
  - Cloud metadata (`169.254.169.254`) and metadata hostnames remain strictly forbidden even when `--allow-private` is active.
  - Human mode prints a loud, visible security warning banner.
  - JSON output explicitly includes `unsafe_private_network_access: true`.
- **Remaining Risk**: Intentional misuse by operator.
- **Deployment Requirement**: Cloud workers **MUST NOT** expose or enable `--allow-private`.

---

### 6. Subprocess Hanging or Zombie Processes
- **Threat**: An external tool deadlocks or hangs indefinitely on a slow connection.
- **Mitigation**:
  - Every external command runs in an isolated process group (`Setpgid: true` on Unix).
  - Context cancellation cascades SIGTERM to `-PID`, followed by SIGKILL after a 1-second grace period (`pkg/integration/process_unix.go`).
- **Remaining Risk**: None under standard POSIX process management.
- **Deployment Requirement**: None.
