# ExposureGuard Engine — Release Readiness Audit (v0.1.0)

**Date**: March 2025  
**Target Release**: v0.1.0-rc1  
**Scope**: Factual audit of engine, CLI, protocols, models, security boundaries, integrations, packaging, and tests against the v0.1.0 release contract.

---

## 1. Status Legend

- **`ready`**: Fully implemented, tested, and aligns with v0.1.0 contract.
- **`needs polish`**: Core implementation exists; requires standardization, schema formalization, or UX cleanup.
- **`needs test`**: Feature exists or is partially verified, but lacks deterministic regression or stress test suites.
- **`needs fix`**: Defect, unsafe assumption, or contract violation that must be resolved prior to v0.1.0 release.
- **`out of scope`**: Explicitly deferred to post-v0.1.0 roadmap (no new scanners, no daemons, no gRPC/WASM).

---

## 2. Area-by-Area Readiness Matrix

| Area | Status | Factual Assessment & Gaps | Target Action for v0.1.0 |
| :--- | :---: | :--- | :--- |
| **Feature Surface** | `ready` | Native checks (DNS, TLS, HTTP, Crawl, JS, Source Maps) + 4 integrations (Subfinder, httpx, Katana, Nuclei). Feature freeze declared. | Freeze feature set. Document deferred ideas in `docs/roadmap.md`. |
| **Scan Profiles** | `needs fix` | Legacy `"website"` profile still default in config/CLI/engine. Profile definitions are scattered across `if` statements instead of centralized structs. | Centralize `quick`, `standard`, `deep` in a formal profile registry. Add `profiles list` and `profiles show`. |
| **Scan Plan Preview** | `needs fix` | No dry-run inspection capability exists. Users and automation cannot preview planned modules without initiating network traffic. | Add `--plan` flag to `exposureguard scan` supporting both human and `--format json` output. |
| **CLI & UX** | `needs polish` | Commands exist (`scan`, `diff`, `doctor`, `integrations`, `version`), but lack `--quiet` mode, unified duration/flag naming, and clean human summary formatting. | Add `--quiet`, unify log levels (`--log-level` writing strictly to stderr), refine human layout. |
| **Config Explainability**| `needs polish` | `internal/config` loads defaults and files, but has no command to inspect effective configuration without credentials. | Add `exposureguard config show` command with secret redaction. |
| **Native Checks & Registry** | `needs polish` | 8 native check/finding rules exist (`tls.*`, `http.*`, `cookie.*`, `frontend.*`), but no registry or listing command exists. | Introduce Checks Registry, add `exposureguard checks list`, generate `docs/checks.md`. |
| **Findings Philosophy** | `needs polish` | Observations vs Findings distinction is mostly upheld, but lacks formal rationale documentation and FP risk definitions. | Publish `docs/finding-philosophy.md` with criteria for severity and confidence. |
| **Snapshot Schema & Hash**| `needs polish` | `snapshot.Build` creates deterministic structs, but lacks formal canonical fingerprint (`SHA-256`), standalone hashing command, and formal docs. | Create `docs/snapshot-v1.md`, add canonical snapshot fingerprint calculation, add `exposureguard snapshot hash`. |
| **Diff & Noise Suppression** | `needs polish` | `diff.Compare` handles asset/finding/observation diffs, but needs explicit noise suppression for dynamic headers (Date, ETag, nonces) and DNS reordering. | Build noise test suite, suppress non-security volatile headers, ensure stable change IDs. |
| **JSON Protocol v1** | `needs polish` | JSON output exists, but `protocol_version=1` is not formalized as a public contract with JSON schemas. | Write `docs/protocol-v1.md`, provide JSON Schemas for `ScanRequest`, `Event`, `ScanResult`, `Snapshot`. |
| **JSONL Protocol & Events** | `needs test` | Event encoder emits JSONL to stdout, but lacks stress testing for goroutine concurrency, sequence monotonicity, and terminal event guarantees. | Add `-race` concurrency stress test verifying monotonic sequence numbers and terminal event ordering. |
| **Process Lifecycle** | `needs test` | Process groups and timeouts exist in `pkg/integration/process.go`, but lack soak testing for SIGINT/SIGTERM cancellation and orphan cleanup. | Add automated Unix cancellation soak test verifying zero leaked processes and zero leaked `/tmp` directories. |
| **Resource Budgets** | `needs test` | Config limits (`MaxPages`, `MaxAssets`, `MaxResponseBytes`, etc.) clamp in model, but need runtime enforcement execution tests. | Add execution tests with synthetic high-volume servers to prove limits halt crawlers/extractors. |
| **Secrets & URL Redaction** | `needs test` | Lexical secret detector and basic redaction exist, but lack a centralized test corpus for fake cloud/API tokens and URL credentials. | Create `testdata/secrets/` regression suite verifying zero leakage in output, JSON, JSONL, and logs. |
| **NetGuard & Private Networks** | `needs fix` | `--allow-private` allows bypass for local development, but doesn't explicitly warn in human mode or flag `unsafe_private_network_access` in metadata. | Harden `--allow-private` with visible metadata warning, block AWS/GCP metadata even when enabled, document production egress. |
| **Egress Reference Configs**| `needs polish` | Docs state Docker does not isolate network stack of subprocesses, but no ready-to-use iptables/nftables configs are provided. | Add reference configurations in `deploy/security/` (`nftables.example.nft`, `iptables.example.sh`). |
| **Container Hardening** | `needs polish` | `Dockerfile` builds, but needs non-root verification, read-only rootfs compatibility (`--read-only`), and pinned digest base images. | Update `Dockerfile` to pin base images, verify non-root user, document read-only container flags. |
| **Supply Chain & Notices**| `needs polish` | Toolchain locks 4 pinned binaries + templates, but `THIRD_PARTY_NOTICES.md` with upstream licenses does not exist. | Create `THIRD_PARTY_NOTICES.md` auditing licenses for Subfinder, httpx, Katana, Nuclei, and dependencies. |
| **Doctor Command** | `needs polish` | Doctor checks integrations, but does not use clear `PASS` / `WARN` / `FAIL` severity tiers, nor does it check snapshot schema readiness. | Polish `doctor` output, support machine-readable `--format json` with severity tiers. |
| **Performance Benchmarks** | `needs test` | No Go benchmarks exist for target normalization, HTML extraction, snapshot hashing, diffing, or JSONL encoding. | Implement `benchmarks/` suite to capture baseline numbers and prevent CPU/alloc regressions. |
| **Release Packaging & SBOM** | `needs polish` | `.goreleaser.yaml` exists; needs verification for multi-arch archives, SHA256SUMS, and automated SBOM generation. | Polish GoReleaser config and add `make release-smoke` target. |
| **Installer Script** | `needs polish` | `install.sh` installs binaries, but needs test for `--check` flag, clean error messages, and failure mode tests. | Add installer test script verifying architecture handling and checksum verification. |
| **Documentation & Navigation** | `needs polish` | README is lengthy and does not showcase the "30-second diff" differentiator. Docs are unindexed without a central navigation hub. | Rewrite `README.md`, create `docs/README.md` navigation map, add PR and Issue templates. |
| **Cloud Integration Fixture** | `needs polish` | `docs/cloud-integration.md` explains protocol, but lacks canonical golden fixtures in `testdata/cloud/`. | Provide `testdata/cloud/` with canonical `scan-request.json`, `expected-events.jsonl`, `expected-result.json`. |
| **New Scanner Integrations** | `out of scope` | `dnsx`, `naabu`, `gitleaks`, `waybackurls`, headless browsers, offensive exploit modules. | Strictly deferred to post-v0.1.0 roadmap (`docs/roadmap.md`). |

---

## 3. Top Priority Engineering Items

1. **Scan Profiles & Plan Preview**: Centralize profile definitions (`quick`, `standard`, `deep`) and add `exposureguard scan --plan`.
2. **Protocol & Snapshot v1 Freeze**: Create JSON schemas, canonical snapshot hash, and diff noise filters.
3. **Registry & Philosophy**: Implement `checks list` command, `docs/finding-philosophy.md`, and document checks.
4. **Security & Redaction**: Centralize secrets regression corpus, redact URL credentials, harden `--allow-private`.
5. **Execution Hardening**: Cancelation soak test, resource limit execution tests, doctor PASS/WARN/FAIL.
6. **Container & Supply Chain**: Egress firewall reference scripts, `THIRD_PARTY_NOTICES.md`, Docker read-only verification.
7. **Release DX**: README rewrite, release-smoke target, GoReleaser polish.
