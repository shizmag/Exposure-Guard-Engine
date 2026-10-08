# ExposureGuard Engine — Documentation Index

Welcome to the technical documentation for ExposureGuard Engine (v0.1.0).

---

## Core Architecture & Contracts

- **[Architecture Overview](architecture.md)**: System design, execution pipelines, isolation model, and data flow.
- **[Protocol v1 Specification](protocol-v1.md)**: Stable single-scan execution contract, `ScanRequest`, JSONL events, and `ScanResult`.
- **[Batch Protocol v1](batch-protocol-v1.md)**: Bounded multi-target subprocess contract, multiplexed JSONL, limits and Cloud scheduling guidance.
- **[Snapshot v1 Specification](snapshot-v1.md)**: Normalized inventory model, stable identity calculation, canonical hashing, and diffing.
- **[Identity Algorithm v1](identity-v1.md)**: Frozen ID formulas and mandatory pre-v1 rebaseline/Cloud compatibility policy.
- **[Product Vision](product.md)**: Motivation, target user journey, and defensive external exposure monitoring principles.
- **[Release Readiness Audit](release-readiness-v0.1.md)**: Factual readiness audit and pre-release evaluation.
- **[Post-v0.1.0 Roadmap](roadmap.md)**: Features, deferred tools, and future architectural evolutions.

---

## Security & Deployment

- **[Security Model](security-model.md)**: Threat model, trust boundaries, safe defaults, and secret redaction.
- **[Deployment Security](deployment-security.md)**: Container hardening, non-root execution, read-only rootfs, and platform egress filtering.
- **[Reference Egress Firewalls](../deploy/security/iptables.example.sh)**: Ready-to-use iptables and nftables egress rules blocking cloud metadata and RFC1918 subnets.
- **[Third-Party Notices](../THIRD_PARTY_NOTICES.md)**: Upstream open-source licenses and attribution for toolchains and dependencies.

---

## Checks & Integrations

- **[Security Checks Catalog](checks.md)**: Registry of native security checks, finding rules, and remediations.
- **[Findings Philosophy](finding-philosophy.md)**: Observation vs. Finding guidelines, severity rationale, and false-positive minimization.
- **[Integrations Overview](integrations.md)**: External toolchain integration guide (Subfinder, httpx, Katana, Nuclei).
- **[Contributing Checks](contributing-checks.md)**: Step-by-step tutorial for implementing and registering new native check modules.
- **[Adding an Integration](adding-an-integration.md)**: Adapter contract tutorial for adding external discovery scanners.
- **[Toolchain Architecture](toolchain.md)**: Pinned versioning, checksum verification, and `tools.lock.json`.

---

## Cloud & Automation

- **[Cloud Integration Contract](cloud-integration.md)**: Standard subprocess worker invocation, stdin/stdout streaming, and Node/TypeScript integration guide.
