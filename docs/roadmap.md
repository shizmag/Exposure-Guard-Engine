# ExposureGuard Engine — Post-v0.1.0 Roadmap

This document captures features, integrations, and architectural ideas evaluated during the v0.1.0 release audit and intentionally deferred to maintain a tight, reliable, and auditable feature freeze.

---

## 1. Scanner Integrations (Deferred)

The following external tools were evaluated and deferred to preserve minimal attack surface, low operational noise, and clear boundary contracts:

- **`dnsx`**: Fast multi-purpose DNS toolkit. Evaluated for wildcards and brute-forcing; deferred because native Go DNS resolver with NetGuard guarantees strict SSRF protection and deterministic query budgets.
- **`naabu`**: Port scanner. Deferred because port scanning introduces noisy active probes and requires elevated raw socket capabilities in containers, violating non-root and low-noise principles.
- **`gitleaks`**: Git repository secret scanner. Deferred because ExposureGuard focuses on public web surface and client-side web assets, not repository history.
- **`waybackurls` / `gau`**: Historical URL archives. Deferred due to external third-party API dependencies, stale URLs leading to false positives, and non-deterministic crawl sets.

---

## 2. Advanced Capabilities (Deferred)

- **Headless Browser Crawling**: Chromium/Playwright integration for SPA DOM execution. Deferred due to massive container image size (+300MB), CPU/memory footprint, and nondeterministic async DOM rendering.
- **Dynamic Plugin Runtime / WASM**: Dynamic check loading via WASM or external plugins. Deferred to keep v0.1.0 single-binary and deterministic.
- **Background Daemon / gRPC API**: Evaluated for worker orchestration; deferred because CLI-invoked, stdin/stdout JSONL process execution provides universal language interoperability, clean memory reclamation, and standard container lifecycle management.
- **Remote Control Plane**: Cloud coordination remains in the ExposureGuard Cloud layer, keeping the engine a clean, decoupled execution worker.
- **Snapshot Schema Migrations**: Snapshot v1→v2 comparison is intentionally a no-change baseline because historical v1 items have no complete provenance. No destructive historical-data migration is provided. Any future conversion tool must preserve history and prove provenance or require an explicit reviewed rebaseline; see `snapshot-v2.md`.
