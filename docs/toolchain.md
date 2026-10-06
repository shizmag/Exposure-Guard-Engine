# ExposureGuard Toolchain & Dependency Management

## 1. Reproducibility & Version Pinning

ExposureGuard enforces deterministic execution across local workstations, CI/CD pipelines, and containerized deployments.

**No tool or template is ever downloaded as `@latest` or `:latest`.**

Every external binary and template bundle is cryptographically pinned in `tools.lock.json`.

---

## 2. Lockfile Schema (`tools.lock.json`)

`tools.lock.json` serves as the single source of truth across all platforms:

```json
{
  "tools": {
    "subfinder": {
      "version": "2.16.0",
      "binary": "subfinder",
      "checksums": {
        "darwin_arm64": { "archive": "...", "sha256": "..." },
        "darwin_amd64": { "archive": "...", "sha256": "..." },
        "linux_amd64":  { "archive": "...", "sha256": "..." },
        "linux_arm64":  { "archive": "...", "sha256": "..." }
      }
    }
  }
}
```

Current pinned baseline:
* **Subfinder**: `2.16.0`
* **httpx**: `1.12.0`
* **Katana**: `1.8.0`
* **Nuclei**: `3.11.1`
* **Nuclei Templates**: `10.5.0`

---

## 3. Host System Hierarchy

ExposureGuard isolates third-party binaries to avoid polluting system folders:

| Component | Default Path | Environment Override |
| :--- | :--- | :--- |
| **Root Home** | `$HOME/.local/share/exposureguard` | `EXPOSUREGUARD_HOME` |
| **Binaries** | `$EXPOSUREGUARD_HOME/bin` | `PATH` |
| **Tool Data** | `$EXPOSUREGUARD_HOME/tools` | - |
| **Nuclei Templates** | `$EXPOSUREGUARD_HOME/tools/nuclei/templates` | `EXPOSUREGUARD_NUCLEI_TEMPLATES` |
| **Temp Execution** | `/tmp/exposureguard` | `TMPDIR` |

### Binary Discovery Order
When invoking a tool, the `Runner` searches:
1. Explicit tool override environment variable (e.g. `EXPOSUREGUARD_SUBFINDER_PATH`)
2. `$EXPOSUREGUARD_HOME/bin/<binary>`
3. Host system `PATH` via standard lookup

---

## 4. Local Installation (`install.sh`)

The root `install.sh` script is idempotent, POSIX-friendly, and operates without `sudo`:

```bash
# Default: install ExposureGuard and all pinned dependencies
./install.sh

# Install engine binary only
./install.sh --engine-only

# Verify environment readiness without modifying files
./install.sh --check

# Custom prefix directory
./install.sh --prefix /opt/security/exposureguard
```

During installation:
1. Target OS (`darwin`, `linux`) and architecture (`amd64`, `arm64`) are detected.
2. ExposureGuard engine is compiled via `go build`.
3. Pinned tool archives are fetched over HTTPS from official release assets.
4. Cryptographic SHA-256 hashes are verified against `tools.lock.json`. If a mismatch is detected, execution aborts immediately.
5. Binaries and templates are unpacked to their respective locations with executable permissions (`0755`).
6. `exposureguard doctor` is executed to verify runtime readiness.

---

## 5. Container Packaging (`Dockerfile`)

The container build uses a multi-stage process:
* **`builder`**: Compiles `exposureguard` statically with `CGO_ENABLED=0`.
* **`tool-fetcher`**: Downloads and cryptographically verifies Linux release archives based on `TARGETARCH`.
* **`runtime`**: Minimal Alpine container running as non-root user `10001:10001` with certificates, templates, and all four discovery tools pre-configured in `/usr/local/bin`.

Parity between local and Docker execution ensures that scans yield bitwise-identical snapshot structures and diff calculations.
