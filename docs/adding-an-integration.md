# Adding an Integration to ExposureGuard

This guide provides step-by-step instructions for contributors adding a new external discovery or security tool adapter to ExposureGuard.

---

## 1. What is an Integration?

In ExposureGuard, external tools are **probe providers**, not domain models. An integration is a self-contained Go package that wraps an external command-line tool, runs it safely via the unified `Runner`, and normalizes its output into ExposureGuard's canonical data model:

```text
External CLI Tool (JSON/JSONL)
             │
             ▼
     Adapter.Parse()
             │
             ▼
   Canonical Normalization
(Asset / Observation / Finding)
             │
             ▼
      Snapshot & Diff
```

---

## 2. Integration Directory Layout

New integrations live in `integrations/<tool_id>/`:

```text
integrations/dnsx/
  adapter.go         # Implements integration.Adapter
  metadata.go        # Declarative metadata and capabilities
  mapping.go         # Converts raw JSON records into Asset/Observation/Finding
  parser.go          # Streams and decodes CLI output
  adapter_test.go    # Contract tests & fixture verification
  testdata/
    dnsx_result.jsonl # Sanitized fixture of real upstream output
```

See `integrations/example/adapter.go` for a minimal reference implementation.

---

## 3. Capabilities

Declare which capability your integration provides:

* `asset-discovery`: Passive subdomain or host discovery
* `http-probe`: Active reachability and port verification
* `asset-enrichment`: Web server and technology fingerprinting
* `crawler`: Recursive link extraction and page spidering
* `endpoint-discovery`: API routes and parameters
* `security-check`: Defensive exposure auditing

---

## 4. The Adapter Interface

Every integration must implement `integration.Adapter` from `pkg/integration`:

```go
type Adapter interface {
    ID() string
    Metadata() Metadata
    Detect(ctx context.Context, runner Runner) (Installation, error)
    Plan(ctx context.Context, request Request) (ExecutionPlan, error)
    Parse(ctx context.Context, input io.Reader, emit Emitter) error
}
```

* **`ID()`**: Unique lowercase identifier (e.g. `"dnsx"`).
* **`Metadata()`**: Returns `integration.Metadata`.
* **`Detect()`**: Probes binary presence (`runner.LookPath`) and extracts version (`runner.DetectVersion`).
* **`Plan()`**: Constructs command arguments, bounds, timeouts, and working directory. **Never call `os/exec` directly.**
* **`Parse()`**: Decodes CLI output (typically JSONL) and streams items via `emit.EmitAsset()`, `emit.EmitObservation()`, and `emit.EmitFinding()`.

---

## 5. Toolchain & Version Pinning

1. Determine the latest official stable release of the tool.
2. Add the tool to `tools.lock.json` with cryptographic SHA-256 hashes for all supported platforms:
   * `darwin_arm64`, `darwin_amd64`
   * `linux_amd64`, `linux_arm64`
3. Update `install.sh` and `Dockerfile` if the tool is part of the standard battery.

---

## 6. Safety & Mode Policies

* **Public scans (`public`)**: Only passive OSINT tools that do not dispatch direct packets to the target are permitted (`RiskClassPassive`).
* **Owned scans (`owned`)**: Active probing and security checking tools are restricted to verified targets (`RiskClassLowImpact` or `RiskClassActive`).
* If an unauthorized mode attempts to plan the adapter, return `integration.NewError(integration.ErrPolicyDenied, ...)`.

---

## 7. Contract Tests & Fixtures

Every adapter must satisfy the standard compliance test suite in `adapter_test.go`:

```go
package dnsx_test

import (
    "testing"
    "github.com/exposureguard/exposureguard/integrations/dnsx"
    "github.com/exposureguard/exposureguard/pkg/integration/integrationtest"
)

func TestDnsxContract(t *testing.T) {
    adapter := dnsx.NewAdapter()
    integrationtest.RunAdapterContract(t, adapter)
}
```

`RunAdapterContract` automatically asserts:
* Non-empty canonical ID and metadata
* Declared capabilities and supported scan modes
* Version detection and compatibility evaluation
* Robustness on malformed or empty output streams
* Absence of panics on unexpected JSON lines

In addition, test fixture parsing against sanitized sample files in `testdata/<tool>_result.jsonl`.

---

## 8. Registration

Register the adapter in an `init()` block within your adapter package:

```go
func init() {
    _ = integration.Register(NewAdapter())
}
```

And import it as a blank import in `cmd/exposureguard/main.go`:

```go
import _ "github.com/exposureguard/exposureguard/integrations/dnsx"
```

---

## 9. Pull Request Checklist

Before submitting a PR for a new integration:

- [ ] Adapter implements `integration.Adapter`
- [ ] No direct `os/exec` calls (uses `Runner`)
- [ ] Safe CLI flags applied (`-silent`, `-json`, disable automatic update checks)
- [ ] Resource bounds configured (`MaxStdoutBytes`, timeouts)
- [ ] Strict mode enforcement (`public` vs `owned`)
- [ ] Sanitized test fixture in `testdata/`
- [ ] Contract tests passing (`RunAdapterContract`)
- [ ] Version pinned in `tools.lock.json`
- [ ] Documentation added in `docs/integrations/<tool>.md`
- [ ] `make ci` passes with zero errors
