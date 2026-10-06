# Contributing Defensive Checks to ExposureGuard

ExposureGuard is designed to be easily extensible. Community contributors can implement and contribute new outside-in defensive checks within an evening.

---

## 1. Golden Rules for Checks

1. **Defensive Outside-In Only**:
   - Checks must only inspect publicly exposed state (GET/HEAD requests).
   - Never implement offensive probes, fuzzing payloads, exploit attempts, or form submissions.
2. **Never Construct Raw Network Clients**:
   - **DO NOT** use `http.Get()`, `net.Dial()`, or `net.LookupHost()`.
   - **ALWAYS** use `env.HTTP` and `env.DNS`. Network safety and SSRF protections must never be bypassed.
3. **No Secret Plaintext in Findings**:
   - Never put unmasked API keys or passwords into `Finding.Evidence`, `Description`, or `Title`.
   - Use `pkg/redact` to mask and fingerprint sensitive values.
4. **Conservative Findings**:
   - Absence of an optional header is an `Observation`, not automatically a high-severity vulnerability.
   - Findings must be actionable and provide clear remediation guidance.

---

## 2. Check Interface

Every check implements the `checks.Check` interface:

```go
package checks

import (
    "context"
    "github.com/exposureguard/exposureguard/pkg/model"
)

type Check interface {
    ID() string
    Name() string
    Stage() string
    Run(ctx context.Context, env *Environment, target model.Target) (Result, error)
}
```

---

## 3. Step-by-Step Implementation Guide

### Step 1: Create Package
Create a new directory under `pkg/checks/<your_check>/`.

### Step 2: Implement the Check
```go
package mycheck

import (
    "context"
    "fmt"
    "net/http"

    "github.com/exposureguard/exposureguard/pkg/checks"
    "github.com/exposureguard/exposureguard/pkg/model"
)

type Check struct{}

func NewCheck() *Check { return &Check{} }

func (c *Check) ID() string    { return "mycheck.sample" }
func (c *Check) Name() string  { return "Sample Check" }
func (c *Check) Stage() string { return "http" }

func (c *Check) Run(ctx context.Context, env *checks.Environment, target model.Target) (checks.Result, error) {
    var result checks.Result

    req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.URL, nil)
    if err != nil {
        return result, err
    }

    resp, err := env.HTTP.Do(req)
    if err != nil {
        return result, err
    }
    defer resp.Body.Close()

    // Record observation or finding...
    return result, nil
}
```

### Step 3: Add Unit Tests
Create `<your_check>_test.go` using `httptest.NewServer` or mock resolvers.
Always run:
```bash
make test
make ci
```
