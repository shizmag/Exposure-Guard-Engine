# Contributing to ExposureGuard

We welcome contributions from the community!

---

## Development Setup

1. **Prerequisites**:
   - Go 1.27.x (managed automatically via Go toolchain)
   - Git, Make, Docker (optional for container builds)

2. **Clone & Build**:
   ```bash
   git clone https://github.com/exposureguard/exposureguard.git
   cd exposureguard
   make build
   ./bin/exposureguard version
   ```

3. **Running Checks & Tests**:
   ```bash
   make test       # Run unit and integration tests
   make test-race  # Run race detector
   make vet        # Run static analyzer
   make ci         # Canonical CI suite
   ```

---

## Coding Standards

- **Pure Go**: No Cgo dependencies (`CGO_ENABLED=0`).
- **No Global Singletons**: Engine components must be thread-safe, accept `context.Context`, and be isolated.
- **Strict SSRF Safety**: Checks must never create unconstrained HTTP clients. Always use `env.HTTP` and `env.DNS`.
- **Reproducible Snapshots**: Ensure all slices and collections are sorted deterministically before snapshot serialization.

---

## Contributing a Check

See [docs/contributing-checks.md](docs/contributing-checks.md) for a guide on writing new defensive checks.
