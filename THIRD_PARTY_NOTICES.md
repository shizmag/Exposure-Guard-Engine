# Third-Party Notices & Licenses

ExposureGuard Engine integrates or redistributes third-party software, libraries, and security rule definitions. This document details upstream origins, pinned versions, and applicable open-source licenses.

---

## 1. External Discovery & Security Tools

The ExposureGuard toolchain installer (`install.sh`) and container images distribute pre-compiled release binaries under their respective open-source licenses:

### Subfinder
- **Project**: [projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder)
- **Version Pinned**: `v2.16.0`
- **License**: MIT License
- **Notice**: Copyright (c) ProjectDiscovery, Inc.

### httpx
- **Project**: [projectdiscovery/httpx](https://github.com/projectdiscovery/httpx)
- **Version Pinned**: `v1.12.0`
- **License**: MIT License
- **Notice**: Copyright (c) ProjectDiscovery, Inc.

### Katana
- **Project**: [projectdiscovery/katana](https://github.com/projectdiscovery/katana)
- **Version Pinned**: `v1.8.0`
- **License**: MIT License
- **Notice**: Copyright (c) ProjectDiscovery, Inc.

### Nuclei & Curated Ruleset
- **Project**: [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei)
- **Version Pinned**: `v3.8.0`
- **License**: MIT License
- **Notice**: Copyright (c) ProjectDiscovery, Inc.
- **Ruleset**: [projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) (Curated subset licensed under MIT).

---

## 2. Direct Go Dependencies

| Package | Version | License | Upstream Repository |
| :--- | :---: | :---: | :--- |
| `github.com/spf13/cobra` | `v1.8.1` | Apache-2.0 | [spf13/cobra](https://github.com/spf13/cobra) |
| `github.com/spf13/pflag` | `v1.0.5` | BSD-3-Clause | [spf13/pflag](https://github.com/spf13/pflag) |
| `github.com/knadh/koanf/v2` | `v2.1.2` | MIT | [knadh/koanf](https://github.com/knadh/koanf) |
| `github.com/stretchr/testify` | `v1.10.0` | MIT | [stretchr/testify](https://github.com/stretchr/testify) |
| `golang.org/x/net` | `v0.33.0` | BSD-3-Clause | [golang/net](https://go.googlesource.com/net) |
| `golang.org/x/sync` | `v0.10.0` | BSD-3-Clause | [golang/sync](https://go.googlesource.com/sync) |
| `golang.org/x/time` | `v0.8.0` | BSD-3-Clause | [golang/time](https://go.googlesource.com/time) |
| `gopkg.in/yaml.v3` | `v3.0.1` | Apache-2.0 / MIT | [go-yaml/yaml](https://github.com/go-yaml/yaml) |

All direct and transitive dependencies are compatible with ExposureGuard's project licensing and permissive open-source redistribution.
