# Subfinder Integration

## 1. Overview
* **Integration ID**: `subfinder`
* **Binary**: `subfinder`
* **Capability**: `asset-discovery`
* **Risk Class**: `passive`
* **Supported Modes**: `public`, `owned`
* **Tested Version**: `2.16.0` (Minimum: `2.6.0`)
* **Upstream**: [projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder)

---

## 2. Security Review & Network Activity

* **Network Activity**: Queries public third-party OSINT databases, certificate transparency logs (e.g. crt.sh), and passive archive services. It does **not** send active packets or DNS queries directly to the target infrastructure.
* **Scan Modes**: Permitted in both `public` and `owned` modes because discovery is purely passive outside-in intelligence.
* **Data Received**: Target domain (e.g. `example.com`), rate-limit constraints. No client credentials or private infrastructure tokens are passed.
* **Data Emitted**: Candidate hostnames discovered in public logs.
* **ExposureGuard Restrictions**:
  * Automatic update checks disabled (`-disable-update-check`).
  * Silent execution mode (`-silent`).
  * Structured JSON Lines output (`-json`).
  * Rate-limited to prevent OSINT source throttling.
  * Emitted hostnames are marked strictly as `candidate` assets until validated by reachability probes.

---

## 3. Data Normalization

### Emitted Asset
```json
{
  "kind": "hostname",
  "value": "api.example.com",
  "source": "subfinder",
  "discovered_via": "crtsh",
  "attributes": {
    "candidate": "true",
    "source": "crtsh"
  }
}
```

### Emitted Observation
```json
{
  "kind": "subdomain.passive_discovery",
  "subject": "api.example.com",
  "data": {
    "domain": "example.com",
    "subdomain": "api.example.com",
    "source": "crtsh",
    "passive": true
  }
}
```
