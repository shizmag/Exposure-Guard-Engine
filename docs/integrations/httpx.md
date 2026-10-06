# httpx Integration

## 1. Overview
* **Integration ID**: `httpx`
* **Binary**: `httpx`
* **Capabilities**: `http-probe`, `asset-enrichment`
* **Risk Class**: `low-impact`
* **Supported Modes**: `owned`
* **Tested Version**: `1.12.0` (Minimum: `1.3.0`)
* **Upstream**: [projectdiscovery/httpx](https://github.com/projectdiscovery/httpx)

---

## 2. Security Review & Network Activity

* **Network Activity**: Dispatches HTTP and HTTPS GET/HEAD probe requests to verify port status, status codes, server headers, and redirect chains.
* **Scan Modes**: Restricted strictly to `owned` mode. Public unverified targets are denied by default (`ErrPolicyDenied`) to protect external infrastructure from uncoordinated probing.
* **Data Received**: Target URLs and pre-validated candidate hosts belonging strictly to the target's authorized domain scope. Private IP spaces and SSRF targets are rejected before handoff.
* **Data Emitted**: HTTP status codes, page titles, server banners, technology detection tags, and canonical URLs.
* **ExposureGuard Restrictions**:
  * Response body capture is omitted (`-ob`).
  * Automatic update checks disabled (`-disable-update-check`).
  * Concurrency bounded by `Limits.MaxConcurrency`.
  * Rate-limited via `-rl` based on `Limits.RequestsPerSecondPerHost`.
  * Timeout strictly enforced per request (`Limits.RequestTimeoutSeconds`) and overall subprocess context.

---

## 3. Deduplication with Native HTTP Checks

Both native HTTP root checks and httpx probes generate canonical `model.AssetKindURL` assets:
* Identity: `ComputeAssetID("url", "https://api.example.com/")`
* If both native checks and httpx detect the same endpoint, `snapshot.Build` merges them into one canonical Asset with combined source attributes (`source: native,httpx`).
* Observations are tagged with `source: httpx` to preserve exact provenance.

---

## 4. Data Normalization

### Emitted Asset
```json
{
  "kind": "url",
  "value": "https://api.example.com",
  "url": "https://api.example.com",
  "source": "httpx",
  "discovered_via": "probe",
  "attributes": {
    "status_code": "200",
    "server": "envoy",
    "technologies": "Envoy,REST"
  }
}
```

### Emitted Observation
```json
{
  "kind": "http.service_probe",
  "subject": "https://api.example.com",
  "data": {
    "url": "https://api.example.com",
    "status_code": 200,
    "webserver": "envoy",
    "technologies": ["Envoy", "REST"],
    "source": "httpx"
  }
}
```
