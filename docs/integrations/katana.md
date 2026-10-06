# Katana Integration

## 1. Overview
* **Integration ID**: `katana`
* **Binary**: `katana`
* **Capabilities**: `crawler`, `endpoint-discovery`
* **Risk Class**: `active`
* **Supported Modes**: `owned`
* **Tested Version**: `1.8.0` (Minimum: `1.0.0`)
* **Upstream**: [projectdiscovery/katana](https://github.com/projectdiscovery/katana)

---

## 2. Security Review & Scope Controls

* **Network Activity**: Recursively fetches web pages, follows hyperlinks, extracts API routes, and catalogs static JavaScript assets.
* **Scan Modes**: Restricted exclusively to `owned` mode under the `deep` scanning profile.
* **Non-Headless Policy**: Runs strictly in standard HTTP crawler mode. Automatic browser automation (headless Chrome) and form submission (`-aff`) are disabled to eliminate the risk of state-modifying actions.
* **Scope Controls**:
  * Scoped exclusively to the target domain via `-fs dn`.
  * Out-of-scope third-party URLs encountered during crawls are classified as `external_reference` assets and are **never** crawled recursively.
  * Crawl depth bounded by `Limits.MaxDepth` (`-d`).
  * Crawl duration bounded by `Limits.TotalTimeoutSeconds` (`-ct`).
  * Request rates bounded by `Limits.RequestsPerSecondPerHost` (`-rl`).
* **Feed-Forward to Native JS Inspection**: Any `.js` files discovered during the Katana crawl are automatically routed to ExposureGuard's native lexical JS analyzer and source map inspector.

---

## 3. Data Normalization

Katana records are categorized into canonical asset kinds:
* `.js` or `application/javascript` -> `model.AssetKindJavaScript`
* Routes matching `/api/`, queries, or `.json` -> `model.AssetKindEndpoint`
* External third-party domains -> `model.AssetKindExternal`
* Other pages -> `model.AssetKindURL`

### Emitted Asset
```json
{
  "kind": "endpoint_candidate",
  "value": "https://example.com/api/v1/auth",
  "url": "https://example.com/api/v1/auth",
  "source": "katana",
  "discovered_via": "https://example.com/login",
  "attributes": {
    "method": "GET",
    "status_code": "200"
  }
}
```

### Emitted Observation
```json
{
  "kind": "crawler.endpoint_discovered",
  "subject": "https://example.com/api/v1/auth",
  "data": {
    "endpoint": "https://example.com/api/v1/auth",
    "source": "https://example.com/login",
    "method": "GET",
    "status_code": 200,
    "crawler": "katana"
  }
}
```
