# ExposureGuard Engine — Security Checks Catalog

This catalog documents the security check modules and finding rules natively supported in ExposureGuard Engine v0.1.0.

You can inspect this list directly from the command line:
```bash
exposureguard checks list
```

---

## Native Finding Rules

| Rule ID | Module | Severity | Confidence | Title | Description | Remediation |
| :--- | :---: | :---: | :---: | :--- | :--- | :--- |
| `cookie.missing_secure` | `http` | `low` | `high` | Cookie Missing Secure Flag | A cookie set over HTTPS lacks the 'Secure' attribute, permitting transmission over unencrypted HTTP. | Set the Secure flag on all cookies set by HTTPS endpoints. |
| `frontend.credential_exposure` | `javascript` | `high` | `medium` | Hardcoded Credential or API Secret in Frontend | Client-side JavaScript assets contain recognizable API keys, cloud tokens, or private secrets. | Revoke the exposed key immediately and migrate secret-dependent operations to backend APIs. |
| `frontend.public_source_map` | `javascript` | `medium` | `high` | Public JavaScript Source Map Detected | Production frontend references a publicly accessible .map file exposing unminified source code. | Disable source map emission in production build pipelines or block public HTTP access to .map files. |
| `http.missing_hsts` | `http` | `low` | `high` | Missing Strict-Transport-Security Header | HTTPS website does not specify an HSTS header, allowing potential protocol downgrade attacks. | Configure the Strict-Transport-Security header (e.g. max-age=31536000; includeSubDomains). |
| `http.technology_disclosure` | `http` | `info` | `high` | Server / Technology Version Disclosure | HTTP response headers (Server or X-Powered-By) disclose backend software framework or version details. | Suppress or sanitize Server and X-Powered-By headers in web server configuration. |
| `tls.expired` | `tls` | `high` | `high` | TLS Certificate Expired | The leaf TLS certificate presented by the target server has passed its expiration date. | Renew and deploy an active, valid TLS certificate immediately. |
| `tls.expires_soon` | `tls` | `low` | `high` | TLS Certificate Expiring Soon | The TLS certificate is approaching its expiration date (within 30 days). | Renew and re-deploy the TLS certificate prior to expiration. |
| `tls.hostname_mismatch` | `tls` | `high` | `high` | TLS Hostname Mismatch | The target hostname is not covered by the Subject Alternative Names (SANs) in the server certificate. | Issue a certificate covering the exact target hostname or parent wildcard domain. |

---

## External Curated Checks (Nuclei Profile)

When running in `--mode owned` with the `deep` profile (or with `--integrations nuclei`), ExposureGuard executes a version-locked, curated defensive ruleset targeting high-impact misconfigurations:

- `nuclei.env-file-exposure`: Publicly accessible `.env` configuration file containing environment secrets.
- `nuclei.git-config-exposure`: Publicly accessible `.git/config` disclosing internal repository paths.
- `nuclei.ds-store-exposure`: Public `.DS_Store` file exposing directory structure.
- `nuclei.server-status-exposure`: Unrestricted Apache/Nginx status page.
- Curated CVE detection for high-severity known vulnerabilities without destructive payloads.

See `profiles/nuclei/v1/manifest.json` for the exact template list and checksums.
