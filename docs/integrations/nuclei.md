# Nuclei Integration

## 1. Overview
* **Integration ID**: `nuclei`
* **Binary**: `nuclei`
* **Capability**: `security-check`
* **Risk Class**: `active`
* **Supported Modes**: `owned`
* **Tested Version**: `3.11.1` (Minimum: `3.0.0`)
* **Templates Version**: `v10.5.0`
* **Curated Profile**: `v1.0-defensive`
* **Upstream**: [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei)

---

## 2. Versioned Curated Defensive Ruleset

Nuclei is strictly governed by ExposureGuard's defensive allowlist policy. **Uncontrolled execution with arbitrary community templates is strictly prohibited.**

Instead of relying solely on coarse CLI tags, ExposureGuard enforces an exact, versioned curated ruleset defined in:
* `profiles/nuclei/v1/manifest.json`
* `profiles/nuclei/v1/templates.txt`

### Exact Selected Template IDs
Every check must match an exact allowed template ID from the curated profile:
* `git-config`
* `env-file`
* `git-head`
* `ds-store`
* `backup-files`
* `docker-compose-exposure`
* `phpinfo-files`
* `security-txt`
* `robots-txt-disclosure`
* `sitemap-xml-disclosure`
* `svn-entries`
* `aws-credentials-exposure`
* `tls-version`
* `ssl-dns-names`
* `certificate-expiry`

The adapter executes Nuclei with `-id <curated-ids>` so upstream template updates never change effective checks unexpectedly.

### Safety Invariants
* **Forbidden Features**: `headless`, `code`, `javascript`, `interactsh` / `oast`, raw `tcp`, `websocket`.
* **Allowed Protocols**: `http`, `ssl`, `dns` only.
* **Deny-List Tags**: `fuzz`, `dos`, `bruteforce`, `intrusive`, `rce`, `code-execution`, `headless`, `active`, `sqli`, `xss`, `lfi`, `ssrf`, `cve`, `destructive`.
* **Out-of-band testing**: strictly disabled via `-ni` (`-no-interactsh`).

---

## 3. Template Pinning & Reproducibility

* Scans **never** perform automatic template updates during runtime.
* Templates are pinned to official release `v10.5.0` in `tools.lock.json`.
* Scanning provenance records:
  * `ruleset_version`: `v1.0-defensive`
  * `templates_version`: `10.5.0`
  * `source_template_id`: exact matched template
  * `source_severity`: upstream severity string

---

## 4. Normalization and Provenance

### Severity Preservation
Both upstream and normalized severities are preserved in observations and finding evidence details:
* Upstream `critical` -> `model.SeverityCritical` (preserved, not downgraded)
* Upstream `high` -> `model.SeverityHigh`
* Upstream `medium` -> `model.SeverityMedium`
* Upstream `low` -> `model.SeverityLow`
* Upstream `info` -> `model.SeverityInfo` (emitted as observation only)

Every finding contains `source_severity` and `normalized_severity` separately in its evidence details.

### Provenance Object
Every observation records explicit provenance to track origin:
```json
{
  "provenance": {
    "type": "integration",
    "id": "nuclei",
    "version": "3.11.1",
    "source_template_id": "git-config",
    "source_template_version": "10.5.0",
    "ruleset_version": "v1.0-defensive",
    "source_severity": "medium",
    "normalized_severity": "medium"
  }
}
```

### Clean UX Representation
Findings prioritize actionable defensive issue descriptions over vendor names:
* Internal rule: `nuclei.git-config`
* Human title: `Git Config File Exposure` (vendor prefixes stripped)
* Remediation: `Restrict public access or remove the exposed file/configuration.`
