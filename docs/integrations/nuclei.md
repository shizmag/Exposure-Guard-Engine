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

## 2. Curated Defensive Policy

Nuclei is strictly governed by ExposureGuard's defensive allowlist policy. **Uncontrolled execution with all templates is strictly prohibited.**

### Allowed Tags
* `exposure`
* `misconfig`, `misconfiguration`
* `config`
* `token`, `artifact`
* `disclosure`, `dev`

### Excluded Tags (Explicit Deny-List)
* `fuzz`, `dos`, `bruteforce`, `brute-force`
* `intrusive`, `oast`, `interactsh`
* `rce`, `code-execution`
* `headless`, `active`
* `sqli`, `xss`, `lfi`, `ssrf`, `cve`

### Excluded Protocols
* `headless`, `tcp`, `code`, `workflow`, `websocket` (Allowed: `http`, `ssl`, `dns`)
* Out-of-band testing disabled via `-ni` (`-no-interactsh`).

---

## 3. Template Pinning & Reproducibility

* Scans **never** perform automatic template updates during runtime.
* Templates are pinned to official release `v10.5.0` and located in deterministic system paths:
  * Local host: `$EXPOSUREGUARD_HOME/tools/nuclei/templates/`
  * Docker container: `/opt/exposureguard/nuclei-templates/`
* Result metadata includes exact ruleset and profile version identifiers (`v1.0-defensive`).

---

## 4. Normalization and Provenance

### Severity Mapping
* Upstream `critical` -> normalized to `model.SeverityHigh` (defensive ceiling)
* Upstream `high` -> `model.SeverityHigh`
* Upstream `medium` -> `model.SeverityMedium`
* Upstream `low` -> `model.SeverityLow`
* Upstream `info` -> `model.SeverityInfo` (emitted as observation only, not actionable finding)

### Provenance Object
Every observation records explicit provenance to track origin:
```json
{
  "provenance": {
    "type": "integration",
    "id": "nuclei",
    "version": "3.11.1",
    "rule": "git-config",
    "profile": "v1.0-defensive"
  }
}
```

### Clean UX Representation
Findings prioritize actionable defensive issue descriptions over vendor names:
* Internal rule: `nuclei.git-config`
* Human title: `Git Config File Exposure` (vendor prefixes stripped)
* Remediation: `Restrict public access or remove the exposed file/configuration.`
