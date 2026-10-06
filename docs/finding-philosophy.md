# ExposureGuard Engine — Findings Philosophy & Quality Standards

**Core Principle**:  
> **Observation can be noisy. Finding must be conservative.**

An **Observation** records objective telemetry about the external state of an asset (e.g., DNS records, HTTP status codes, TLS leaf certificates, JavaScript URLs). It carries no inherent risk judgment.

A **Finding** represents an actionable security exposure or operational misconfiguration that a reasonable security engineer or site owner would want to fix. ExposureGuard strictly penalizes noisy, unproven findings: if confidence is low or the condition is normal production behavior, it remains an Observation, not a Finding.

---

## 1. Severity Rationale

ExposureGuard classifies findings into five conservative tiers:

- **Critical**: Direct, unauthenticated compromise or active credential takeover with zero user interaction (e.g., live cloud secret with administrative privileges, unauthenticated remote command execution via curated nuclei profile).
- **High**: Severe security exposure with imminent risk (e.g., expired TLS certificate, hostname mismatch, hardcoded private API token in client bundle, `.env` file publicly accessible).
- **Medium**: Demonstrable security weakness or sensitive asset leak (e.g., unminified production source maps exposing proprietary algorithms/internal routes).
- **Low**: Security posture hygiene defect without immediate direct exploitation (e.g., missing `Strict-Transport-Security` header, cookies lacking `Secure` attribute, TLS expiring within 30 days).
- **Info**: Informational surface exposure (e.g., verbose `Server` or `X-Powered-By` technology banner).

---

## 2. Confidence Rationale

- **High**: Deterministically proven via cryptographic or strict syntactic verification (e.g., certificate validity date checks, mathematical SAN matching, strict HTTP header presence/absence).
- **Medium**: High-probability heuristic match with structural verification (e.g., high-entropy credential regex matching known provider token structures).
- **Low**: Tentative detection. *Rule of thumb: ExposureGuard v0.1.0 avoids emitting Low confidence findings to prevent alert fatigue.*

---

## 3. Native Finding Rules Audit

### 1. `tls.expired`
- **Why Finding**: An expired certificate causes browser security warnings, breaking user trust and encryption availability.
- **Severity**: `High`
- **Confidence**: `High` (direct date comparison against `crypto/x509` NotAfter).
- **Conditions**: `now.After(cert.NotAfter)`.
- **FP Risk**: Negligible (accurate system clock assumed).

### 2. `tls.expires_soon`
- **Why Finding**: Certificate renewal was likely forgotten or automated renewal failed.
- **Severity**: `Low` (Medium if < 7 days).
- **Confidence**: `High`.
- **Conditions**: `cert.NotAfter.Sub(now) < 30 * 24 * time.Hour`.
- **FP Risk**: Negligible.

### 3. `tls.hostname_mismatch`
- **Why Finding**: TLS handshake succeeds cryptographically, but the SAN does not match target hostname, causing browser warnings.
- **Severity**: `High`
- **Confidence**: `High`.
- **Conditions**: Standard Go `x509.Verify` hostname verification failure.
- **FP Risk**: Low (SNI correctly configured during dial).

### 4. `http.missing_hsts`
- **Why Finding**: Enables SSL stripping and unencrypted HTTP downgrade for visitors.
- **Severity**: `Low`
- **Confidence**: `High`.
- **Conditions**: Target scheme is HTTPS, response header lacks `Strict-Transport-Security`.
- **FP Risk**: Low. Excluded on plain HTTP targets.

### 5. `http.technology_disclosure`
- **Why Finding**: Unnecessary technology version disclosure assists adversaries in tailoring exploit payloads.
- **Severity**: `Info`
- **Confidence**: `High`.
- **Conditions**: `Server` or `X-Powered-By` header contains version numbers or framework names.
- **FP Risk**: Low.

### 6. `cookie.missing_secure`
- **Why Finding**: Sensitive session or identity cookies may be transmitted over cleartext HTTP if user clicks an `http://` link.
- **Severity**: `Low`
- **Confidence**: `High`.
- **Conditions**: Response received over HTTPS sets cookie without `; Secure`.
- **FP Risk**: Low.

### 7. `frontend.public_source_map`
- **Why Finding**: Exposes proprietary frontend source code, internal comments, staging endpoint paths, and developer notes directly to visitors.
- **Severity**: `Medium`
- **Confidence**: `High`.
- **Conditions**: Production `.js` file contains `//# sourceMappingURL=...` and referenced `.map` file returns HTTP 200 with valid v3 JSON mapping.
- **FP Risk**: Negligible (HTTP status and JSON schema validated before emitting finding).

### 8. `frontend.credential_exposure`
- **Why Finding**: Client-side bundles frequently leak cloud API keys (AWS, GitHub, Slack) that grant unintended access.
- **Severity**: `High`
- **Confidence**: `Medium`.
- **Conditions**: Strict prefix and character-set match against verified provider token formats (e.g. `AKIA[0-9A-Z]{16}`, `ghp_[0-9a-zA-Z]{36}`).
- **FP Risk**: Low. Generic random strings without provider-specific structure are filtered out. Evidence preview is always redacted.

---

## 4. Evidence Handling & Redaction

For every emitted Finding:
1. **Minimal Evidence**: The engine attaches only minimal necessary evidence (e.g., matching header key/value snippet, URL, or sanitized preview).
2. **Mandatory Redaction**: Any potential secret value is masked (e.g., `AKIA****************`). Plaintext secrets are strictly prohibited from appearing in findings, observations, or snapshots.
