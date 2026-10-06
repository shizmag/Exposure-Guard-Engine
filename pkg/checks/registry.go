package checks

import (
	"sort"
	"strings"

	"github.com/exposureguard/exposureguard/pkg/model"
)

// RuleMetadata provides documentation and taxonomy for an actionable finding rule.
type RuleMetadata struct {
	ID          string           `json:"id"`
	Module      string           `json:"module"`
	Severity    model.Severity   `json:"severity"`
	Confidence  model.Confidence `json:"confidence"`
	Title       string           `json:"title"`
	Description string           `json:"description"`
	Remediation string           `json:"remediation"`
}

var nativeRules = []RuleMetadata{
	{
		ID:          "tls.expired",
		Module:      "tls",
		Severity:    model.SeverityHigh,
		Confidence:  model.ConfidenceHigh,
		Title:       "TLS Certificate Expired",
		Description: "The leaf TLS certificate presented by the target server has passed its expiration date.",
		Remediation: "Renew and deploy an active, valid TLS certificate immediately.",
	},
	{
		ID:          "tls.expires_soon",
		Module:      "tls",
		Severity:    model.SeverityLow,
		Confidence:  model.ConfidenceHigh,
		Title:       "TLS Certificate Expiring Soon",
		Description: "The TLS certificate is approaching its expiration date (within 30 days).",
		Remediation: "Renew and re-deploy the TLS certificate prior to expiration.",
	},
	{
		ID:          "tls.hostname_mismatch",
		Module:      "tls",
		Severity:    model.SeverityHigh,
		Confidence:  model.ConfidenceHigh,
		Title:       "TLS Hostname Mismatch",
		Description: "The target hostname is not covered by the Subject Alternative Names (SANs) in the server certificate.",
		Remediation: "Issue a certificate covering the exact target hostname or parent wildcard domain.",
	},
	{
		ID:          "http.missing_hsts",
		Module:      "http",
		Severity:    model.SeverityLow,
		Confidence:  model.ConfidenceHigh,
		Title:       "Missing Strict-Transport-Security Header",
		Description: "HTTPS website does not specify an HSTS header, allowing potential protocol downgrade attacks.",
		Remediation: "Configure the Strict-Transport-Security header (e.g. max-age=31536000; includeSubDomains).",
	},
	{
		ID:          "http.technology_disclosure",
		Module:      "http",
		Severity:    model.SeverityInfo,
		Confidence:  model.ConfidenceHigh,
		Title:       "Server / Technology Version Disclosure",
		Description: "HTTP response headers (Server or X-Powered-By) disclose backend software framework or version details.",
		Remediation: "Suppress or sanitize Server and X-Powered-By headers in web server configuration.",
	},
	{
		ID:          "cookie.missing_secure",
		Module:      "http",
		Severity:    model.SeverityLow,
		Confidence:  model.ConfidenceHigh,
		Title:       "Cookie Missing Secure Flag",
		Description: "A cookie set over HTTPS lacks the 'Secure' attribute, permitting transmission over unencrypted HTTP.",
		Remediation: "Set the Secure flag on all cookies set by HTTPS endpoints.",
	},
	{
		ID:          "frontend.public_source_map",
		Module:      "javascript",
		Severity:    model.SeverityMedium,
		Confidence:  model.ConfidenceHigh,
		Title:       "Public JavaScript Source Map Detected",
		Description: "Production frontend references a publicly accessible .map file exposing unminified source code.",
		Remediation: "Disable source map emission in production build pipelines or block public HTTP access to .map files.",
	},
	{
		ID:          "frontend.credential_exposure",
		Module:      "javascript",
		Severity:    model.SeverityHigh,
		Confidence:  model.ConfidenceMedium,
		Title:       "Hardcoded Credential or API Secret in Frontend",
		Description: "Client-side JavaScript assets contain recognizable API keys, cloud tokens, or private secrets.",
		Remediation: "Revoke the exposed key immediately and migrate secret-dependent operations to backend APIs.",
	},
}

// AllRules returns all registered native finding rules sorted deterministically by ID.
func AllRules() []RuleMetadata {
	cpy := make([]RuleMetadata, len(nativeRules))
	copy(cpy, nativeRules)
	sort.Slice(cpy, func(i, j int) bool {
		return cpy[i].ID < cpy[j].ID
	})
	return cpy
}

// GetRule retrieves rule metadata by ID.
func GetRule(id string) (RuleMetadata, bool) {
	norm := strings.ToLower(strings.TrimSpace(id))
	for _, r := range nativeRules {
		if strings.ToLower(r.ID) == norm {
			return r, true
		}
	}
	return RuleMetadata{}, false
}
