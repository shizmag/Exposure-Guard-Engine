package static

import (
	"bytes"
	"fmt"
	"regexp"
	"sort"

	"github.com/exposureguard/exposureguard/pkg/model"
	"github.com/exposureguard/exposureguard/pkg/redact"
	"github.com/exposureguard/exposureguard/pkg/snapshot"
)

type credentialRule struct {
	Provider string
	Type     string
	Severity model.Severity
	Regex    *regexp.Regexp
}

var credentialRules = []credentialRule{
	{
		Provider: "AWS",
		Type:     "AWS Access Key ID",
		Severity: model.SeverityHigh,
		Regex:    regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	},
	{
		Provider: "GitHub",
		Type:     "GitHub Personal Access Token",
		Severity: model.SeverityHigh,
		Regex:    regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}\b`),
	},
	{
		Provider: "GitHub",
		Type:     "GitHub Fine-Grained Token",
		Severity: model.SeverityHigh,
		Regex:    regexp.MustCompile(`\bgithub_pat_[0-9a-zA-Z_]{82}\b`),
	},
	{
		Provider: "Slack",
		Type:     "Slack Token",
		Severity: model.SeverityHigh,
		Regex:    regexp.MustCompile(`\bxox[baprs]-[0-9a-zA-Z-]{10,48}\b`),
	},
	{
		Provider: "Stripe",
		Type:     "Stripe API Key",
		Severity: model.SeverityHigh,
		Regex:    regexp.MustCompile(`\b(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,99}\b`),
	},
	{
		Provider: "Google",
		Type:     "Google API Key",
		Severity: model.SeverityMedium,
		Regex:    regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`),
	},
	{
		Provider: "JWT",
		Type:     "JSON Web Token",
		Severity: model.SeverityMedium,
		Regex:    regexp.MustCompile(`\beyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\b`),
	},
	{
		Provider: "Database",
		Type:     "Database Connection URL",
		Severity: model.SeverityHigh,
		Regex:    regexp.MustCompile(`\b(?:postgres|postgresql|mysql|mongodb|redis):\/\/[a-zA-Z0-9_\-]+:[^@\s\n'"]+@[a-zA-Z0-9_\-\.]+:[0-9]+\b`),
	},
}

// DetectCredentials scans raw JS bytes for curated high-confidence credentials.
// It IMMEDIATELY masks and fingerprints findings. Plaintext secrets are NEVER stored or returned.
func DetectCredentials(jsURL string, content []byte) []model.Finding {
	var findings []model.Finding
	seenFingerprints := make(map[string]bool)

	for _, rule := range credentialRules {
		indices := rule.Regex.FindAllIndex(content, -1)
		for _, idx := range indices {
			start, end := idx[0], idx[1]
			rawSecret := string(content[start:end])

			fp := redact.FingerprintSecret(rawSecret)
			if seenFingerprints[fp] {
				continue
			}
			seenFingerprints[fp] = true

			masked := redact.MaskSecret(rawSecret)
			line := bytes.Count(content[:start], []byte("\n")) + 1

			findingID := snapshot.ComputeFindingID("frontend.credential_exposure:"+rule.Provider, jsURL, fp)

			findings = append(findings, model.Finding{
				ID:          findingID,
				CheckID:     "frontend.javascript",
				RuleID:      "frontend.credential_exposure",
				Severity:    rule.Severity,
				Confidence:  model.ConfidenceHigh,
				Title:       fmt.Sprintf("%s Exposed in Public Frontend", rule.Type),
				Description: fmt.Sprintf("Publicly accessible JavaScript contains an exposed %s (%s).", rule.Type, rule.Provider),
				Asset:       jsURL,
				Evidence: model.Evidence{
					Fingerprint:   fp,
					MaskedPreview: masked,
					Offset:        start,
					Line:          line,
					Details: map[string]any{
						"provider": rule.Provider,
						"type":     rule.Type,
					},
				},
				Remediation: fmt.Sprintf("Revoke this %s immediately, audit access logs, and move secrets to secure backend storage.", rule.Provider),
			})
		}
	}

	// Sort findings deterministically
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].ID < findings[j].ID
	})

	return findings
}
