package nuclei

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/exposureguard/exposureguard/pkg/integration"
	"github.com/exposureguard/exposureguard/pkg/model"
)

// Info holds metadata fields reported by Nuclei templates.
type Info struct {
	Name        string         `json:"name"`
	Author      any            `json:"author,omitempty"`
	Tags        any            `json:"tags,omitempty"`
	Description string         `json:"description,omitempty"`
	Reference   any            `json:"reference,omitempty"`
	Severity    string         `json:"severity"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// Record models a single match event from Nuclei JSONL output.
type Record struct {
	TemplateID       string   `json:"template-id"`
	Info             Info     `json:"info"`
	Type             string   `json:"type"`
	Host             string   `json:"host"`
	MatchedAt        string   `json:"matched-at"`
	ExtractedResults []string `json:"extracted-results,omitempty"`
	Timestamp        string   `json:"timestamp,omitempty"`
	MatcherName      string   `json:"matcher-name,omitempty"`
}

// NormalizeSeverity maps upstream Nuclei severity strings to ExposureGuard Severity levels.
func NormalizeSeverity(raw string) model.Severity {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical":
		return model.SeverityHigh // Normalize defensive ceiling to High unless verified exploitation
	case "high":
		return model.SeverityHigh
	case "medium":
		return model.SeverityMedium
	case "low":
		return model.SeverityLow
	default:
		return model.SeverityInfo
	}
}

// MapRecord converts a raw Nuclei finding into an Observation and actionable Finding.
func MapRecord(rec Record, emit integration.Emitter) {
	if rec.TemplateID == "" {
		return
	}

	subject := rec.MatchedAt
	if subject == "" {
		subject = rec.Host
	}
	if subject == "" {
		return
	}

	sev := NormalizeSeverity(rec.Info.Severity)
	conf := model.ConfidenceMedium
	if len(rec.ExtractedResults) > 0 {
		conf = model.ConfidenceHigh
	}

	// 1. Emit normalized Observation with full provenance
	obsData := map[string]any{
		"template_id":  rec.TemplateID,
		"matched_at":   rec.MatchedAt,
		"host":         rec.Host,
		"type":         rec.Type,
		"raw_severity": rec.Info.Severity,
		"extracted":    rec.ExtractedResults,
		"provenance": map[string]any{
			"type":    "integration",
			"id":      "nuclei",
			"version": TestedVersion,
			"rule":    rec.TemplateID,
			"profile": CuratedProfileVersion,
		},
	}

	obs := model.Observation{
		Kind:    "security.exposure_observation",
		Subject: subject,
		Data:    obsData,
	}
	emit.EmitObservation(obs)

	// 2. Derive actionable Finding if severity is above Info or actionable exposure
	if sev != model.SeverityInfo {
		title := rec.Info.Name
		if title == "" {
			title = "Public Exposure: " + rec.TemplateID
		}
		// Ensure title uses defensive domain language without vendor prefixes
		title = strings.TrimPrefix(title, "Nuclei ")

		desc := rec.Info.Description
		if desc == "" {
			desc = "Exposed resource or misconfiguration identified at " + subject
		}

		h := sha256.Sum256([]byte(rec.TemplateID + ":" + subject))
		fp := hex.EncodeToString(h[:])[:16]

		finding := model.Finding{
			CheckID:     "integration.nuclei",
			RuleID:      "nuclei." + rec.TemplateID,
			Severity:    sev,
			Confidence:  conf,
			Title:       title,
			Description: desc,
			Asset:       subject,
			Evidence: model.Evidence{
				URL:         subject,
				Fingerprint: fp,
			},
			Remediation: "Restrict public access or remove the exposed file/configuration.",
		}
		emit.EmitFinding(finding)
	}
}
