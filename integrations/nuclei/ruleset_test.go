package nuclei_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/exposureguard/exposureguard/integrations/nuclei"
	"github.com/exposureguard/exposureguard/pkg/integration"
	"github.com/exposureguard/exposureguard/pkg/model"
)

type rulesetManifest struct {
	RulesetVersion   string `json:"ruleset_version"`
	TemplatesVersion string `json:"templates_version"`
	SafetyCriteria   struct {
		AllowedProtocols    []string `json:"allowed_protocols"`
		DisallowedProtocols []string `json:"disallowed_protocols"`
		DisallowedFeatures  []string `json:"disallowed_features"`
		DisallowedTags      []string `json:"disallowed_tags"`
	} `json:"safety_criteria"`
	AllowedTemplates []struct {
		ID            string   `json:"id"`
		Path          string   `json:"path"`
		Protocol      string   `json:"protocol"`
		Severity      string   `json:"severity"`
		Tags          []string `json:"tags"`
		RequestsCount int      `json:"requests_count"`
	} `json:"allowed_templates"`
}

func TestCuratedRulesetSafetyCriteria(t *testing.T) {
	manifestPath := filepath.Join("..", "..", "profiles", "nuclei", "v1", "manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("failed to read %s: %v", manifestPath, err)
	}

	var manifest rulesetManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("failed to unmarshal manifest: %v", err)
	}

	if manifest.RulesetVersion != nuclei.CuratedProfileVersion {
		t.Errorf("manifest ruleset_version = %q; want %q", manifest.RulesetVersion, nuclei.CuratedProfileVersion)
	}
	if manifest.TemplatesVersion != nuclei.CuratedTemplatesVersion {
		t.Errorf("manifest templates_version = %q; want %q", manifest.TemplatesVersion, nuclei.CuratedTemplatesVersion)
	}

	templatesTxtPath := filepath.Join("..", "..", "profiles", "nuclei", "v1", "templates.txt")
	txtData, err := os.ReadFile(templatesTxtPath)
	if err != nil {
		t.Fatalf("failed to read %s: %v", templatesTxtPath, err)
	}
	txtLines := strings.Split(strings.TrimSpace(string(txtData)), "\n")
	var cleanedTxtIDs []string
	for _, l := range txtLines {
		trimmed := strings.TrimSpace(l)
		if trimmed != "" {
			cleanedTxtIDs = append(cleanedTxtIDs, trimmed)
		}
	}

	if len(manifest.AllowedTemplates) == 0 {
		t.Fatal("manifest contains 0 allowed templates")
	}

	var manifestIDs []string
	for _, tpl := range manifest.AllowedTemplates {
		manifestIDs = append(manifestIDs, tpl.ID)

		// 1. Verify protocol safety: must be in allowed list
		if !slices.Contains(manifest.SafetyCriteria.AllowedProtocols, tpl.Protocol) {
			t.Errorf("template %s has forbidden protocol %q", tpl.ID, tpl.Protocol)
		}
		if slices.Contains(manifest.SafetyCriteria.DisallowedProtocols, tpl.Protocol) {
			t.Errorf("template %s has strictly disallowed protocol %q", tpl.ID, tpl.Protocol)
		}

		// 2. Verify tags: must not contain disallowed/intrusive tags
		for _, tag := range tpl.Tags {
			if slices.Contains(manifest.SafetyCriteria.DisallowedTags, strings.ToLower(tag)) {
				t.Errorf("template %s contains forbidden tag %q", tpl.ID, tag)
			}
		}

		// 3. Verify single/bounded requests count
		if tpl.RequestsCount > 5 {
			t.Errorf("template %s has excessive requests_count: %d", tpl.ID, tpl.RequestsCount)
		}
	}

	// Verify exact match between manifest, templates.txt, and CuratedTemplateIDs in Go
	for _, id := range nuclei.CuratedTemplateIDs {
		if !slices.Contains(manifestIDs, id) {
			t.Errorf("CuratedTemplateIDs entry %q not in manifest.json", id)
		}
		if !slices.Contains(cleanedTxtIDs, id) {
			t.Errorf("CuratedTemplateIDs entry %q not in templates.txt", id)
		}
	}
}

func TestNucleiSeverityPreservation(t *testing.T) {
	// 1. Check critical severity mapping
	if nuclei.NormalizeSeverity("critical") != model.SeverityCritical {
		t.Errorf("NormalizeSeverity('critical') = %v; want SeverityCritical", nuclei.NormalizeSeverity("critical"))
	}
	if nuclei.NormalizeSeverity("high") != model.SeverityHigh {
		t.Errorf("NormalizeSeverity('high') = %v; want SeverityHigh", nuclei.NormalizeSeverity("high"))
	}

	// 2. Test MapRecord preservation
	rec := nuclei.Record{
		TemplateID: "aws-credentials-exposure",
		Info: nuclei.Info{
			Name:        "AWS Credentials File",
			Severity:    "critical",
			Description: "Exposed AWS credentials file with active keys.",
		},
		Type:      "http",
		Host:      "https://example.com",
		MatchedAt: "https://example.com/.aws/credentials",
	}

	emit := &integration.CollectEmitter{}
	nuclei.MapRecord(rec, emit)

	if len(emit.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(emit.Findings))
	}
	f := emit.Findings[0]

	// Must preserve critical
	if f.Severity != model.SeverityCritical {
		t.Errorf("expected finding severity critical, got %s", f.Severity)
	}

	// Check Evidence details
	details := f.Evidence.Details
	if details["source_severity"] != "critical" {
		t.Errorf("expected source_severity critical, got %v", details["source_severity"])
	}
	if details["normalized_severity"] != "critical" {
		t.Errorf("expected normalized_severity critical, got %v", details["normalized_severity"])
	}
	if details["source_template_id"] != "aws-credentials-exposure" {
		t.Errorf("expected source_template_id aws-credentials-exposure, got %v", details["source_template_id"])
	}
	if details["ruleset_version"] != nuclei.CuratedProfileVersion {
		t.Errorf("expected ruleset_version %s, got %v", nuclei.CuratedProfileVersion, details["ruleset_version"])
	}

	// Check Observation provenance
	if len(emit.Observations) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(emit.Observations))
	}
	obs := emit.Observations[0]
	prov, ok := obs.Data["provenance"].(map[string]any)
	if !ok {
		t.Fatalf("missing provenance on observation: %v", obs.Data)
	}
	if prov["source_severity"] != "critical" {
		t.Errorf("observation provenance source_severity = %v; want critical", prov["source_severity"])
	}
	if prov["normalized_severity"] != "critical" {
		t.Errorf("observation provenance normalized_severity = %v; want critical", prov["normalized_severity"])
	}
	if prov["source_template_id"] != "aws-credentials-exposure" {
		t.Errorf("observation provenance source_template_id = %v; want aws-credentials-exposure", prov["source_template_id"])
	}
}

func TestCuratedPolicyFlagsIncludeTemplateIDs(t *testing.T) {
	policy := nuclei.DefaultCuratedPolicy()
	args := policy.BuildCLIArgs()
	argsStr := strings.Join(args, " ")

	if !strings.Contains(argsStr, "-id git-config,") {
		t.Errorf("expected -id flag with curated template IDs, got: %s", argsStr)
	}
	if !strings.Contains(argsStr, "-ni") {
		t.Errorf("expected -ni (no-interactsh), got: %s", argsStr)
	}
}
