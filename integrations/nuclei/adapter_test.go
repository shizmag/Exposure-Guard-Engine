package nuclei_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/exposureguard/exposureguard/integrations/nuclei"
	"github.com/exposureguard/exposureguard/pkg/integration"
	"github.com/exposureguard/exposureguard/pkg/integration/integrationtest"
	"github.com/exposureguard/exposureguard/pkg/model"
)

func TestNucleiContract(t *testing.T) {
	adapter := nuclei.NewAdapter()
	integrationtest.RunAdapterContract(t, adapter)
}

func TestNucleiParseFixture(t *testing.T) {
	f, err := os.Open("testdata/nuclei_result.jsonl")
	if err != nil {
		t.Fatalf("opening fixture failed: %v", err)
	}
	defer f.Close()

	adapter := nuclei.NewAdapter()
	emit := &integration.CollectEmitter{}

	ctx := context.Background()
	if err := adapter.Parse(ctx, f, emit); err != nil {
		t.Fatalf("parsing fixture failed: %v", err)
	}

	if len(emit.Observations) != 3 {
		t.Fatalf("expected 3 observations, got %d", len(emit.Observations))
	}

	// Verify provenance on observations
	for _, o := range emit.Observations {
		if o.Kind != "security.exposure_observation" {
			t.Errorf("expected security.exposure_observation, got %s", o.Kind)
		}
		prov, ok := o.Data["provenance"].(map[string]any)
		if !ok {
			t.Fatalf("missing provenance on observation: %v", o.Data)
		}
		if prov["type"] != "integration" || prov["id"] != "nuclei" {
			t.Errorf("unexpected provenance: %v", prov)
		}
	}

	// Verify findings: git-config (medium) and env-file (high) must produce findings, tls-version (info) must not.
	if len(emit.Findings) != 2 {
		t.Fatalf("expected 2 actionable findings, got %d", len(emit.Findings))
	}

	ruleIDs := map[string]bool{
		"nuclei.git-config": false,
		"nuclei.env-file":   false,
	}

	for _, fnd := range emit.Findings {
		if _, ok := ruleIDs[fnd.RuleID]; ok {
			ruleIDs[fnd.RuleID] = true
		}
		if fnd.CheckID != "integration.nuclei" {
			t.Errorf("expected check_id integration.nuclei, got %s", fnd.CheckID)
		}
		if strings.Contains(strings.ToLower(fnd.Title), "nuclei template") {
			t.Errorf("title should not leak internal implementation: %s", fnd.Title)
		}
	}

	for rID, found := range ruleIDs {
		if !found {
			t.Errorf("finding %s was not emitted", rID)
		}
	}
}

func TestNucleiPolicyRejection(t *testing.T) {
	adapter := nuclei.NewAdapter()
	ctx := context.Background()

	req := integration.Request{
		Target: model.Target{
			Raw:    "example.com",
			URL:    "https://example.com",
			Scheme: "https",
			Host:   "example.com",
			Domain: "example.com",
			Port:   443,
		},
		Mode:    model.ScanModePublic, // Should be rejected
		Profile: "deep",
		Timeout: 10 * time.Second,
	}

	_, err := adapter.Plan(ctx, req)
	if err == nil {
		t.Fatal("expected policy rejection error for public scan mode")
	}
	if !integration.IsErrorCode(err, integration.ErrPolicyDenied) {
		t.Fatalf("expected ErrPolicyDenied, got %v", err)
	}
}

func TestCuratedPolicyFlags(t *testing.T) {
	policy := nuclei.DefaultCuratedPolicy()
	args := policy.BuildCLIArgs()
	argsStr := strings.Join(args, " ")

	if !strings.Contains(argsStr, "-tags exposure,misconfig") {
		t.Errorf("expected exposure tags in args: %s", argsStr)
	}
	if !strings.Contains(argsStr, "-etags fuzz,dos") {
		t.Errorf("expected excluded fuzz tags in args: %s", argsStr)
	}
	if !strings.Contains(argsStr, "-ni") {
		t.Errorf("expected -ni (no-interactsh) in args: %s", argsStr)
	}
}

func TestNucleiParseFixturesComprehensive(t *testing.T) {
	adapter := nuclei.NewAdapter()
	ctx := t.Context()

	// 1. Valid single record
	t.Run("valid", func(t *testing.T) {
		f, err := os.Open("testdata/valid.jsonl")
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()

		emit := &integration.CollectEmitter{}
		if err := adapter.Parse(ctx, f, emit); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(emit.Observations) != 1 {
			t.Fatalf("expected 1 observation, got %d", len(emit.Observations))
		}
		if len(emit.Findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(emit.Findings))
		}
	})

	// 2. Multiple records
	t.Run("multiple", func(t *testing.T) {
		f, err := os.Open("testdata/multiple.jsonl")
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()

		emit := &integration.CollectEmitter{}
		if err := adapter.Parse(ctx, f, emit); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(emit.Observations) != 4 {
			t.Fatalf("expected 4 observations, got %d", len(emit.Observations))
		}
		// Medium, High, Critical produce findings; Info does not
		if len(emit.Findings) != 3 {
			t.Fatalf("expected 3 findings, got %d", len(emit.Findings))
		}
	})

	// 3. Empty output
	t.Run("empty", func(t *testing.T) {
		f, err := os.Open("testdata/empty.jsonl")
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()

		emit := &integration.CollectEmitter{}
		if err := adapter.Parse(ctx, f, emit); err != nil {
			t.Fatalf("unexpected error on empty input: %v", err)
		}
		if len(emit.Observations) != 0 || len(emit.Findings) != 0 {
			t.Errorf("expected 0 items, got %d obs / %d findings", len(emit.Observations), len(emit.Findings))
		}
	})

	// 4. Malformed / truncated records
	t.Run("malformed", func(t *testing.T) {
		f, err := os.Open("testdata/malformed.jsonl")
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()

		emit := &integration.CollectEmitter{}
		if err := adapter.Parse(ctx, f, emit); err != nil {
			t.Fatalf("unexpected error on malformed input: %v", err)
		}
		if len(emit.Observations) != 2 {
			t.Fatalf("expected 2 valid observations from malformed file, got %d", len(emit.Observations))
		}
	})

	// 5. Unexpected optional fields
	t.Run("unexpected_fields", func(t *testing.T) {
		f, err := os.Open("testdata/unexpected_fields.jsonl")
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()

		emit := &integration.CollectEmitter{}
		if err := adapter.Parse(ctx, f, emit); err != nil {
			t.Fatalf("unexpected error on unknown fields: %v", err)
		}
		if len(emit.Observations) != 1 {
			t.Fatalf("expected 1 observation, got %d", len(emit.Observations))
		}
	})
}
