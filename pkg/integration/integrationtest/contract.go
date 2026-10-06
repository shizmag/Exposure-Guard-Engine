package integrationtest

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/exposureguard/exposureguard/pkg/integration"
	"github.com/exposureguard/exposureguard/pkg/model"
)

// RunAdapterContract executes standard compliance assertions against any integration Adapter.
func RunAdapterContract(t *testing.T, a integration.Adapter) {
	t.Helper()

	t.Run("metadata_contract", func(t *testing.T) {
		if a.ID() == "" {
			t.Fatal("adapter ID must not be empty")
		}
		meta := a.Metadata()
		if meta.ID != a.ID() {
			t.Fatalf("metadata ID %q does not match adapter ID %q", meta.ID, a.ID())
		}
		if meta.Binary == "" {
			t.Fatal("metadata Binary must not be empty")
		}
		if meta.DisplayName == "" {
			t.Fatal("metadata DisplayName must not be empty")
		}
		if len(meta.Capabilities) == 0 {
			t.Fatal("adapter must declare at least one capability")
		}
		if len(meta.SupportedModes) == 0 {
			t.Fatal("adapter must declare at least one supported mode")
		}
		switch meta.RiskClass {
		case integration.RiskClassPassive, integration.RiskClassLowImpact, integration.RiskClassActive:
			// valid
		default:
			t.Fatalf("unexpected risk class: %q", meta.RiskClass)
		}
	})

	t.Run("plan_contract", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		req := integration.Request{
			Target: model.Target{
				Raw:    "example.com",
				Scheme: "https",
				Host:   "example.com",
				Domain: "example.com",
				Port:   443,
				URL:    "https://example.com",
			},
			Mode:       a.Metadata().SupportedModes[0],
			Profile:    "standard",
			WorkDir:    t.TempDir(),
			InputHosts: []string{"example.com"},
			Limits:     model.DefaultLimits(),
			Timeout:    10 * time.Second,
		}

		plan, err := a.Plan(ctx, req)
		if err != nil {
			t.Fatalf("plan failed on valid request: %v", err)
		}
		if plan.Command.Binary != a.Metadata().Binary {
			t.Errorf("plan binary %q does not match metadata binary %q", plan.Command.Binary, a.Metadata().Binary)
		}
		if len(plan.Command.Args) == 0 {
			t.Errorf("plan generated empty args")
		}
	})

	t.Run("parse_robustness", func(t *testing.T) {
		ctx := context.Background()
		emit := &integration.CollectEmitter{}

		// 1. Empty reader
		if err := a.Parse(ctx, strings.NewReader(""), emit); err != nil {
			t.Logf("empty reader returned non-fatal note: %v", err)
		}

		// 2. Malformed JSON lines
		malformed := "not json\n{truncated\nnull\n{\"foo\":\n"
		if err := a.Parse(ctx, strings.NewReader(malformed), emit); err != nil {
			t.Logf("malformed input returned: %v", err)
		}

		// 3. Huge line (100KB)
		hugeLine := "{\"key\":\"" + strings.Repeat("A", 100*1024) + "\"}\n"
		if err := a.Parse(ctx, strings.NewReader(hugeLine), emit); err != nil {
			t.Logf("huge line parsed with notice: %v", err)
		}
	})

	t.Run("detection_contract", func(t *testing.T) {
		ctx := context.Background()
		meta := a.Metadata()

		// Case 1: Binary missing
		missingRunner := &MockRunner{
			LookPathFunc: func(b string) (string, error) {
				return "", fmt.Errorf("binary not found: %s", b)
			},
		}
		inst, err := a.Detect(ctx, missingRunner)
		if err != nil {
			t.Logf("missing binary returned error: %v", err)
		}
		if inst.Installed {
			t.Errorf("expected Installed=false for missing binary")
		}

		// Case 2: Tested version present
		if meta.TestedVersion != "" {
			testedRunner := NewMockRunnerWithVersion(meta.Binary, meta.TestedVersion)
			inst, err := a.Detect(ctx, testedRunner)
			if err != nil {
				t.Fatalf("detect failed on tested version: %v", err)
			}
			if !inst.Installed {
				t.Errorf("expected Installed=true for tested version")
			}
			if !inst.Compatible {
				t.Errorf("expected Compatible=true for tested version %q", meta.TestedVersion)
			}
		}
	})
}
