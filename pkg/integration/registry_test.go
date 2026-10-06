package integration_test

import (
	"context"
	"io"
	"testing"

	"github.com/exposureguard/exposureguard/pkg/integration"
	"github.com/exposureguard/exposureguard/pkg/model"
)

type dummyAdapter struct {
	id   string
	meta integration.Metadata
}

func (d *dummyAdapter) ID() string {
	return d.id
}

func (d *dummyAdapter) Metadata() integration.Metadata {
	return d.meta
}

func (d *dummyAdapter) Detect(ctx context.Context, runner integration.Runner) (integration.Installation, error) {
	return integration.Installation{Installed: true, Compatible: true}, nil
}

func (d *dummyAdapter) Plan(ctx context.Context, req integration.Request) (integration.ExecutionPlan, error) {
	return integration.ExecutionPlan{}, nil
}

func (d *dummyAdapter) Parse(ctx context.Context, input io.Reader, emit integration.Emitter) error {
	return nil
}

func TestRegistry(t *testing.T) {
	reg := integration.NewRegistry()

	a1 := &dummyAdapter{
		id: "tool-a",
		meta: integration.Metadata{
			ID:          "tool-a",
			Binary:      "tool-a",
			DisplayName: "Tool A",
			Capabilities: []integration.Capability{
				integration.CapabilityAssetDiscovery,
			},
			SupportedModes: []model.ScanMode{model.ScanModePublic},
			RiskClass:      integration.RiskClassPassive,
		},
	}

	a2 := &dummyAdapter{
		id: "tool-b",
		meta: integration.Metadata{
			ID:          "tool-b",
			Binary:      "tool-b",
			DisplayName: "Tool B",
			Capabilities: []integration.Capability{
				integration.CapabilitySecurityCheck,
			},
			SupportedModes: []model.ScanMode{model.ScanModeOwned},
			RiskClass:      integration.RiskClassActive,
		},
	}

	if err := reg.Register(a1); err != nil {
		t.Fatalf("register a1 failed: %v", err)
	}
	if err := reg.Register(a2); err != nil {
		t.Fatalf("register a2 failed: %v", err)
	}

	// Duplicate registration error
	if err := reg.Register(a1); err == nil {
		t.Fatal("expected duplicate error for a1")
	}

	// Lookup
	got, ok := reg.Get("tool-a")
	if !ok || got.ID() != "tool-a" {
		t.Fatalf("expected tool-a, got %v (found: %v)", got, ok)
	}

	// List
	list := reg.List()
	if len(list) != 2 {
		t.Fatalf("expected 2 adapters, got %d", len(list))
	}
	if list[0].ID() != "tool-a" || list[1].ID() != "tool-b" {
		t.Fatalf("unexpected sorted list: %v, %v", list[0].ID(), list[1].ID())
	}

	// By capability
	caps := reg.ByCapability(integration.CapabilityAssetDiscovery)
	if len(caps) != 1 || caps[0].ID() != "tool-a" {
		t.Fatalf("expected 1 asset-discovery adapter, got %v", caps)
	}
}
