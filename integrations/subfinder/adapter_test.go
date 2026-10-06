package subfinder_test

import (
	"context"
	"os"
	"testing"

	"github.com/exposureguard/exposureguard/integrations/subfinder"
	"github.com/exposureguard/exposureguard/pkg/integration"
	"github.com/exposureguard/exposureguard/pkg/integration/integrationtest"
	"github.com/exposureguard/exposureguard/pkg/model"
)

func TestSubfinderContract(t *testing.T) {
	adapter := subfinder.NewAdapter()
	integrationtest.RunAdapterContract(t, adapter)
}

func TestSubfinderParseFixture(t *testing.T) {
	data, err := os.ReadFile("testdata/subfinder_result.jsonl")
	if err != nil {
		t.Fatalf("reading fixture failed: %v", err)
	}

	adapter := subfinder.NewAdapter()
	emit := &integration.CollectEmitter{}

	ctx := context.Background()
	if err := adapter.Parse(ctx, os.NewFile(0, ""), emit); err != nil {
		// test empty
	}

	emit = &integration.CollectEmitter{}
	if err := subfinder.Parse(ctx, os.NewFile(0, ""), emit); err != nil {
		// test empty
	}

	emit = &integration.CollectEmitter{}
	f, err := os.Open("testdata/subfinder_result.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if err := adapter.Parse(ctx, f, emit); err != nil {
		t.Fatalf("parse fixture failed: %v", err)
	}

	if len(emit.Assets) != 3 {
		t.Fatalf("expected 3 assets, got %d", len(emit.Assets))
	}

	expectedHosts := map[string]bool{
		"api.example.com":     false,
		"auth.example.com":    false,
		"staging.example.com": false,
	}

	for _, a := range emit.Assets {
		if a.Kind != model.AssetKindHostname {
			t.Errorf("expected AssetKindHostname, got %v", a.Kind)
		}
		if _, ok := expectedHosts[a.Value]; ok {
			expectedHosts[a.Value] = true
		}
		if a.Source != "subfinder" {
			t.Errorf("expected source subfinder, got %v", a.Source)
		}
	}

	for host, found := range expectedHosts {
		if !found {
			t.Errorf("host %s was not emitted", host)
		}
	}

	if len(emit.Observations) != 3 {
		t.Fatalf("expected 3 observations, got %d", len(emit.Observations))
	}
	for _, o := range emit.Observations {
		if o.Kind != "subdomain.passive_discovery" {
			t.Errorf("expected subdomain.passive_discovery, got %s", o.Kind)
		}
		if o.Data["passive"] != true {
			t.Errorf("expected passive=true in observation data")
		}
	}
	_ = data
}
