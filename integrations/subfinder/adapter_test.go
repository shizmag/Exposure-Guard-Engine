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

func TestSubfinderParseFixturesComprehensive(t *testing.T) {
	adapter := subfinder.NewAdapter()
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
		if len(emit.Assets) != 1 {
			t.Fatalf("expected 1 asset, got %d", len(emit.Assets))
		}
		if emit.Assets[0].Value != "api.example.com" {
			t.Errorf("expected api.example.com, got %s", emit.Assets[0].Value)
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
		if len(emit.Assets) != 3 {
			t.Fatalf("expected 3 assets, got %d", len(emit.Assets))
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
		if len(emit.Assets) != 0 || len(emit.Observations) != 0 {
			t.Errorf("expected 0 assets/obs, got %d/%d", len(emit.Assets), len(emit.Observations))
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
		// Must not panic or return error on malformed lines; skips them gracefully
		if err := adapter.Parse(ctx, f, emit); err != nil {
			t.Fatalf("unexpected error on malformed input: %v", err)
		}
		// Expect the 2 valid records to have been parsed
		if len(emit.Assets) != 2 {
			t.Fatalf("expected 2 valid assets from malformed file, got %d", len(emit.Assets))
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
		if len(emit.Assets) != 2 {
			t.Fatalf("expected 2 assets, got %d", len(emit.Assets))
		}
	})
}
