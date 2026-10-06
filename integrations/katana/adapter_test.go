package katana_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/exposureguard/exposureguard/integrations/katana"
	"github.com/exposureguard/exposureguard/pkg/integration"
	"github.com/exposureguard/exposureguard/pkg/integration/integrationtest"
	"github.com/exposureguard/exposureguard/pkg/model"
)

func TestKatanaContract(t *testing.T) {
	adapter := katana.NewAdapter()
	integrationtest.RunAdapterContract(t, adapter)
}

func TestKatanaParseFixture(t *testing.T) {
	f, err := os.Open("testdata/katana_result.jsonl")
	if err != nil {
		t.Fatalf("opening fixture failed: %v", err)
	}
	defer f.Close()

	adapter := katana.NewAdapter()
	emit := &integration.CollectEmitter{}

	ctx := context.Background()
	if err := adapter.Parse(ctx, f, emit); err != nil {
		t.Fatalf("parsing fixture failed: %v", err)
	}

	if len(emit.Assets) != 4 {
		t.Fatalf("expected 4 assets, got %d", len(emit.Assets))
	}

	kindsByValue := make(map[string]model.AssetKind)
	for _, a := range emit.Assets {
		kindsByValue[a.Value] = a.Kind
		if a.Source != "katana" {
			t.Errorf("expected source katana, got %s", a.Source)
		}
	}

	if kindsByValue["https://example.com/assets/bundle.js"] != model.AssetKindJavaScript {
		t.Errorf("expected AssetKindJavaScript for bundle.js, got %v", kindsByValue["https://example.com/assets/bundle.js"])
	}
	if kindsByValue["https://example.com/api/v1/auth"] != model.AssetKindEndpoint {
		t.Errorf("expected AssetKindEndpoint for /api/v1/auth, got %v", kindsByValue["https://example.com/api/v1/auth"])
	}
	if kindsByValue["https://cdn.thirdparty.com/library.js"] != model.AssetKindExternal {
		t.Errorf("expected AssetKindExternal for third-party cdn, got %v", kindsByValue["https://cdn.thirdparty.com/library.js"])
	}
	if kindsByValue["https://example.com/about"] != model.AssetKindURL {
		t.Errorf("expected AssetKindURL for /about, got %v", kindsByValue["https://example.com/about"])
	}

	if len(emit.Observations) != 4 {
		t.Fatalf("expected 4 observations, got %d", len(emit.Observations))
	}
	for _, o := range emit.Observations {
		if o.Kind != "crawler.endpoint_discovered" {
			t.Errorf("expected crawler.endpoint_discovered, got %s", o.Kind)
		}
	}
}

func TestKatanaPolicyRejection(t *testing.T) {
	adapter := katana.NewAdapter()
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
		Mode:    model.ScanModePublic, // Should be rejected for katana
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

func TestKatanaParseFixturesComprehensive(t *testing.T) {
	adapter := katana.NewAdapter()
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
		if emit.Assets[0].Kind != model.AssetKindJavaScript {
			t.Errorf("expected AssetKindJavaScript, got %v", emit.Assets[0].Kind)
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
		if len(emit.Assets) != 4 {
			t.Fatalf("expected 4 assets, got %d", len(emit.Assets))
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
		if err := adapter.Parse(ctx, f, emit); err != nil {
			t.Fatalf("unexpected error on malformed input: %v", err)
		}
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
		if len(emit.Assets) != 1 {
			t.Fatalf("expected 1 asset, got %d", len(emit.Assets))
		}
	})
}
