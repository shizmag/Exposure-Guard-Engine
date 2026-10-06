package httpx_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/exposureguard/exposureguard/integrations/httpx"
	"github.com/exposureguard/exposureguard/pkg/integration"
	"github.com/exposureguard/exposureguard/pkg/integration/integrationtest"
	"github.com/exposureguard/exposureguard/pkg/model"
)

func TestHttpxContract(t *testing.T) {
	adapter := httpx.NewAdapter()
	integrationtest.RunAdapterContract(t, adapter)
}

func TestHttpxParseFixture(t *testing.T) {
	f, err := os.Open("testdata/httpx_result.jsonl")
	if err != nil {
		t.Fatalf("opening fixture failed: %v", err)
	}
	defer f.Close()

	adapter := httpx.NewAdapter()
	emit := &integration.CollectEmitter{}

	ctx := context.Background()
	if err := adapter.Parse(ctx, f, emit); err != nil {
		t.Fatalf("parsing fixture failed: %v", err)
	}

	if len(emit.Assets) != 2 {
		t.Fatalf("expected 2 assets, got %d", len(emit.Assets))
	}

	for _, a := range emit.Assets {
		if a.Kind != model.AssetKindURL {
			t.Errorf("expected AssetKindURL, got %v", a.Kind)
		}
		if a.Source != "httpx" {
			t.Errorf("expected source httpx, got %s", a.Source)
		}
	}

	if len(emit.Observations) != 2 {
		t.Fatalf("expected 2 observations, got %d", len(emit.Observations))
	}

	firstObs := emit.Observations[0]
	if firstObs.Kind != "http.service_probe" {
		t.Errorf("expected kind http.service_probe, got %s", firstObs.Kind)
	}
	if firstObs.Data["status_code"] != float64(200) && firstObs.Data["status_code"] != 200 {
		t.Errorf("expected status_code 200, got %v", firstObs.Data["status_code"])
	}
	if firstObs.Data["webserver"] != "envoy" {
		t.Errorf("expected webserver envoy, got %v", firstObs.Data["webserver"])
	}
}

func TestHttpxPolicyRejection(t *testing.T) {
	adapter := httpx.NewAdapter()
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
		Mode:    model.ScanModePublic, // Should be rejected for httpx
		Profile: "standard",
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
