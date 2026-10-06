package engine

import (
	"bytes"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/exposureguard/exposureguard/pkg/crawl"
	"github.com/exposureguard/exposureguard/pkg/diff"
	"github.com/exposureguard/exposureguard/pkg/model"
	"github.com/exposureguard/exposureguard/pkg/protocol"
	"github.com/exposureguard/exposureguard/pkg/snapshot"
	"github.com/exposureguard/exposureguard/pkg/static"
	"github.com/exposureguard/exposureguard/pkg/target"
)

func BenchmarkTargetNormalization(b *testing.B) {
	raw := "https://Sub.Example.COM:443/app/../dashboard?utm_source=ad#frag"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := target.Parse(raw)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHTMLExtraction(b *testing.B) {
	htmlData := `
<!DOCTYPE html>
<html>
<head>
  <script src="/static/app.js"></script>
  <link rel="stylesheet" href="/style.css">
  <link rel="modulepreload" href="/vendor.mjs">
</head>
<body>
  <h1>ExposureGuard Benchmark</h1>
  <a href="/about">About</a>
  <a href="/contact">Contact</a>
  <a href="https://external.example.org/api">External</a>
  <form action="/login" method="post"></form>
</body>
</html>`

	baseURL, _ := url.Parse("https://example.com/page")
	tgt, _ := target.Parse("https://example.com")
	scope := target.NewScope(tgt)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		crawl.ExtractHTML(baseURL, []byte(htmlData), scope)
	}
}

func BenchmarkJSCredentialDetection(b *testing.B) {
	jsData := []byte(`
const config = {
  version: "1.0.0",
  endpoint: "/api/v1",
  token: "AKIAIOSFODNN7EXAMPLE",
  github: "ghp_FakeGitHubPersonalAccessToken123456",
  slack: "xoxb-123456789012-1234567890123-FakeSlackTokenABCDEFGHIJKL"
};
`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		static.DetectCredentials("https://example.com/app.js", jsData)
	}
}

func BenchmarkSnapshotNormalizationAndHash(b *testing.B) {
	tgt := model.Target{
		URL:    "https://example.com/",
		Host:   "example.com",
		Scheme: "https",
		Port:   443,
	}

	assets := make([]model.Asset, 50)
	for i := 0; i < 50; i++ {
		assets[i] = model.Asset{
			Kind:  model.AssetKindJavaScript,
			Value: fmt.Sprintf("https://example.com/chunk-%d.js", i),
		}
	}

	obs := make([]model.Observation, 20)
	for i := 0; i < 20; i++ {
		obs[i] = model.Observation{
			Kind:    "http_response",
			Subject: fmt.Sprintf("https://example.com/page-%d", i),
			Data:    map[string]any{"status_code": 200, "response_time_ms": i * 5},
		}
	}

	findings := []model.Finding{
		{RuleID: "http.missing_hsts", Severity: model.SeverityLow, Asset: "https://example.com/"},
		{RuleID: "frontend.public_source_map", Severity: model.SeverityMedium, Asset: "https://example.com/chunk-1.js.map"},
	}

	now := time.Now()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s := snapshot.Build(tgt, assets, obs, findings, now)
		_ = snapshot.ComputeCanonicalHash(&s)
	}
}

func BenchmarkDiffComputation(b *testing.B) {
	tgt := model.Target{URL: "https://example.com/", Host: "example.com", Scheme: "https", Port: 443}

	assetsOld := make([]model.Asset, 50)
	assetsNew := make([]model.Asset, 50)
	for i := 0; i < 50; i++ {
		assetsOld[i] = model.Asset{ID: fmt.Sprintf("%d", i), Kind: model.AssetKindHostname, Value: fmt.Sprintf("sub%d.example.com", i)}
		assetsNew[i] = model.Asset{ID: fmt.Sprintf("%d", i), Kind: model.AssetKindHostname, Value: fmt.Sprintf("sub%d.example.com", i)}
	}
	// Add one change
	assetsNew[49].Value = "changed.example.com"

	snapOld := snapshot.Build(tgt, assetsOld, nil, nil, time.Now())
	snapNew := snapshot.Build(tgt, assetsNew, nil, nil, time.Now())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = diff.Compare(&snapOld, &snapNew)
	}
}

func BenchmarkJSONLEncoding(b *testing.B) {
	var buf bytes.Buffer
	enc := protocol.NewEncoder(&buf, "bench-scan")
	data := map[string]any{
		"target": "https://example.com",
		"asset":  "sub.example.com",
		"score":  123.45,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		_ = enc.Emit(protocol.EventObservation, data)
	}
}
