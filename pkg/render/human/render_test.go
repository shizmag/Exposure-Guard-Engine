package human

import (
	"bytes"
	"testing"
	"time"

	"github.com/exposureguard/exposureguard/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRenderHumanOutput(t *testing.T) {
	res := &model.ScanResult{
		Status: model.ScanStatusComplete,
		Target: model.Target{URL: "https://example.com/", Scheme: "https", Host: "example.com"},
		Snapshot: model.Snapshot{
			Assets: []model.Asset{
				{Kind: model.AssetKindHostname, Value: "example.com"},
				{Kind: model.AssetKindURL, Value: "https://example.com/"},
				{Kind: model.AssetKindJavaScript, Value: "https://example.com/app.js"},
			},
			Observations: []model.Observation{
				{
					Kind: "tls_certificate",
					Data: map[string]any{
						"verification_status": "valid",
						"days_until_expire":   54,
					},
				},
			},
			Findings: []model.Finding{
				{
					ID:       "f1",
					RuleID:   "frontend.public_source_map",
					Title:    "Public source map discovered",
					Severity: model.SeverityMedium,
					Asset:    "https://example.com/app.js.map",
				},
			},
			Summary: model.SnapshotSummary{
				MediumFindings: 1,
			},
		},
		Changes: []model.Change{
			{
				Type:   "asset.added",
				Reason: "New asset discovered",
			},
		},
		Summary: model.ScanStats{
			AssetsDiscovered: 3,
			TotalFindings:    1,
			TotalChanges:     1,
			TotalDuration:    1500 * time.Millisecond,
		},
	}

	t.Run("standard_render", func(t *testing.T) {
		var buf bytes.Buffer
		err := Render(&buf, res, Options{Quiet: false, NoColor: true})
		require.NoError(t, err)

		out := buf.String()
		assert.Contains(t, out, "ExposureGuard")
		assert.Contains(t, out, "https://example.com/")
		assert.Contains(t, out, "1 hostname(s)")
		assert.Contains(t, out, "1 page(s)")
		assert.Contains(t, out, "1 JavaScript asset(s)")
		assert.Contains(t, out, "Valid (expires in 54 days)")
		assert.Contains(t, out, "1 medium")
		assert.Contains(t, out, "frontend.public_source_map")
		assert.Contains(t, out, "New asset discovered")
		assert.Contains(t, out, "Scan completed in 1.5s")
	})

	t.Run("quiet_render", func(t *testing.T) {
		var buf bytes.Buffer
		err := Render(&buf, res, Options{Quiet: true, NoColor: true})
		require.NoError(t, err)

		out := buf.String()
		assert.Contains(t, out, "Target: https://example.com/")
		assert.Contains(t, out, "Scan completed in 1.5s")
		assert.Contains(t, out, "3 assets, 1 findings, 1 changes")
		assert.NotContains(t, out, "Surface")
	})

	t.Run("nil_result", func(t *testing.T) {
		var buf bytes.Buffer
		err := Render(&buf, nil, Options{})
		require.NoError(t, err)
		assert.Empty(t, buf.String())
	})
}
