package diff

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/exposureguard/exposureguard/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiffGoldenSourceMapAppeared(t *testing.T) {
	oldPath := filepath.Join("..", "..", "testdata", "snapshots", "diff_source_map_old.json")
	newPath := filepath.Join("..", "..", "testdata", "snapshots", "diff_source_map_new.json")

	oldBytes, err := os.ReadFile(oldPath)
	require.NoError(t, err)
	newBytes, err := os.ReadFile(newPath)
	require.NoError(t, err)

	var oldSnap, newSnap model.Snapshot
	require.NoError(t, json.Unmarshal(oldBytes, &oldSnap))
	require.NoError(t, json.Unmarshal(newBytes, &newSnap))

	changes := Compare(&oldSnap, &newSnap)
	require.NotEmpty(t, changes)

	var foundMapAppeared, foundFindingAppeared bool
	for _, ch := range changes {
		if ch.Type == "frontend.source_map_appeared" {
			foundMapAppeared = true
			assert.Equal(t, model.ImportanceMedium, ch.Importance)
			assert.Equal(t, "https://example.com/bundle.js.map", ch.Subject)
		}
		if ch.Type == "finding.appeared" {
			foundFindingAppeared = true
			assert.Equal(t, model.ImportanceMedium, ch.Importance)
			assert.Equal(t, "https://example.com/bundle.js.map", ch.Subject)
		}
	}

	assert.True(t, foundMapAppeared, "frontend.source_map_appeared change must be emitted")
	assert.True(t, foundFindingAppeared, "finding.appeared change must be emitted")
}

func TestDiffObservations(t *testing.T) {
	oldSnap := &model.Snapshot{
		Observations: []model.Observation{
			{
				Kind:    "tls_certificate",
				Subject: "example.com",
				Data: map[string]any{
					"fingerprint_sha256":  "fp_old",
					"verification_status": "valid",
				},
			},
			{
				Kind:    "http_response",
				Subject: "https://example.com/",
				Data: map[string]any{
					"status_code": 200,
				},
			},
			{
				Kind:    "security_headers",
				Subject: "https://example.com/",
				Data: map[string]any{
					"strict_transport_security": "max-age=31536000",
					"server":                    "nginx",
				},
			},
		},
	}

	newSnap := &model.Snapshot{
		Observations: []model.Observation{
			{
				Kind:    "tls_certificate",
				Subject: "example.com",
				Data: map[string]any{
					"fingerprint_sha256":  "fp_new",
					"verification_status": "invalid",
				},
			},
			{
				Kind:    "http_response",
				Subject: "https://example.com/",
				Data: map[string]any{
					"status_code": 500,
				},
			},
			{
				Kind:    "security_headers",
				Subject: "https://example.com/",
				Data: map[string]any{
					"content_security_policy": "default-src 'self'",
					"server":                  "cloudflare",
					// strict_transport_security was REMOVED!
				},
			},
		},
	}

	changes := Compare(oldSnap, newSnap)
	require.NotEmpty(t, changes)

	changeTypes := make(map[string]bool)
	for _, ch := range changes {
		changeTypes[ch.Type] = true
	}

	assert.True(t, changeTypes["tls.certificate_changed"])
	assert.True(t, changeTypes["tls.validation_changed"])
	assert.True(t, changeTypes["http.status_changed"])
	assert.True(t, changeTypes["http.security_header_removed"])
	assert.True(t, changeTypes["http.security_header_added"])
	assert.True(t, changeTypes["http.security_header_changed"])
}
