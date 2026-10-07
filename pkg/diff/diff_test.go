package diff

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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
	for _, change := range changes {
		if strings.HasPrefix(change.Type, "http.security_header_") {
			assert.Equal(t, "https://example.com/", change.Subject[:len("https://example.com/")], "header change subject includes asset URL")
			assert.NotEmpty(t, change.Key)
			assert.Len(t, change.Key, 64)
		}
	}
}

func TestDiffZeroChangesOnIdenticalState(t *testing.T) {
	snapA := &model.Snapshot{
		Assets: []model.Asset{
			{ID: "1", Kind: model.AssetKindHostname, Value: "a.example.com"},
			{ID: "2", Kind: model.AssetKindHostname, Value: "b.example.com"},
		},
		Observations: []model.Observation{
			{ID: "o1", Kind: "http_response", Subject: "https://example.com/", Data: map[string]any{"status_code": 200}},
		},
		Findings: []model.Finding{
			{ID: "f1", RuleID: "tls.expired", Asset: "example.com", Severity: model.SeverityHigh},
		},
	}

	snapB := &model.Snapshot{
		Assets: []model.Asset{
			{ID: "2", Kind: model.AssetKindHostname, Value: "b.example.com"},
			{ID: "1", Kind: model.AssetKindHostname, Value: "a.example.com"},
		},
		Observations: []model.Observation{
			{ID: "o1", Kind: "http_response", Subject: "https://example.com/", Data: map[string]any{"status_code": 200}},
		},
		Findings: []model.Finding{
			{ID: "f1", RuleID: "tls.expired", Asset: "example.com", Severity: model.SeverityHigh},
		},
	}

	changes := Compare(snapA, snapB)
	assert.Empty(t, changes, "identical semantic states must produce zero changes")
}

func TestDiffNoiseSuppression(t *testing.T) {
	snapA := &model.Snapshot{
		Observations: []model.Observation{
			{
				Kind:    "security_headers",
				Subject: "https://example.com/",
				Data: map[string]any{
					"content_security_policy":   "default-src 'self'",
					"strict_transport_security": "max-age=31536000",
				},
			},
		},
	}

	snapB := &model.Snapshot{
		Observations: []model.Observation{
			{
				Kind:    "security_headers",
				Subject: "https://example.com/",
				Data: map[string]any{
					"content_security_policy":   "default-src 'self'",
					"strict_transport_security": "max-age=31536000",
				},
			},
		},
	}

	changes := Compare(snapA, snapB)
	assert.Empty(t, changes, "volatile or identical headers must produce zero changes")
}

func TestDiffSemanticTransitions(t *testing.T) {
	oldSnap := &model.Snapshot{
		Assets: []model.Asset{
			{ID: "sub1", Kind: model.AssetKindHostname, Value: "old-staging.example.com"},
		},
		Findings: []model.Finding{
			{ID: "f1", RuleID: "http.missing_hsts", Asset: "example.com", Title: "Missing HSTS", Severity: model.SeverityLow},
		},
	}

	newSnap := &model.Snapshot{
		Assets: []model.Asset{
			{ID: "map1", Kind: model.AssetKindSourceMap, Value: "https://example.com/main.js.map"},
		},
		Findings: nil, // finding resolved!
	}

	changes := Compare(oldSnap, newSnap)
	require.NotEmpty(t, changes)

	types := make(map[string]model.Change)
	for _, ch := range changes {
		types[ch.Type] = ch
		assert.NotEmpty(t, ch.ID, "change must have a non-empty deterministic ID")
		assert.Len(t, ch.ID, 64, "change ID must be 64-hex SHA-256 characters")
		assert.Len(t, ch.Key, 64, "change key must be 64-hex SHA-256 characters")
	}

	assert.Contains(t, types, "asset.removed")
	assert.Equal(t, "old-staging.example.com", types["asset.removed"].Subject)

	assert.Contains(t, types, "finding.resolved")
	assert.Equal(t, "example.com", types["finding.resolved"].Subject)

	assert.Contains(t, types, "frontend.source_map_appeared")
	assert.Equal(t, "https://example.com/main.js.map", types["frontend.source_map_appeared"].Subject)
}

func TestDiffNilSafety(t *testing.T) {
	assert.Nil(t, Compare(nil, nil))
	assert.Nil(t, Compare(&model.Snapshot{}, nil))
	assert.Nil(t, Compare(nil, &model.Snapshot{}))
}
