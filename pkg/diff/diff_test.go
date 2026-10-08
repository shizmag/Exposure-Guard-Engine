package diff

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/exposureguard/exposureguard/pkg/model"
	"github.com/exposureguard/exposureguard/pkg/snapshot"
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

func TestDiffJSONRoundTrippedHTTPStatusDoesNotCreateChange(t *testing.T) {
	previous := model.Snapshot{Observations: []model.Observation{{
		Kind: "http_response", Subject: "http://example.com/", Data: map[string]any{"status_code": 200},
	}}}
	encoded, err := json.Marshal(previous)
	require.NoError(t, err)
	var loaded model.Snapshot
	require.NoError(t, json.Unmarshal(encoded, &loaded))

	current := model.Snapshot{Observations: []model.Observation{{
		Kind: "http_response", Subject: "http://example.com/", Data: map[string]any{"status_code": 200},
	}}}
	assert.Empty(t, Compare(&loaded, &current), "JSON numeric normalization must not create a false HTTP status transition")
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

func TestCoverageAwareMixedProfileLifecycle(t *testing.T) {
	deep := &model.Snapshot{
		SchemaVersion: "2",
		Coverage:      []string{"dns", "tls", "http", "crawl", "javascript", "integration.subfinder", "integration.httpx", "integration.katana", "integration.nuclei"},
		Assets:        []model.Asset{{ID: "map-x", Kind: model.AssetKindSourceMap, Value: "https://example.com/app.js.map", Coverage: []string{"javascript"}}},
		Findings:      []model.Finding{{ID: "finding-x", CheckID: "integration.nuclei", RuleID: "nuclei.exposure", Asset: "example.com", Severity: model.SeverityHigh, Coverage: []string{"integration.nuclei"}}},
	}
	quick := &model.Snapshot{SchemaVersion: "2", Coverage: []string{"dns", "tls", "http"}}
	standard := &model.Snapshot{SchemaVersion: "2", Coverage: []string{"dns", "tls", "http", "crawl", "javascript", "integration.subfinder"}}
	quickAgain := &model.Snapshot{SchemaVersion: "2", Coverage: []string{"dns", "tls", "http"}}

	assert.Empty(t, Compare(deep, quick), "quick lacks JavaScript and nuclei coverage, so it cannot report their disappearance")
	assert.Empty(t, Compare(quick, standard), "coverage changes alone cannot claim a previously missing asset disappeared or appeared")
	assert.Empty(t, Compare(standard, quickAgain), "a second quick scan still cannot resolve findings from uncovered stages")
	newlyDiscovered := Compare(quick, deep)
	assert.ElementsMatch(t, []string{"finding.appeared", "frontend.source_map_appeared"}, changeTypes(newlyDiscovered), "positive observations from a deeper scan must be reported")
	deepToStandard := Compare(deep, standard)
	assert.NotContains(t, changeTypes(deepToStandard), "finding.resolved", "standard cannot resolve a finding only produced by the nuclei integration")

	deepAgain := &model.Snapshot{SchemaVersion: "2", Coverage: append([]string(nil), deep.Coverage...)}
	changes := Compare(deep, deepAgain)
	require.Len(t, changes, 2)
	assert.ElementsMatch(t, []string{"finding.resolved", "frontend.source_map_disappeared"}, changeTypes(changes))

	partialDeep := &model.Snapshot{SchemaVersion: "2", Coverage: []string{"dns", "tls", "http"}}
	partialChanges := Compare(deep, partialDeep)
	assert.NotContains(t, changeTypes(partialChanges), "frontend.source_map_disappeared", "missing JavaScript coverage cannot resolve the source map")
	assert.NotContains(t, changeTypes(partialChanges), "finding.resolved", "partial deep coverage cannot resolve findings from stages that did not complete")
}

func TestSnapshotV1ToV2TransitionsNeverInferResolution(t *testing.T) {
	legacy := &model.Snapshot{
		SchemaVersion: "1",
		Findings: []model.Finding{{
			ID: "legacy-finding", CheckID: "integration.nuclei", RuleID: "nuclei.exposure",
			Asset: "example.com", Severity: model.SeverityHigh,
		}},
		Assets: []model.Asset{{ID: "legacy-asset", Kind: model.AssetKindHostname, Value: "old.example.com"}},
	}
	profiles := []struct {
		name     string
		coverage []string
	}{
		{name: "quick", coverage: []string{"dns", "tls", "http"}},
		{name: "standard", coverage: []string{"dns", "tls", "http", "crawl", "javascript", "integration.subfinder"}},
		{name: "deep", coverage: []string{"dns", "tls", "http", "crawl", "javascript", "integration.subfinder", "integration.httpx", "integration.katana", "integration.nuclei"}},
	}
	for _, profile := range profiles {
		t.Run("v1_to_v2_"+profile.name, func(t *testing.T) {
			current := &model.Snapshot{SchemaVersion: "2", Coverage: profile.coverage}
			assert.Empty(t, Compare(legacy, current), "a v1 baseline has no provenance; %s cannot safely infer changes", profile.name)
		})
	}
}

func TestCoverageLifecycleKeepsPerProfileHistoryAndRequiresEveryAssetOrigin(t *testing.T) {
	deep := &model.Snapshot{
		SchemaVersion: "2",
		Coverage:      []string{"dns", "tls", "http", "crawl", "javascript", "integration.subfinder", "integration.httpx", "integration.katana", "integration.nuclei"},
		Findings: []model.Finding{{
			ID: "finding-x", CheckID: "integration.nuclei", RuleID: "nuclei.exposure",
			Asset: "example.com", Severity: model.SeverityHigh, Coverage: []string{"integration.nuclei"},
		}},
	}
	sequence := []*model.Snapshot{
		{SchemaVersion: "2", Coverage: []string{"dns", "tls", "http"}},
		{SchemaVersion: "2", Coverage: []string{"dns", "tls", "http"}},
		{SchemaVersion: "2", Coverage: []string{"dns", "tls", "http", "crawl", "javascript", "integration.subfinder"}},
	}
	for _, current := range sequence {
		assert.NotContains(t, changeTypes(Compare(deep, current)), "finding.resolved")
	}
	confirmedDeep := &model.Snapshot{SchemaVersion: "2", Coverage: append([]string(nil), deep.Coverage...)}
	assert.Contains(t, changeTypes(Compare(deep, confirmedDeep)), "finding.resolved")

	multiOrigin := &model.Snapshot{
		SchemaVersion: "2", Coverage: []string{"dns", "integration.subfinder"},
		Assets: []model.Asset{{
			ID: "multi-origin", Kind: model.AssetKindHostname, Value: "api.example.com",
			Coverage: []string{"dns", "integration.subfinder"},
		}},
	}
	withoutOneOrigin := &model.Snapshot{SchemaVersion: "2", Coverage: []string{"dns"}}
	assert.NotContains(t, changeTypes(Compare(multiOrigin, withoutOneOrigin)), "asset.removed")
	withAllOrigins := &model.Snapshot{SchemaVersion: "2", Coverage: []string{"dns", "integration.subfinder"}}
	assert.Contains(t, changeTypes(Compare(multiOrigin, withAllOrigins)), "asset.removed")
}

func TestV2ProfileTransitionsRespectCoverage(t *testing.T) {
	quick := &model.Snapshot{SchemaVersion: "2", Coverage: []string{"dns", "tls", "http"}}
	deep := &model.Snapshot{
		SchemaVersion: "2",
		Coverage:      []string{"dns", "tls", "http", "crawl", "javascript", "integration.subfinder", "integration.httpx", "integration.katana", "integration.nuclei"},
		Findings: []model.Finding{{
			ID: "finding-x", CheckID: "integration.nuclei", RuleID: "nuclei.exposure",
			Asset: "example.com", Severity: model.SeverityHigh, Coverage: []string{"integration.nuclei"},
		}},
	}

	assert.Contains(t, changeTypes(Compare(quick, deep)), "finding.appeared", "deep positive evidence is retained after quick coverage")
	quickAgain := snapshot.CarryForwardUncovered(deep, *quick)
	assert.NotContains(t, changeTypes(Compare(deep, &quickAgain)), "finding.resolved", "quick cannot resolve a deep-only finding")
	assert.Len(t, quickAgain.Findings, 1)
	assert.True(t, quickAgain.Findings[0].CarriedForward)
}

func TestPartialV2BaselineCarriesItemsUntilCompleteCoverage(t *testing.T) {
	deepCoverage := []string{"dns", "tls", "http", "crawl", "javascript", "integration.subfinder", "integration.httpx", "integration.katana", "integration.nuclei"}
	baseline := &model.Snapshot{
		SchemaVersion: "2",
		Coverage:      deepCoverage,
		Assets: []model.Asset{{
			ID: "asset-x", Kind: model.AssetKindHostname, Value: "api.example.com",
			Coverage: []string{"dns", "integration.subfinder"},
		}},
		Findings: []model.Finding{{
			ID: "finding-x", CheckID: "integration.nuclei", RuleID: "nuclei.exposure",
			Asset: "api.example.com", Severity: model.SeverityHigh, Coverage: []string{"integration.nuclei"},
		}},
	}
	partial := snapshot.CarryForwardUncovered(baseline, model.Snapshot{
		SchemaVersion: "2", Coverage: []string{"dns", "tls", "http"},
	})
	assert.Empty(t, Compare(baseline, &partial), "partial coverage keeps prior findings and assets in the comparison baseline")
	assert.Len(t, partial.Findings, 1)
	assert.True(t, partial.Findings[0].CarriedForward)
	assert.Len(t, partial.Assets, 1)
	assert.True(t, partial.Assets[0].CarriedForward)
	assert.Equal(t, []string{"integration.nuclei"}, partial.Findings[0].Coverage)

	complete := snapshot.CarryForwardUncovered(&partial, model.Snapshot{
		SchemaVersion: "2", Coverage: deepCoverage,
	})
	changes := changeTypes(Compare(&partial, &complete))
	assert.Contains(t, changes, "finding.resolved", "the later complete run emits the Engine-owned resolution")
	assert.Contains(t, changes, "asset.removed", "the later complete run can confirm all prior asset origins are absent")
	assert.Empty(t, complete.Findings)
	assert.Empty(t, complete.Assets)
}

func TestCurrentObservationRetainsPriorMultiOriginProvenance(t *testing.T) {
	previous := &model.Snapshot{
		SchemaVersion: "2", Coverage: []string{"dns", "integration.subfinder"},
		Assets: []model.Asset{{
			ID: "asset-x", Kind: model.AssetKindHostname, Value: "api.example.com",
			Coverage: []string{"dns", "integration.subfinder"},
		}},
	}
	current := snapshot.CarryForwardUncovered(previous, model.Snapshot{
		SchemaVersion: "2", Coverage: []string{"dns"},
		Assets: []model.Asset{{
			ID: "asset-x", Kind: model.AssetKindHostname, Value: "api.example.com",
			Coverage: []string{"dns"},
		}},
	})
	assert.Len(t, current.Assets, 1)
	assert.Equal(t, []string{"dns", "integration.subfinder"}, current.Assets[0].Coverage)
	assert.False(t, current.Assets[0].CarriedForward, "positive current evidence means this asset was observed in this scan")
}

func changeTypes(changes []model.Change) []string {
	result := make([]string, 0, len(changes))
	for _, change := range changes {
		result = append(result, change.Type)
	}
	return result
}
