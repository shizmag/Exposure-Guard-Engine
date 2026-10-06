package snapshot

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/exposureguard/exposureguard/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildSnapshotDeterministic(t *testing.T) {
	tgt := model.Target{
		Raw:    "https://example.com",
		URL:    "https://example.com/",
		Host:   "example.com",
		Scheme: "https",
		Port:   443,
		Domain: "example.com",
	}

	assets := []model.Asset{
		{Kind: model.AssetKindJavaScript, Value: "https://example.com/z.js"},
		{Kind: model.AssetKindJavaScript, Value: "https://example.com/a.js"},
	}

	obs := []model.Observation{
		{Kind: "b_obs", Subject: "sub", Data: map[string]any{"v": 2}},
		{Kind: "a_obs", Subject: "sub", Data: map[string]any{"v": 1}},
	}

	findings := []model.Finding{
		{RuleID: "low.finding", Severity: model.SeverityLow, Asset: "asset1"},
		{RuleID: "high.finding", Severity: model.SeverityHigh, Asset: "asset2"},
	}

	fixedTime := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	snap1 := Build(tgt, assets, obs, findings, fixedTime)
	snap2 := Build(tgt, assets, obs, findings, fixedTime)

	b1, err := json.Marshal(snap1)
	require.NoError(t, err)
	b2, err := json.Marshal(snap2)
	require.NoError(t, err)

	assert.Equal(t, string(b1), string(b2), "two builds with identical inputs must produce bitwise identical JSON")

	// Verify sorting:
	assert.Equal(t, "https://example.com/a.js", snap1.Assets[0].Value)
	assert.Equal(t, "https://example.com/z.js", snap1.Assets[1].Value)
	assert.Equal(t, model.SeverityHigh, snap1.Findings[0].Severity)
	assert.Equal(t, model.SeverityLow, snap1.Findings[1].Severity)
}

func TestSnapshotGoldenCompatibility(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "testdata", "snapshots", "snapshot_v1_expected.json")
	data, err := os.ReadFile(fixturePath)
	require.NoError(t, err)

	var snap model.Snapshot
	err = json.Unmarshal(data, &snap)
	require.NoError(t, err)

	assert.Equal(t, "1", snap.SchemaVersion)
	assert.Equal(t, "example.com", snap.Target.Host)
	assert.Len(t, snap.Assets, 1)
	assert.Len(t, snap.Observations, 1)
	assert.Len(t, snap.Findings, 1)
	assert.Equal(t, 1, snap.Summary.TotalFindings)
}
