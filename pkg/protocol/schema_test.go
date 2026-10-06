package protocol

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/exposureguard/exposureguard/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func findRepoRoot(t *testing.T) string {
	wd, err := os.Getwd()
	require.NoError(t, err)

	for {
		if _, err := os.Stat(filepath.Join(wd, "go.mod")); err == nil {
			return wd
		}
		parent := filepath.Dir(wd)
		if parent == wd {
			t.Fatal("could not locate repository root")
		}
		wd = parent
	}
}

func TestJSONSchemasValidity(t *testing.T) {
	root := findRepoRoot(t)

	schemaFiles := []string{
		filepath.Join(root, "schemas", "protocol-v1", "scan-request.schema.json"),
		filepath.Join(root, "schemas", "protocol-v1", "event.schema.json"),
		filepath.Join(root, "schemas", "protocol-v1", "scan-result.schema.json"),
		filepath.Join(root, "schemas", "snapshot-v1.schema.json"),
	}

	for _, sf := range schemaFiles {
		t.Run(filepath.Base(sf), func(t *testing.T) {
			data, err := os.ReadFile(sf)
			require.NoError(t, err, "schema file should exist and be readable: %s", sf)

			var parsed map[string]any
			err = json.Unmarshal(data, &parsed)
			require.NoError(t, err, "schema must be valid JSON: %s", sf)

			assert.NotEmpty(t, parsed["$schema"])
			assert.NotEmpty(t, parsed["title"])
			assert.Equal(t, "object", parsed["type"])
		})
	}
}

func TestGoldenSnapshotMatchesSchema(t *testing.T) {
	root := findRepoRoot(t)
	goldenPath := filepath.Join(root, "testdata", "snapshots", "snapshot_v1_expected.json")

	data, err := os.ReadFile(goldenPath)
	require.NoError(t, err)

	var snap model.Snapshot
	require.NoError(t, json.Unmarshal(data, &snap))

	assert.Equal(t, "1", snap.SchemaVersion)
	assert.NotEmpty(t, snap.Target.URL)
	assert.NotEmpty(t, snap.Assets)
	assert.NotEmpty(t, snap.Observations)
	assert.NotEmpty(t, snap.Findings)
	assert.Equal(t, 1, snap.Summary.TotalAssets)
	assert.Equal(t, 1, snap.Summary.TotalFindings)
}

func TestEventEnvelopeSerialization(t *testing.T) {
	env := Envelope{
		SchemaVersion: "1",
		Seq:           1,
		Timestamp:     time.Now().UTC(),
		ScanID:        "test-scan",
		Type:          EventScanStarted,
		Data: map[string]string{
			"target": "https://example.com",
		},
	}

	data, err := json.Marshal(env)
	require.NoError(t, err)

	var unmarshaled map[string]any
	require.NoError(t, json.Unmarshal(data, &unmarshaled))

	assert.Equal(t, "1", unmarshaled["schema_version"])
	assert.Equal(t, float64(1), unmarshaled["seq"])
	assert.Equal(t, "test-scan", unmarshaled["scan_id"])
	assert.Equal(t, "scan.started", unmarshaled["type"])
	assert.NotNil(t, unmarshaled["data"])
}

func TestCloudCanonicalFixtures(t *testing.T) {
	root := findRepoRoot(t)

	// 1. ScanRequest fixture
	reqPath := filepath.Join(root, "testdata", "cloud", "scan-request.json")
	reqBytes, err := os.ReadFile(reqPath)
	require.NoError(t, err)
	var req model.ScanRequest
	require.NoError(t, json.Unmarshal(reqBytes, &req))
	assert.Equal(t, "1", req.SchemaVersion)
	assert.Equal(t, "https://example.com", req.Target)
	assert.Equal(t, "standard", req.Profile)

	// 2. ScanResult fixture
	resPath := filepath.Join(root, "testdata", "cloud", "expected-result.json")
	resBytes, err := os.ReadFile(resPath)
	require.NoError(t, err)
	var res model.ScanResult
	require.NoError(t, json.Unmarshal(resBytes, &res))
	assert.Equal(t, "1", res.Snapshot.SchemaVersion)
	assert.Equal(t, model.ScanStatusComplete, res.Status)
	assert.NotEmpty(t, res.Snapshot.Fingerprint)

	// 3. Events JSONL fixture
	eventsPath := filepath.Join(root, "testdata", "cloud", "expected-events.jsonl")
	eventsBytes, err := os.ReadFile(eventsPath)
	require.NoError(t, err)
	lines := splitLines(string(eventsBytes))
	require.NotEmpty(t, lines)

	for i, l := range lines {
		var env Envelope
		require.NoError(t, json.Unmarshal([]byte(l), &env))
		assert.Equal(t, int64(i+1), env.Seq, "event sequence in cloud fixture must be strictly monotonic")
		if i == 0 {
			assert.Equal(t, EventScanStarted, env.Type)
		}
		if i == len(lines)-1 {
			assert.Equal(t, EventScanCompleted, env.Type)
		}
	}
}

func splitLines(s string) []string {
	var res []string
	for _, l := range strings.Split(s, "\n") {
		trimmed := strings.TrimSpace(l)
		if trimmed != "" {
			res = append(res, trimmed)
		}
	}
	return res
}
