package e2e_test

import (
	"encoding/json"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/exposureguard/exposureguard/integrations"
	"github.com/exposureguard/exposureguard/pkg/checks"
	"github.com/exposureguard/exposureguard/pkg/diff"
	"github.com/exposureguard/exposureguard/pkg/engine"
	"github.com/exposureguard/exposureguard/pkg/integration"
	"github.com/exposureguard/exposureguard/pkg/model"
	"github.com/exposureguard/exposureguard/pkg/netguard"
	"github.com/exposureguard/exposureguard/test/e2e"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func runPipelineScan(t *testing.T, targetURL string, reg *integration.Registry) *model.ScanResult {
	t.Helper()

	if _, err := url.Parse(targetURL); err != nil {
		require.NoError(t, err)
	}

	limits := model.DefaultLimits()
	limits.TotalTimeoutSeconds = 30
	limits.RequestTimeoutSeconds = 5
	limits.MaxDepth = 2
	limits.MaxPages = 20

	policy := netguard.AllowPrivateNetworkPolicy{}
	scanEnv := checks.NewEnvironmentWithPolicy(nil, nil, policy, limits, nil)

	eng := engine.NewEngineWithIntegrations(scanEnv, nil, reg, integration.NewOSRunner(""))

	req := model.ScanRequest{
		ScanID:       "e2e-" + strconv.FormatInt(time.Now().UnixNano(), 10),
		Target:       targetURL,
		Profile:      "deep",
		Mode:         model.ScanModeOwned,
		Integrations: "auto",
		Limits:       limits,
	}

	res, err := eng.Run(t.Context(), engine.Options{Request: req})
	require.NoError(t, err)
	require.NotNil(t, res)
	return res
}

func TestEndToEndPipelineAndDiff(t *testing.T) {
	server := e2e.NewSyntheticServer()
	defer server.Close()

	reg := integrations.NewBuiltinRegistry()

	// -------------------------------------------------------------
	// State A: Safe configuration (CSP present, no source map, no leak)
	// -------------------------------------------------------------
	server.SetState(e2e.StateA)
	resA := runPipelineScan(t, server.URL(), reg)
	snapA := resA.Snapshot
	require.NotNil(t, snapA)

	// Verify State A invariants
	assert.NotEmpty(t, snapA.Assets, "State A must discover assets")
	assert.NotEmpty(t, snapA.Observations, "State A must record observations")

	// In State A, there should be NO public source map finding
	for _, f := range snapA.Findings {
		assert.NotEqual(t, "frontend.public_source_map", f.RuleID, "State A must not report public source map")
		assert.NotEqual(t, "security.csp_missing", f.RuleID, "State A must not report missing CSP")
	}

	// -------------------------------------------------------------
	// State B: Drifted configuration (CSP removed, source map public, new portal)
	// -------------------------------------------------------------
	server.SetState(e2e.StateB)
	resB := runPipelineScan(t, server.URL(), reg)
	snapB := resB.Snapshot
	require.NotNil(t, snapB)

	// In State B, source map and Nuclei git exposure MUST be detected
	var foundSourceMapFinding, foundNucleiGitFinding bool
	for _, f := range snapB.Findings {
		if f.RuleID == "frontend.public_source_map" {
			foundSourceMapFinding = true
			assert.Equal(t, model.SeverityMedium, f.Severity)
		}
		if f.RuleID == "nuclei.git_config" || f.RuleID == "nuclei.git-config" {
			foundNucleiGitFinding = true
		}
	}

	assert.True(t, foundSourceMapFinding, "State B must emit frontend.public_source_map finding")
	assert.True(t, foundNucleiGitFinding, "State B must emit nuclei git config finding")

	// -------------------------------------------------------------
	// Compare State A vs State B via diff.Compare
	// -------------------------------------------------------------
	changes := diff.Compare(&snapA, &snapB)
	require.NotEmpty(t, changes, "diff between State A and State B must not be empty")

	for _, ch := range changes {
		t.Logf("Change: type=%s subject=%s reason=%s", ch.Type, ch.Subject, ch.Reason)
	}

	var foundSourceMapAppeared, foundFindingAppeared, foundNewAsset, foundCSPRemoved bool
	for _, ch := range changes {
		if ch.Type == "frontend.source_map_appeared" {
			foundSourceMapAppeared = true
			assert.Equal(t, model.ImportanceMedium, ch.Importance)
		}
		if ch.Type == "http.security_header_removed" && ch.Subject == "content_security_policy" {
			foundCSPRemoved = true
		}
		if ch.Type == "finding.appeared" && (ch.Subject == server.URL()+"/static/app.js.map" || ch.Subject == server.URL()+"/.git/config") {
			foundFindingAppeared = true
		}
		if ch.Type == "asset.added" {
			foundNewAsset = true
		}
	}

	assert.True(t, foundSourceMapAppeared, "diff must contain frontend.source_map_appeared change")
	assert.True(t, foundCSPRemoved, "diff must contain http.security_header_removed for CSP")
	assert.True(t, foundFindingAppeared, "diff must contain finding.appeared change")
	assert.True(t, foundNewAsset, "diff must contain asset.appeared for newly discovered asset")

	// Verify deterministic sorting of diff changes
	for i := 1; i < len(changes); i++ {
		prev := changes[i-1]
		curr := changes[i]
		if prev.Importance < curr.Importance {
			t.Errorf("changes not sorted by importance descending: %v before %v", prev.Importance, curr.Importance)
		}
	}
}

func TestEndToEndWithCLIExecutable(t *testing.T) {
	// Locate compiled bin/exposureguard
	binPath := filepath.Join("..", "..", "bin", "exposureguard")
	if _, err := os.Stat(binPath); err != nil {
		t.Skip("bin/exposureguard not found, run make build first")
	}

	server := e2e.NewSyntheticServer()
	defer server.Close()

	// State A scan via CLI
	server.SetState(e2e.StateA)
	tmpDir := t.TempDir()
	snapAPath := filepath.Join(tmpDir, "snap_a.json")

	cmdA := exec.Command(binPath, "scan", server.URL(),
		"--allow-private",
		"--mode", "owned",
		"--profile", "standard",
		"--snapshot-out", snapAPath,
		"--format", "json",
	)
	outA, err := cmdA.CombinedOutput()
	require.NoError(t, err, "CLI scan State A failed: %s", string(outA))

	dataA, err := os.ReadFile(snapAPath)
	require.NoError(t, err)
	var snapA model.Snapshot
	require.NoError(t, json.Unmarshal(dataA, &snapA))
	require.NotEmpty(t, snapA.Assets)

	// State B scan via CLI
	server.SetState(e2e.StateB)
	snapBPath := filepath.Join(tmpDir, "snap_b.json")

	cmdB := exec.Command(binPath, "scan", server.URL(),
		"--allow-private",
		"--mode", "owned",
		"--profile", "standard",
		"--snapshot-out", snapBPath,
		"--format", "json",
	)
	outB, err := cmdB.CombinedOutput()
	require.NoError(t, err, "CLI scan State B failed: %s", string(outB))

	dataB, err := os.ReadFile(snapBPath)
	require.NoError(t, err)
	var snapB model.Snapshot
	require.NoError(t, json.Unmarshal(dataB, &snapB))

	// Run diff via CLI
	cmdDiff := exec.Command(binPath, "diff", snapAPath, snapBPath, "--format", "json")
	outDiff, err := cmdDiff.CombinedOutput()
	require.NoError(t, err, "CLI diff failed: %s", string(outDiff))

	var changes []model.Change
	require.NoError(t, json.Unmarshal(outDiff, &changes))
	require.NotEmpty(t, changes, "diff must report changes between State A and State B")

	var foundSourceMapChange bool
	for _, c := range changes {
		if c.Type == "frontend.source_map_appeared" {
			foundSourceMapChange = true
		}
	}
	assert.True(t, foundSourceMapChange, "CLI diff must report frontend.source_map_appeared")
}

func TestSemanticSnapshotDeterminismAndInvariants(t *testing.T) {
	server := e2e.NewSyntheticServer()
	defer server.Close()

	reg := integrations.NewBuiltinRegistry()

	server.SetState(e2e.StateA)

	// Run scan twice to verify bitwise/semantic determinism
	res1 := runPipelineScan(t, server.URL(), reg)
	res2 := runPipelineScan(t, server.URL(), reg)

	snap1 := res1.Snapshot
	snap2 := res2.Snapshot

	require.Equal(t, snap1.SchemaVersion, "1")
	require.Equal(t, snap1.Summary.TotalAssets, len(snap1.Assets))
	require.Equal(t, snap1.Summary.TotalObservations, len(snap1.Observations))
	require.Equal(t, snap1.Summary.TotalFindings, len(snap1.Findings))

	// Invariant: Asset IDs, counts, and kinds match exactly between two runs
	require.Equal(t, len(snap1.Assets), len(snap2.Assets))
	for i := range snap1.Assets {
		assert.Equal(t, snap1.Assets[i].ID, snap2.Assets[i].ID)
		assert.Equal(t, snap1.Assets[i].Kind, snap2.Assets[i].Kind)
		assert.Equal(t, snap1.Assets[i].Value, snap2.Assets[i].Value)
	}

	// Invariant: Observation IDs match
	require.Equal(t, len(snap1.Observations), len(snap2.Observations))
	for i := range snap1.Observations {
		assert.Equal(t, snap1.Observations[i].ID, snap2.Observations[i].ID)
		assert.Equal(t, snap1.Observations[i].Kind, snap2.Observations[i].Kind)
	}

	// Invariant: Diff between identical runs is strictly empty
	changes := diff.Compare(&snap1, &snap2)
	assert.Empty(t, changes, "diff between identical repeated runs must be empty")
}

func TestDockerLocalSemanticParity(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker binary not available on host")
	}

	cmdInspect := exec.Command("docker", "image", "inspect", "exposureguard")
	if err := cmdInspect.Run(); err != nil {
		t.Skip("exposureguard docker image not built, run make docker-build first")
	}

	binPath := filepath.Clean(filepath.Join("..", "..", "bin", "exposureguard"))
	if _, err := os.Stat(binPath); err != nil {
		t.Skip("bin/exposureguard not found, run make build first")
	}

	server := e2e.NewSyntheticServer()
	defer server.Close()

	// Use StateB (contains source map and git exposure)
	server.SetState(e2e.StateB)

	u, err := url.Parse(server.URL())
	require.NoError(t, err)
	port := u.Port()

	tmpDir := t.TempDir()
	localSnapPath := filepath.Join(tmpDir, "local_snap.json")
	dockerSnapPath := filepath.Join(tmpDir, "docker_snap.json")

	// 1. Run local scan
	cmdLocal := exec.Command(binPath, "scan", server.URL(),
		"--allow-private",
		"--mode", "owned",
		"--profile", "standard",
		"--snapshot-out", localSnapPath,
		"--format", "json",
	)
	outLocal, err := cmdLocal.CombinedOutput()
	require.NoError(t, err, "local scan failed: %s", string(outLocal))

	// 2. Run docker scan
	dockerTarget := "http://host.docker.internal:" + port
	cmdDocker := exec.Command("docker", "run", "--rm",
		"-v", tmpDir+":/out",
		"exposureguard", "scan", dockerTarget,
		"--allow-private",
		"--mode", "owned",
		"--profile", "standard",
		"--snapshot-out", "/out/docker_snap.json",
		"--format", "json",
	)
	outDocker, err := cmdDocker.CombinedOutput()
	require.NoError(t, err, "docker scan failed: %s", string(outDocker))

	// 3. Load both snapshots
	dataLocal, err := os.ReadFile(localSnapPath)
	require.NoError(t, err)
	var snapLocal model.Snapshot
	require.NoError(t, json.Unmarshal(dataLocal, &snapLocal))

	dataDocker, err := os.ReadFile(dockerSnapPath)
	require.NoError(t, err)
	var snapDocker model.Snapshot
	require.NoError(t, json.Unmarshal(dataDocker, &snapDocker))

	// 4. Verify semantic parity
	assert.Equal(t, snapLocal.SchemaVersion, snapDocker.SchemaVersion)

	// Both must report the public source map finding
	var localHasSourceMap, dockerHasSourceMap bool
	for _, f := range snapLocal.Findings {
		if f.RuleID == "frontend.public_source_map" {
			localHasSourceMap = true
		}
	}
	for _, f := range snapDocker.Findings {
		if f.RuleID == "frontend.public_source_map" {
			dockerHasSourceMap = true
		}
	}
	assert.True(t, localHasSourceMap, "local scan must detect public source map")
	assert.True(t, dockerHasSourceMap, "docker scan must detect public source map")
	assert.Equal(t, len(snapLocal.Findings), len(snapDocker.Findings), "finding counts must match between local and docker")

	// Verify observation kinds parity (ignoring platform-specific host resolving variations)
	localObsKinds := make(map[string]bool)
	for _, o := range snapLocal.Observations {
		localObsKinds[o.Kind] = true
	}
	dockerObsKinds := make(map[string]bool)
	for _, o := range snapDocker.Observations {
		dockerObsKinds[o.Kind] = true
	}

	for kind := range localObsKinds {
		if kind != "dns_record" { // DNS records differ on host.docker.internal vs 127.0.0.1
			assert.True(t, dockerObsKinds[kind], "observation kind %s should be present in docker scan", kind)
		}
	}
}
