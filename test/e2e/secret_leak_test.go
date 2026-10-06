package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/exposureguard/exposureguard/pkg/checks"
	"github.com/exposureguard/exposureguard/pkg/engine"
	"github.com/exposureguard/exposureguard/pkg/model"
	"github.com/exposureguard/exposureguard/pkg/netguard"
	"github.com/exposureguard/exposureguard/pkg/protocol"
	"github.com/exposureguard/exposureguard/pkg/render/human"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecretLeakageRegressionSuite(t *testing.T) {
	fakeBundlePath := filepath.Clean(filepath.Join("..", "..", "testdata", "secrets", "fake_bundle.js"))
	bundleBytes, err := os.ReadFile(fakeBundlePath)
	require.NoError(t, err)

	// List of known sensitive values that MUST NEVER appear in raw form
	prohibitedPlaintexts := []string{
		"AKIAIOSFODNN7EXAMPLE",
		"ghp_FakeGitHubPersonalAccessToken123456",
		"superSecretPassword987!",
		"FakeSlackTokenABCDEFGHIJKL",
		"SuperSecretUserPass",
		"secretQueryToken12345",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintln(w, `
<!DOCTYPE html>
<html>
<head><title>Test App</title></head>
<body>
  <script src="/static/fake_bundle.js"></script>
  <a href="/api?token=secretQueryToken12345">API Link</a>
</body>
</html>`)
	})

	mux.HandleFunc("/static/fake_bundle.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write(bundleBytes)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	var eventBuf bytes.Buffer
	encoder := protocol.NewEncoder(&eventBuf, "secret-test-scan")

	limits := model.DefaultLimits()
	limits.TotalTimeoutSeconds = 10
	limits.MaxPages = 5

	env := checks.NewEnvironmentWithPolicy(
		ts.Client(),
		nil,
		netguard.AllowPrivateNetworkPolicy{},
		limits,
		encoder,
	)

	eng := engine.NewEngine(env, encoder)
	req := model.ScanRequest{
		ScanID:  "secret-test-scan",
		Target:  ts.URL,
		Profile: "standard",
		Mode:    model.ScanModePublic,
		Limits:  limits,
	}

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	result, err := eng.Run(ctx, engine.Options{Request: req})
	require.NoError(t, err)
	require.NotNil(t, result)

	// 1. Check JSON serialization of ScanResult
	jsonResultBytes, err := json.Marshal(result)
	require.NoError(t, err)
	jsonResultStr := string(jsonResultBytes)

	for _, secret := range prohibitedPlaintexts {
		assert.False(t, strings.Contains(jsonResultStr, secret),
			"CRITICAL LEAK: ScanResult JSON contains plaintext secret: %s", secret)
	}

	// 2. Check JSONL streaming events
	eventsStr := eventBuf.String()
	for _, secret := range prohibitedPlaintexts {
		assert.False(t, strings.Contains(eventsStr, secret),
			"CRITICAL LEAK: JSONL events contain plaintext secret: %s", secret)
	}

	// 3. Check Human formatted render
	var humanBuf bytes.Buffer
	err = human.Render(&humanBuf, result, human.Options{NoColor: true})
	require.NoError(t, err)
	humanStr := humanBuf.String()

	for _, secret := range prohibitedPlaintexts {
		assert.False(t, strings.Contains(humanStr, secret),
			"CRITICAL LEAK: Human output contains plaintext secret: %s", secret)
	}

	// 4. Verify Findings were actually generated (proving detector ran and properly masked)
	assert.NotEmpty(t, result.Snapshot.Findings, "Credential detector should have generated findings")
	var foundCredFinding bool
	for _, f := range result.Snapshot.Findings {
		if f.RuleID == "frontend.credential_exposure" {
			foundCredFinding = true
			assert.NotEmpty(t, f.Evidence.MaskedPreview)
			assert.NotEmpty(t, f.Evidence.Fingerprint)
			// Ensure preview is masked
			assert.Contains(t, f.Evidence.MaskedPreview, "...")
		}
	}
	assert.True(t, foundCredFinding, "At least one frontend.credential_exposure finding must be generated")
}
