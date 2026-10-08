package e2e

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/exposureguard/exposureguard/pkg/checks"
	"github.com/exposureguard/exposureguard/pkg/engine"
	"github.com/exposureguard/exposureguard/pkg/integration"
	"github.com/exposureguard/exposureguard/pkg/integration/integrationtest"
	"github.com/exposureguard/exposureguard/pkg/model"
	"github.com/exposureguard/exposureguard/pkg/netguard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCancellationSoakAndTempCleanup(t *testing.T) {
	var cancelFunc context.CancelFunc

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintln(w, `<html><body><a href="/p1">P1</a></body></html>`)
	})
	mux.HandleFunc("/p1", func(w http.ResponseWriter, _ *http.Request) {
		if cancelFunc != nil {
			cancelFunc()
		}
		time.Sleep(50 * time.Millisecond)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintln(w, `<html><body>Done</body></html>`)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	scanID := fmt.Sprintf("soak-test-%d", time.Now().UnixNano())
	tempScanDir := filepath.Clean(filepath.Join(os.TempDir(), "exposureguard", scanID))

	reg := integration.NewRegistry()
	mockAdapter := integrationtest.NewMockAdapter("katana", integration.Metadata{
		ID:             "katana",
		Binary:         "katana",
		SupportedModes: []model.ScanMode{model.ScanModeOwned},
	})
	require.NoError(t, reg.Register(mockAdapter))

	limits := model.DefaultLimits()
	limits.TotalTimeoutSeconds = 30
	limits.MaxPages = 100

	env := checks.NewEnvironmentWithPolicy(
		ts.Client(),
		nil,
		netguard.AllowPrivateNetworkPolicy{},
		limits,
		nil,
	)

	eng := engine.NewEngineWithIntegrations(env, nil, reg, integrationtest.NewMockRunner())

	req := model.ScanRequest{
		ScanID:       scanID,
		Target:       ts.URL,
		Profile:      "standard",
		Mode:         model.ScanModePublic,
		Integrations: "none",
		Limits:       limits,
	}

	// Create a context that is canceled during execution
	ctx, cancel := context.WithCancel(t.Context())
	cancelFunc = cancel

	res, err := eng.Run(ctx, engine.Options{Request: req})
	// Engine may return an error or partial/failed result due to cancellation
	if err != nil {
		assert.ErrorIs(t, ctx.Err(), context.Canceled)
	} else if res != nil {
		assert.Equal(t, model.ScanStatusCancelled, res.Status)
	}

	// Verify temp directory was completely removed after cancellation
	time.Sleep(50 * time.Millisecond)
	_, statErr := os.Stat(tempScanDir)
	assert.True(t, os.IsNotExist(statErr), "temporary directory %s must be completely cleaned up after cancellation", tempScanDir)
}
