package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/exposureguard/exposureguard/pkg/checks"
	"github.com/exposureguard/exposureguard/pkg/integration"
	"github.com/exposureguard/exposureguard/pkg/integration/integrationtest"
	"github.com/exposureguard/exposureguard/pkg/model"
	"github.com/exposureguard/exposureguard/pkg/netguard"
	"github.com/exposureguard/exposureguard/pkg/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type enginePermissivePolicy struct{}

func (enginePermissivePolicy) IsBlockedIP(_ netip.Addr) bool   { return false }
func (enginePermissivePolicy) IsBlockedHostname(_ string) bool { return false }

func TestEngineEndToEnd(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("X-Powered-By", "Next.js")
		fmt.Fprintln(w, `
<html>
<body>
    <h1>Welcome</h1>
    <script src="/static/app.js"></script>
</body>
</html>`)
	})

	mux.HandleFunc("/static/app.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(w, `
const api = "/api/v1/auth";
//# sourceMappingURL=/static/app.js.map
`)
	})

	mux.HandleFunc("/static/app.js.map", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{
  "version": 3,
  "sources": ["src/app.tsx"],
  "sourcesContent": ["export const App = () => {};"],
  "mappings": "AAAA;"
}`)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	_, portStr, err := net.SplitHostPort(ts.Listener.Addr().String())
	require.NoError(t, err)
	port, err := strconv.ParseUint(portStr, 10, 16)
	require.NoError(t, err)

	limits := model.DefaultLimits()
	limits.TotalTimeoutSeconds = 10
	limits.RequestTimeoutSeconds = 2

	resolver := netguard.NewSafeResolverWithPolicy(nil, enginePermissivePolicy{})
	transport := netguard.NewSafeTransportWithPolicy(resolver, enginePermissivePolicy{}, limits)
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}

	var jsonlBuf bytes.Buffer
	enc := protocol.NewEncoder(&jsonlBuf, "test-scan-001")

	env := checks.NewEnvironmentWithPolicy(client, resolver, enginePermissivePolicy{}, limits, enc)
	eng := NewEngine(env, enc)

	req := model.ScanRequest{
		SchemaVersion: "1",
		ScanID:        "test-scan-001",
		Target:        ts.URL,
		Profile:       "website",
		Mode:          model.ScanModePublic,
		Limits:        limits,
	}

	res, err := eng.Run(t.Context(), Options{Request: req})
	require.NoError(t, err)
	require.NotNil(t, res)

	assert.Equal(t, model.ScanStatusComplete, res.Status)
	assert.Equal(t, uint16(port), res.Target.Port)
	assert.NotEmpty(t, res.Snapshot.Assets)
	assert.NotEmpty(t, res.Snapshot.Observations)
	assert.NotEmpty(t, res.Snapshot.Findings)

	// Verify streaming JSONL protocol
	lines := strings.Split(strings.TrimSpace(jsonlBuf.String()), "\n")
	assert.Greater(t, len(lines), 5, "JSONL events should be streamed in real-time")

	var firstEvent, lastEvent protocol.Envelope
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &firstEvent))
	require.NoError(t, json.Unmarshal([]byte(lines[len(lines)-1]), &lastEvent))

	assert.Equal(t, protocol.EventScanStarted, firstEvent.Type)
	assert.Equal(t, protocol.EventScanCompleted, lastEvent.Type)
	assert.Equal(t, int64(1), firstEvent.Seq)
}

type mockEngineAdapter struct {
	id   string
	meta integration.Metadata
}

func (m *mockEngineAdapter) ID() string {
	return m.id
}

func (m *mockEngineAdapter) Metadata() integration.Metadata {
	return m.meta
}

func (m *mockEngineAdapter) Detect(ctx context.Context, runner integration.Runner) (integration.Installation, error) {
	return integration.Installation{
		Installed:  true,
		Path:       "/bin/mock",
		Version:    "1.0.0",
		Compatible: true,
	}, nil
}

func (m *mockEngineAdapter) Plan(ctx context.Context, req integration.Request) (integration.ExecutionPlan, error) {
	return integration.ExecutionPlan{
		Command: integration.CommandSpec{
			Binary:  "echo",
			Args:    []string{"mock output"},
			Timeout: 2 * time.Second,
		},
		OutputSource: integration.OutputSourceStdout,
	}, nil
}

func (m *mockEngineAdapter) Parse(ctx context.Context, input io.Reader, emit integration.Emitter) error {
	emit.EmitAsset(model.Asset{
		Kind:   model.AssetKindHostname,
		Value:  "discovered.example.com",
		Source: "mock",
	})
	emit.EmitObservation(model.Observation{
		Kind:    "mock.discovery",
		Subject: "discovered.example.com",
		Data:    map[string]any{"mock": true},
	})
	return nil
}

func TestEngineWithMockIntegration(t *testing.T) {
	reg := integration.NewRegistry()
	mockA := &mockEngineAdapter{
		id: "subfinder",
		meta: integration.Metadata{
			ID:          "subfinder",
			Binary:      "echo",
			DisplayName: "Mock Subfinder",
			Capabilities: []integration.Capability{
				integration.CapabilityAssetDiscovery,
			},
			SupportedModes: []model.ScanMode{model.ScanModePublic, model.ScanModeOwned},
			RiskClass:      integration.RiskClassPassive,
		},
	}
	require.NoError(t, reg.Register(mockA))

	runner := &integrationtest.MockRunner{
		RunFunc: func(ctx context.Context, plan integration.ExecutionPlan) (*integration.RunResult, error) {
			return &integration.RunResult{
				ExitCode: 0,
				Stdout:   io.NopCloser(strings.NewReader("mock line\n")),
				Duration: 5 * time.Millisecond,
			}, nil
		},
	}

	limits := model.DefaultLimits()
	limits.TotalTimeoutSeconds = 5
	resolver := netguard.NewSafeResolverWithPolicy(nil, enginePermissivePolicy{})
	transport := netguard.NewSafeTransportWithPolicy(resolver, enginePermissivePolicy{}, limits)
	client := &http.Client{Transport: transport, Timeout: 1 * time.Second}

	var jsonlBuf bytes.Buffer
	enc := protocol.NewEncoder(&jsonlBuf, "test-scan-mock")
	env := checks.NewEnvironmentWithPolicy(client, resolver, enginePermissivePolicy{}, limits, enc)
	eng := NewEngineWithIntegrations(env, enc, reg, runner)

	req := model.ScanRequest{
		SchemaVersion: "1",
		ScanID:        "test-scan-mock",
		Target:        "https://example.com",
		Profile:       "standard",
		Mode:          model.ScanModePublic,
		Limits:        limits,
		Integrations:  "subfinder",
	}

	res, err := eng.Run(t.Context(), Options{Request: req})
	require.NoError(t, err)
	require.NotNil(t, res)

	assert.Contains(t, res.Summary.IntegrationsRan, "subfinder")

	// Discovered asset and observation from integration must be present in snapshot
	var foundAsset bool
	for _, a := range res.Snapshot.Assets {
		if a.Value == "discovered.example.com" {
			foundAsset = true
			break
		}
	}
	assert.True(t, foundAsset, "expected mock discovered asset in snapshot")
}

func TestEngineRequireIntegrationMissing(t *testing.T) {
	reg := integration.NewRegistry()
	runner := &integrationtest.MockRunner{}

	limits := model.DefaultLimits()
	limits.TotalTimeoutSeconds = 5
	resolver := netguard.NewSafeResolverWithPolicy(nil, enginePermissivePolicy{})
	transport := netguard.NewSafeTransportWithPolicy(resolver, enginePermissivePolicy{}, limits)
	client := &http.Client{Transport: transport, Timeout: 1 * time.Second}

	env := checks.NewEnvironmentWithPolicy(client, resolver, enginePermissivePolicy{}, limits, nil)
	eng := NewEngineWithIntegrations(env, nil, reg, runner)

	req := model.ScanRequest{
		SchemaVersion:       "1",
		ScanID:              "test-scan-missing",
		Target:              "https://example.com",
		Profile:             "standard",
		Mode:                model.ScanModePublic,
		Limits:              limits,
		RequireIntegrations: []string{"nonexistent-tool"},
	}

	_, err := eng.Run(t.Context(), Options{Request: req})
	require.Error(t, err, "expected error when required integration is missing")
	assert.Contains(t, err.Error(), "required integration \"nonexistent-tool\" is not registered")
}
