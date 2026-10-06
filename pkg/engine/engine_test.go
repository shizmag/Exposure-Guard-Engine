package engine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/exposureguard/exposureguard/pkg/checks"
	"github.com/exposureguard/exposureguard/pkg/model"
	"github.com/exposureguard/exposureguard/pkg/netguard"
	"github.com/exposureguard/exposureguard/pkg/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type enginePermissivePolicy struct{}

func (enginePermissivePolicy) IsBlockedIP(_ netip.Addr) bool { return false }
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
