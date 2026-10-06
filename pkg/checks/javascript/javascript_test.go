package javascript

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/exposureguard/exposureguard/pkg/checks"
	"github.com/exposureguard/exposureguard/pkg/model"
	"github.com/exposureguard/exposureguard/pkg/netguard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type jsPermissivePolicy struct{}

func (jsPermissivePolicy) IsBlockedIP(_ netip.Addr) bool { return false }
func (jsPermissivePolicy) IsBlockedHostname(_ string) bool { return false }

func TestJavaScriptCheckWithSourceMap(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/bundle.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(w, `
const api = "/api/v1/billing";
console.log("running app");
//# sourceMappingURL=/bundle.js.map
`)
	})

	mux.HandleFunc("/bundle.js.map", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{
  "version": 3,
  "sources": ["src/billing.ts", "src/secret.ts"],
  "sourcesContent": ["export const pay = () => {};"],
  "mappings": "AAAA;"
}`)
	})

	// Fake fallback test endpoint
	mux.HandleFunc("/fallback.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprintln(w, `console.log("no explicit map comment");`)
	})
	mux.HandleFunc("/fallback.js.map", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{
  "version": 3,
  "sources": ["src/fallback.ts"],
  "mappings": "AAAA;"
}`)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	host, portStr, err := net.SplitHostPort(ts.Listener.Addr().String())
	require.NoError(t, err)
	port, err := strconv.ParseUint(portStr, 10, 16)
	require.NoError(t, err)

	limits := model.DefaultLimits()
	resolver := netguard.NewSafeResolverWithPolicy(nil, jsPermissivePolicy{})
	transport := netguard.NewSafeTransportWithPolicy(resolver, jsPermissivePolicy{}, limits)
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}

	env := checks.NewEnvironmentWithPolicy(client, resolver, jsPermissivePolicy{}, limits, nil)
	targetModel := model.Target{
		Raw:    ts.URL,
		URL:    ts.URL + "/",
		Host:   host,
		Scheme: "http",
		Port:   uint16(port),
	}

	jsAssets := []model.Asset{
		{
			ID:    "js-1",
			Kind:  model.AssetKindJavaScript,
			Value: ts.URL + "/bundle.js",
		},
		{
			ID:    "js-2",
			Kind:  model.AssetKindJavaScript,
			Value: ts.URL + "/fallback.js",
		},
	}

	check := NewCheck(jsAssets)
	res, err := check.Run(t.Context(), env, targetModel)
	require.NoError(t, err)

	// Check findings: both source maps should trigger public_source_map finding
	var foundBundleMap, foundFallbackMap bool
	for _, f := range res.Findings {
		if f.RuleID == "frontend.public_source_map" {
			if f.Asset == ts.URL+"/bundle.js.map" {
				foundBundleMap = true
				assert.Equal(t, model.SeverityMedium, f.Severity)
				assert.Contains(t, f.Evidence.SourcePaths, "src/billing.ts")
			}
			if f.Asset == ts.URL+"/fallback.js.map" {
				foundFallbackMap = true
			}
		}
	}

	assert.True(t, foundBundleMap, "explicit sourceMappingURL finding must be generated")
	assert.True(t, foundFallbackMap, "fallback .map probe finding must be generated")

	// Check endpoint candidate
	var foundEndpoint bool
	for _, a := range res.Assets {
		if a.Kind == model.AssetKindEndpoint && a.Value == "/api/v1/billing" {
			foundEndpoint = true
		}
	}
	assert.True(t, foundEndpoint, "endpoint candidate /api/v1/billing must be discovered")
}
