package static

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAnalyzeJavaScript(t *testing.T) {
	jsCode := `
// Application Bundle
const API_URL = "/api/v1/users";
const GRAPHQL = "/graphql";
const WS_URL = "wss://stream.example.com/live";
const EXTERNAL = "https://cdn.partner.com/sdk.js";
const ignored = "regular text string without api path";

function fetchStats() {
    return fetch("/api/v2/metrics");
}

//# sourceMappingURL=app.js.map
`

	res := AnalyzeJavaScript("https://example.com/app.js", []byte(jsCode))

	assert.Equal(t, "app.js.map", res.SourceMappingURL)

	// Check endpoint candidates
	var endpoints []string
	for _, ep := range res.EndpointCandidates {
		endpoints = append(endpoints, ep.Value)
	}
	assert.Contains(t, endpoints, "/api/v1/users")
	assert.Contains(t, endpoints, "/api/v2/metrics")
	assert.Contains(t, endpoints, "/graphql")
	assert.NotContains(t, endpoints, "regular text string without api path")

	// Check discovered URLs
	assert.Contains(t, res.DiscoveredURLs, "wss://stream.example.com/live")
	assert.Contains(t, res.DiscoveredURLs, "https://cdn.partner.com/sdk.js")
}

func TestValidateSourceMap(t *testing.T) {
	// 1. Valid source map
	validJSON := `{
  "version": 3,
  "file": "app.min.js",
  "sources": ["src/index.ts", "src/auth.ts", "src/api.ts"],
  "sourcesContent": ["const x = 1;", "export const auth = {};", "export const api = {};"],
  "mappings": "AAAA,IAAMA,EAAI,CAAV;AACA,OAAO,MAAMC,EAAO,EAAb"
}`

	meta, valid := ValidateSourceMap([]byte(validJSON))
	require.True(t, valid)
	assert.Equal(t, 3, meta.Version)
	assert.Equal(t, 3, meta.SourceCount)
	assert.True(t, meta.HasContent)
	assert.Contains(t, meta.SampleSources, "src/index.ts")
	assert.NotEmpty(t, meta.Fingerprint)

	// 2. Invalid HTML page returning 200
	htmlDoc := `<!DOCTYPE html><html><body>404 Not Found</body></html>`
	_, valid = ValidateSourceMap([]byte(htmlDoc))
	assert.False(t, valid)

	// 3. Generic JSON without source map fields
	genericJSON := `{"status": "error", "message": "file not found"}`
	_, valid = ValidateSourceMap([]byte(genericJSON))
	assert.False(t, valid)
}
