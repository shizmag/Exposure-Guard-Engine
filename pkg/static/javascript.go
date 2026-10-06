package static

import (
	"bytes"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/exposureguard/exposureguard/pkg/model"
	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/js"
)

var (
	sourceMapExplicitRegex = regexp.MustCompile(`(?m)(?:/{2}|/\*)[#@]\s*sourceMappingURL=([^\s*]+)`)
	endpointRegex          = regexp.MustCompile(`^/(?:api|v[0-9]|graphql|auth|user|oauth|webhook|ws|rest)(?:/[a-zA-Z0-9_\-./]*)?$`)
)

// AnalysisResult holds extracted static insights from a JavaScript bundle.
type AnalysisResult struct {
	SourceMappingURL   string
	EndpointCandidates []model.Asset
	DiscoveredURLs     []string
}

// AnalyzeJavaScript inspects raw JS bytes using lexical parsing.
// It never executes JavaScript code.
func AnalyzeJavaScript(jsURL string, content []byte) *AnalysisResult {
	res := &AnalysisResult{}

	// 1. Detect explicit sourceMappingURL comment
	matches := sourceMapExplicitRegex.FindSubmatch(content)
	if len(matches) > 1 {
		rawMapURL := strings.TrimSpace(string(matches[1]))
		rawMapURL = strings.TrimSuffix(rawMapURL, "*/")
		res.SourceMappingURL = strings.TrimSpace(rawMapURL)
	}

	// 2. Lexical token extraction using tdewolff/parse/v2/js
	l := js.NewLexer(parse.NewInput(bytes.NewReader(content)))
	seenEndpoints := make(map[string]bool)
	seenURLs := make(map[string]bool)

	for {
		tt, text := l.Next()
		if tt == js.ErrorToken {
			break
		}

		if tt == js.StringToken || tt == js.TemplateToken {
			val := string(text)
			// Strip quotes or backticks
			if len(val) >= 2 {
				val = val[1 : len(val)-1]
			}
			val = strings.TrimSpace(val)
			if val == "" {
				continue
			}

			// Check for absolute URL
			if strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://") || strings.HasPrefix(val, "ws"+"://") || strings.HasPrefix(val, "wss://") {
				if _, err := url.Parse(val); err == nil {
					if !seenURLs[val] {
						seenURLs[val] = true
						res.DiscoveredURLs = append(res.DiscoveredURLs, val)
					}
				}
				continue
			}

			// Check for relative API endpoint candidate
			if strings.HasPrefix(val, "/") && !strings.HasPrefix(val, "//") {
				if endpointRegex.MatchString(val) {
					if !seenEndpoints[val] {
						seenEndpoints[val] = true
						res.EndpointCandidates = append(res.EndpointCandidates, model.Asset{
							Kind:          model.AssetKindEndpoint,
							Value:         val,
							Source:        jsURL,
							DiscoveredVia: "javascript_bundle_literal",
							Attributes: map[string]string{
								"confidence": "0.8",
							},
						})
					}
				}
			}
		}
	}

	// Sort endpoint candidates deterministically
	sort.Slice(res.EndpointCandidates, func(i, j int) bool {
		return res.EndpointCandidates[i].Value < res.EndpointCandidates[j].Value
	})

	// Sort URLs deterministically
	sort.Strings(res.DiscoveredURLs)

	return res
}
