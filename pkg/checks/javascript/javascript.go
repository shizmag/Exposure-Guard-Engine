package javascript

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"

	"github.com/exposureguard/exposureguard/pkg/checks"
	"github.com/exposureguard/exposureguard/pkg/model"
	"github.com/exposureguard/exposureguard/pkg/static"
	"github.com/exposureguard/exposureguard/pkg/target"
)

// Check inspects discovered JavaScript bundles and detects source maps.
type Check struct {
	discoveredJSAssets []model.Asset
}

// NewCheck returns an instantiated JavaScript inspection check.
func NewCheck(jsAssets []model.Asset) *Check {
	return &Check{discoveredJSAssets: jsAssets}
}

func (c *Check) ID() string    { return "frontend.javascript" }
func (c *Check) Name() string  { return "JavaScript Bundles & Source Maps Inspection" }
func (c *Check) Stage() string { return "javascript" }

func (c *Check) Run(ctx context.Context, env *checks.Environment, targetModel model.Target) (checks.Result, error) {
	var result checks.Result
	scope := target.NewScope(targetModel)

	limits := env.Limits
	limits.Clamp()

	maxJSBytes := int64(8 * 1024 * 1024)   // 8 MiB per JS file
	maxMapBytes := int64(10 * 1024 * 1024) // 10 MiB per Source Map
	probedMaps := make(map[string]bool)

	// Filter same-host JS assets to inspect
	var targetJSAssets []model.Asset
	for _, a := range c.discoveredJSAssets {
		if a.Kind == model.AssetKindJavaScript && scope.IsAllowedCrawl(a.Value) {
			targetJSAssets = append(targetJSAssets, a)
		}
	}

	for _, jsAsset := range targetJSAssets {
		if ctx.Err() != nil {
			break
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, jsAsset.Value, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "ExposureGuard/0.1.0 (+https://github.com/exposureguard/exposureguard)")

		resp, err := env.HTTP.Do(req)
		if err != nil {
			continue
		}

		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxJSBytes))
		resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK {
			continue
		}

		// 1. Lexical static analysis
		analysis := static.AnalyzeJavaScript(jsAsset.Value, bodyBytes)

		// Record endpoint candidates as discovered assets
		for _, ep := range analysis.EndpointCandidates {
			epID := fmt.Sprintf("%x", sha256.Sum256([]byte("endpoint:"+ep.Value+":"+jsAsset.Value)))
			ep.ID = epID
			result.Assets = append(result.Assets, ep)
		}

		// Detect credential exposures in JavaScript bundle
		credFindings := static.DetectCredentials(jsAsset.Value, bodyBytes)
		result.Findings = append(result.Findings, credFindings...)

		// 2. Resolve source map candidates (explicit and conservative fallback)
		var candidateMapURLs []string

		baseURL, err := url.Parse(jsAsset.Value)
		if err == nil {
			if analysis.SourceMappingURL != "" {
				// Explicit sourceMappingURL
				if resolved, err := baseURL.Parse(analysis.SourceMappingURL); err == nil {
					candidateMapURLs = append(candidateMapURLs, resolved.String())
				}
			}
			// Conservative fallback: <jsAsset>.map
			fallbackURL := jsAsset.Value + ".map"
			candidateMapURLs = append(candidateMapURLs, fallbackURL)
		}

		// 3. Probe and validate candidate source maps
		for _, mapURL := range candidateMapURLs {
			if probedMaps[mapURL] || !scope.IsAllowedCrawl(mapURL) {
				continue
			}
			probedMaps[mapURL] = true

			mapReq, err := http.NewRequestWithContext(ctx, http.MethodGet, mapURL, nil)
			if err != nil {
				continue
			}
			mapReq.Header.Set("User-Agent", "ExposureGuard/0.1.0 (+https://github.com/exposureguard/exposureguard)")

			mapResp, err := env.HTTP.Do(mapReq)
			if err != nil {
				continue
			}

			mapBytes, err := io.ReadAll(io.LimitReader(mapResp.Body, maxMapBytes))
			mapResp.Body.Close()
			if err != nil || mapResp.StatusCode != http.StatusOK {
				continue
			}

			// Validate real source map schema (rejection of HTML/spa error 200 pages)
			meta, valid := static.ValidateSourceMap(mapBytes)
			if !valid {
				continue
			}

			// Valid real source map detected!
			mapID := fmt.Sprintf("%x", sha256.Sum256([]byte("sourcemap:"+mapURL)))
			result.Assets = append(result.Assets, model.Asset{
				ID:            mapID,
				Kind:          model.AssetKindSourceMap,
				Value:         mapURL,
				URL:           mapURL,
				Source:        jsAsset.Value,
				DiscoveredVia: "source_map_probe",
				Attributes: map[string]string{
					"source_count": fmt.Sprintf("%d", meta.SourceCount),
					"has_content":  fmt.Sprintf("%t", meta.HasContent),
				},
			})

			obsID := fmt.Sprintf("%x", sha256.Sum256([]byte("obs:sourcemap:"+mapURL)))
			result.Observations = append(result.Observations, model.Observation{
				ID:      obsID,
				Kind:    "source_map_detected",
				Scope:   "frontend",
				Subject: mapURL,
				Data: map[string]any{
					"url":          mapURL,
					"js_source":    jsAsset.Value,
					"source_count": meta.SourceCount,
					"has_content":  meta.HasContent,
					"size_bytes":   meta.ContentSize,
					"fingerprint":  meta.Fingerprint,
				},
			})

			findingID := fmt.Sprintf("%x", sha256.Sum256([]byte("finding:frontend.public_source_map:"+mapURL)))
			result.Findings = append(result.Findings, model.Finding{
				ID:          findingID,
				CheckID:     c.ID(),
				RuleID:      "frontend.public_source_map",
				Severity:    model.SeverityMedium,
				Confidence:  model.ConfidenceHigh,
				Title:       "Public Source Map Accessible",
				Description: fmt.Sprintf("Publicly accessible production source map exposes %d source files.", meta.SourceCount),
				Asset:       mapURL,
				Evidence: model.Evidence{
					MapURL:      mapURL,
					Fingerprint: meta.Fingerprint,
					SourceCount: meta.SourceCount,
					HasContent:  meta.HasContent,
					SourcePaths: meta.SampleSources,
					ContentSize: meta.ContentSize,
				},
				Remediation: "Remove public production source maps or restrict access to internal developer environments.",
			})
		}
	}

	// Sort assets deterministically
	sort.Slice(result.Assets, func(i, j int) bool {
		return result.Assets[i].Value < result.Assets[j].Value
	})

	// Sort observations deterministically
	sort.Slice(result.Observations, func(i, j int) bool {
		return result.Observations[i].Subject < result.Observations[j].Subject
	})

	// Sort findings deterministically
	sort.Slice(result.Findings, func(i, j int) bool {
		return result.Findings[i].Asset < result.Findings[j].Asset
	})

	return result, nil
}
