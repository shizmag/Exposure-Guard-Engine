package http

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/exposureguard/exposureguard/pkg/checks"
	"github.com/exposureguard/exposureguard/pkg/model"
)

// Check performs safe root HTTP probe, security headers evaluation, and cookie metadata analysis.
type Check struct{}

// NewCheck returns an HTTP inspection check.
func NewCheck() *Check {
	return &Check{}
}

func (c *Check) ID() string    { return "http.root" }
func (c *Check) Name() string  { return "HTTP Root & Headers Inspection" }
func (c *Check) Stage() string { return "http" }

// CookieInfo holds non-secret cookie attributes.
type CookieInfo struct {
	Name     string `json:"name"`
	Secure   bool   `json:"secure"`
	HttpOnly bool   `json:"http_only"`
	SameSite string `json:"same_site,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Path     string `json:"path,omitempty"`
}

func (c *Check) Run(ctx context.Context, env *checks.Environment, target model.Target) (checks.Result, error) {
	var result checks.Result

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.URL, nil)
	if err != nil {
		return result, fmt.Errorf("failed to create root HTTP request: %w", err)
	}

	req.Header.Set("User-Agent", "ExposureGuard/0.1.0 (+https://github.com/exposureguard/exposureguard)")

	start := time.Now()
	resp, err := env.HTTP.Do(req)
	duration := time.Since(start)
	if err != nil {
		return result, fmt.Errorf("HTTP root request to %s failed: %w", target.URL, err)
	}
	defer resp.Body.Close()

	// Read body bounded by MaxResponseBytes
	limitReader := io.LimitReader(resp.Body, env.Limits.MaxResponseBytes)
	bodyBytes, err := io.ReadAll(limitReader)
	if err != nil {
		return result, fmt.Errorf("reading response body failed: %w", err)
	}

	bodyHash := sha256.Sum256(bodyBytes)
	bodyFp := hex.EncodeToString(bodyHash[:])

	finalURL := resp.Request.URL.String()

	// 1. HTTP Response Observation
	httpObsData := map[string]any{
		"requested_url":          target.URL,
		"final_url":              finalURL,
		"status_code":            resp.StatusCode,
		"proto":                  resp.Proto,
		"content_type":           resp.Header.Get("Content-Type"),
		"content_length":         len(bodyBytes),
		"body_fingerprint":       bodyFp,
		"response_time_ms":       duration.Milliseconds(),
		"redirected":             finalURL != target.URL,
	}

	httpObsID := fmt.Sprintf("%x", sha256.Sum256([]byte("http:root:"+target.URL)))[:16]
	result.Observations = append(result.Observations, model.Observation{
		ID:      httpObsID,
		Kind:    "http_response",
		Scope:   "http",
		Subject: target.URL,
		Data:    httpObsData,
	})

	// 2. Security Headers Analysis
	headersObs, headerFindings := c.analyzeHeaders(resp.Header, target, finalURL)
	result.Observations = append(result.Observations, headersObs)
	result.Findings = append(result.Findings, headerFindings...)

	// 3. Cookie Metadata Analysis (VALUES STRIPPED)
	cookieObs, cookieFindings := c.analyzeCookies(resp.Cookies(), target)
	result.Observations = append(result.Observations, cookieObs...)
	result.Findings = append(result.Findings, cookieFindings...)

	// 4. Well-Known Public Resources (robots.txt, sitemap.xml, security.txt)
	wellKnownObs, wellKnownAssets := c.probeWellKnown(ctx, env, target)
	result.Observations = append(result.Observations, wellKnownObs...)
	result.Assets = append(result.Assets, wellKnownAssets...)

	return result, nil
}

func (c *Check) analyzeHeaders(header http.Header, target model.Target, finalURL string) (model.Observation, []model.Finding) {
	var findings []model.Finding

	normalized := map[string]string{
		"content_security_policy":              header.Get("Content-Security-Policy"),
		"content_security_policy_report_only":  header.Get("Content-Security-Policy-Report-Only"),
		"strict_transport_security":           header.Get("Strict-Transport-Security"),
		"x_content_type_options":              header.Get("X-Content-Type-Options"),
		"referrer_policy":                     header.Get("Referrer-Policy"),
		"permissions_policy":                  header.Get("Permissions-Policy"),
		"cross_origin_opener_policy":          header.Get("Cross-Origin-Opener-Policy"),
		"cross_origin_embedder_policy":        header.Get("Cross-Origin-Embedder-Policy"),
		"cross_origin_resource_policy":        header.Get("Cross-Origin-Resource-Policy"),
		"server":                              header.Get("Server"),
		"x_powered_by":                        header.Get("X-Powered-By"),
		"cache_control":                       header.Get("Cache-Control"),
	}

	obsData := make(map[string]any)
	for k, v := range normalized {
		if v != "" {
			obsData[k] = v
		}
	}

	obsID := fmt.Sprintf("%x", sha256.Sum256([]byte("headers:"+target.URL)))[:16]
	obs := model.Observation{
		ID:      obsID,
		Kind:    "security_headers",
		Scope:   "http",
		Subject: target.URL,
		Data:    obsData,
	}

	// Finding: Missing HSTS on HTTPS targets
	isHTTPS := target.Scheme == "https" || strings.HasPrefix(finalURL, "https://")
	if isHTTPS && header.Get("Strict-Transport-Security") == "" {
		findings = append(findings, model.Finding{
			ID:          fmt.Sprintf("%x", sha256.Sum256([]byte("finding:http.missing_hsts:"+target.Host)))[:16],
			CheckID:     c.ID(),
			RuleID:      "http.missing_hsts",
			Severity:    model.SeverityLow,
			Confidence:  model.ConfidenceHigh,
			Title:       "Missing Strict-Transport-Security Header",
			Description: "The website serves HTTPS but does not instruct browsers to enforce HTTPS connections via HSTS.",
			Asset:       target.URL,
			Evidence: model.Evidence{
				Headers: map[string]string{"Strict-Transport-Security": ""},
			},
			Remediation: "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header to HTTPS responses.",
		})
	}

	// Finding: Technology disclosure in X-Powered-By
	if xpb := header.Get("X-Powered-By"); xpb != "" {
		findings = append(findings, model.Finding{
			ID:          fmt.Sprintf("%x", sha256.Sum256([]byte("finding:http.technology_disclosure:"+target.Host+":"+xpb)))[:16],
			CheckID:     c.ID(),
			RuleID:      "http.technology_disclosure",
			Severity:    model.SeverityInfo,
			Confidence:  model.ConfidenceHigh,
			Title:       "Server Technology Disclosure via X-Powered-By",
			Description: fmt.Sprintf("Response header discloses underlying backend technology: %s", xpb),
			Asset:       target.URL,
			Evidence: model.Evidence{
				Headers: map[string]string{"X-Powered-By": xpb},
			},
			Remediation: "Disable the X-Powered-By header in your server or framework configuration.",
		})
	}

	return obs, findings
}

func (c *Check) analyzeCookies(cookies []*http.Cookie, target model.Target) ([]model.Observation, []model.Finding) {
	var observations []model.Observation
	var findings []model.Finding

	for _, ck := range cookies {
		sameSite := "Default"
		switch ck.SameSite {
		case http.SameSiteLaxMode:
			sameSite = "Lax"
		case http.SameSiteStrictMode:
			sameSite = "Strict"
		case http.SameSiteNoneMode:
			sameSite = "None"
		}

		info := CookieInfo{
			Name:     ck.Name,
			Secure:   ck.Secure,
			HttpOnly: ck.HttpOnly,
			SameSite: sameSite,
			Domain:   ck.Domain,
			Path:     ck.Path,
		}

		obsID := fmt.Sprintf("%x", sha256.Sum256([]byte("cookie:"+target.Host+":"+ck.Name)))[:16]
		observations = append(observations, model.Observation{
			ID:      obsID,
			Kind:    "cookie_metadata",
			Scope:   "http",
			Subject: ck.Name,
			Data: map[string]any{
				"name":      info.Name,
				"secure":    info.Secure,
				"http_only": info.HttpOnly,
				"same_site": info.SameSite,
				"domain":    info.Domain,
				"path":      info.Path,
			},
		})

		// Check sensitive cookie without Secure flag
		nameLower := strings.ToLower(ck.Name)
		isSensitive := strings.Contains(nameLower, "sess") ||
			strings.Contains(nameLower, "auth") ||
			strings.Contains(nameLower, "token") ||
			strings.Contains(nameLower, "jwt") ||
			strings.Contains(nameLower, "id")

		if target.Scheme == "https" && isSensitive && !ck.Secure {
			findings = append(findings, model.Finding{
				ID:          fmt.Sprintf("%x", sha256.Sum256([]byte("finding:cookie.missing_secure:"+target.Host+":"+ck.Name)))[:16],
				CheckID:     c.ID(),
				RuleID:      "cookie.missing_secure",
				Severity:    model.SeverityMedium,
				Confidence:  model.ConfidenceHigh,
				Title:       fmt.Sprintf("Sensitive Cookie %q Missing Secure Attribute", ck.Name),
				Description: fmt.Sprintf("Cookie %q appears to carry authentication/session data but lacks the Secure attribute.", ck.Name),
				Asset:       target.URL,
				Evidence: model.Evidence{
					Details: map[string]any{"cookie_name": ck.Name},
				},
				Remediation: "Set the 'Secure' attribute on all sensitive cookies transmitted over HTTPS.",
			})
		}
	}

	return observations, findings
}

func (c *Check) probeWellKnown(ctx context.Context, env *checks.Environment, target model.Target) ([]model.Observation, []model.Asset) {
	var observations []model.Observation
	var assets []model.Asset

	paths := []string{
		"/robots.txt",
		"/sitemap.xml",
		"/.well-known/security.txt",
	}

	for _, p := range paths {
		targetURL := strings.TrimSuffix(target.URL, "/") + p
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
		if err != nil {
			continue
		}

		resp, err := env.HTTP.Do(req)
		if err != nil {
			continue
		}

		if resp.StatusCode == http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
			resp.Body.Close()
			obsID := fmt.Sprintf("%x", sha256.Sum256([]byte("wellknown:"+targetURL)))[:16]
			observations = append(observations, model.Observation{
				ID:      obsID,
				Kind:    "well_known_resource",
				Scope:   "http",
				Subject: targetURL,
				Data: map[string]any{
					"path":        p,
					"status_code": resp.StatusCode,
					"size":        len(body),
				},
			})

			// Passive asset extraction from robots.txt / sitemap
			if p == "/robots.txt" {
				extracted := parseRobotsSitemaps(string(body))
				for _, sm := range extracted {
					assetID := fmt.Sprintf("%x", sha256.Sum256([]byte("url:"+sm)))[:16]
					assets = append(assets, model.Asset{
						ID:            assetID,
						Kind:          model.AssetKindURL,
						Value:         sm,
						URL:           sm,
						Source:        "robots.txt",
						DiscoveredVia: "sitemap_directive",
					})
				}
			}
		} else {
			resp.Body.Close()
		}
	}

	// Sort assets deterministically
	sort.Slice(assets, func(i, j int) bool {
		return assets[i].Value < assets[j].Value
	})

	return observations, assets
}

func parseRobotsSitemaps(content string) []string {
	var sitemaps []string
	lines := strings.Split(content, "\n")
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if strings.HasPrefix(strings.ToLower(trimmed), "sitemap:") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				sm := strings.TrimSpace(parts[1])
				if _, err := url.Parse(sm); err == nil && sm != "" {
					sitemaps = append(sitemaps, sm)
				}
			}
		}
	}
	return sitemaps
}
