package http

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

type permissivePolicy struct{}

func (permissivePolicy) IsBlockedIP(_ netip.Addr) bool   { return false }
func (permissivePolicy) IsBlockedHostname(_ string) bool { return false }

func TestHTTPCheck(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("X-Powered-By", "Express")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		http.SetCookie(w, &http.Cookie{
			Name:     "auth_token",
			Value:    "SUPER_SECRET_SESSION_TOKEN_123",
			Path:     "/",
			HttpOnly: true,
			Secure:   false, // Missing Secure on HTTPS
		})
		fmt.Fprintln(w, "<html><body>Hello World</body></html>")
	})

	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, "User-agent: *")
		fmt.Fprintln(w, "Sitemap: https://example.com/sitemap_index.xml")
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	host, portStr, err := net.SplitHostPort(ts.Listener.Addr().String())
	require.NoError(t, err)
	port, err := strconv.ParseUint(portStr, 10, 16)
	require.NoError(t, err)

	limits := model.DefaultLimits()
	resolver := netguard.NewSafeResolverWithPolicy(nil, permissivePolicy{})
	transport := netguard.NewSafeTransportWithPolicy(resolver, permissivePolicy{}, limits)
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}

	env := checks.NewEnvironment(client, resolver, limits, nil)
	target := model.Target{
		Raw:    ts.URL,
		URL:    ts.URL,
		Host:   host,
		Scheme: "https", // Test HTTPS security assertions
		Port:   uint16(port),
	}

	check := NewCheck()
	res, err := check.Run(t.Context(), env, target)
	require.NoError(t, err)

	// Verify observations
	var foundResp, foundHeaders, foundCookie, foundRobots bool
	for _, obs := range res.Observations {
		switch obs.Kind {
		case "http_response":
			foundResp = true
			assert.Equal(t, 200, obs.Data["status_code"])
			assert.NotEmpty(t, obs.Data["body_fingerprint"])
		case "security_headers":
			foundHeaders = true
			assert.Equal(t, "Express", obs.Data["x_powered_by"])
		case "cookie_metadata":
			foundCookie = true
			assert.Equal(t, "auth_token", obs.Data["name"])
			assert.Equal(t, false, obs.Data["secure"])
			assert.Equal(t, true, obs.Data["http_only"])
			// Verify secret cookie value is strictly excluded
			_, hasValue := obs.Data["value"]
			assert.False(t, hasValue, "cookie value must never be saved in observation")
		case "well_known_resource":
			if obs.Data["path"] == "/robots.txt" {
				foundRobots = true
			}
		}
	}

	assert.True(t, foundResp, "http_response observation must exist")
	assert.True(t, foundHeaders, "security_headers observation must exist")
	assert.True(t, foundCookie, "cookie_metadata observation must exist")
	assert.True(t, foundRobots, "well_known_resource observation must exist")

	// Verify findings
	var foundHSTS, foundTechDisclosure, foundCookieSecure bool
	for _, f := range res.Findings {
		switch f.RuleID {
		case "http.missing_hsts":
			foundHSTS = true
		case "http.technology_disclosure":
			foundTechDisclosure = true
		case "cookie.missing_secure":
			foundCookieSecure = true
		}
	}

	assert.True(t, foundHSTS, "http.missing_hsts finding must be generated")
	assert.True(t, foundTechDisclosure, "http.technology_disclosure finding must be generated")
	assert.True(t, foundCookieSecure, "cookie.missing_secure finding must be generated")

	// Verify assets extracted from robots.txt
	var foundSitemapAsset bool
	for _, a := range res.Assets {
		if a.Value == "https://example.com/sitemap_index.xml" {
			foundSitemapAsset = true
			assert.Equal(t, model.AssetKindURL, a.Kind)
			assert.Equal(t, "robots.txt", a.Source)
		}
	}
	assert.True(t, foundSitemapAsset, "sitemap URL asset must be discovered from robots.txt")
}
