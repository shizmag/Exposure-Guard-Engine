package crawl

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/exposureguard/exposureguard/pkg/checks"
	"github.com/exposureguard/exposureguard/pkg/model"
	"github.com/exposureguard/exposureguard/pkg/netguard"
	"github.com/exposureguard/exposureguard/pkg/target"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCanonicalizeAndCrawlKey(t *testing.T) {
	base, _ := url.Parse("https://example.com/blog/")

	// 1. Relative link resolution & fragment stripping
	u, err := CanonicalizeURL(base, "post-1#comment")
	require.NoError(t, err)
	assert.Equal(t, "https://example.com/blog/post-1", u.String())

	// 2. Absolute same-host with default port
	u, err = CanonicalizeURL(base, "https://example.com:443/about/")
	require.NoError(t, err)
	assert.Equal(t, "https://example.com/about/", u.String())

	// 3. Javascript: pseudo-protocol ignored
	u, err = CanonicalizeURL(base, "javascript:void(0)")
	require.NoError(t, err)
	assert.Nil(t, u)

	// 4. Tracking parameter removal in CrawlKey
	trackURL, _ := url.Parse("https://example.com/page?id=42&utm_source=twitter&utm_medium=cpc&sort=asc")
	key := CrawlKey(trackURL)
	assert.Contains(t, key, "id=42")
	assert.Contains(t, key, "sort=asc")
	assert.NotContains(t, key, "utm_source")
	assert.NotContains(t, key, "utm_medium")
}

func TestExtractHTML(t *testing.T) {
	baseURL, _ := url.Parse("https://app.example.com/dashboard")
	tgt, _ := target.Parse("https://app.example.com")
	scope := target.NewScope(tgt)

	htmlDoc := `
<!DOCTYPE html>
<html>
<head>
    <script src="/js/vendor.js"></script>
    <link rel="modulepreload" href="/js/app.mjs">
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
    <a href="/profile">Profile</a>
    <a href="https://external-partner.com/docs">Partner Docs</a>
    <a href="/image.png">Logo</a>
    <iframe src="/embedded"></iframe>
    <form action="/api/v1/update"></form>
</body>
</html>
`

	ext, err := ExtractHTML(baseURL, []byte(htmlDoc), scope)
	require.NoError(t, err)

	// Check JS assets
	var jsURLs []string
	for _, j := range ext.JavaScriptURLs {
		jsURLs = append(jsURLs, j.String())
	}
	assert.Contains(t, jsURLs, "https://app.example.com/js/vendor.js")
	assert.Contains(t, jsURLs, "https://app.example.com/js/app.mjs")

	// Check Crawl candidates (image.png must be excluded)
	var crawlURLs []string
	for _, c := range ext.CrawlCandidates {
		crawlURLs = append(crawlURLs, c.String())
	}
	assert.Contains(t, crawlURLs, "https://app.example.com/profile")
	assert.Contains(t, crawlURLs, "https://app.example.com/embedded")
	assert.NotContains(t, crawlURLs, "https://app.example.com/image.png")

	// Check External reference
	assert.Contains(t, ext.ExternalReferences, "https://external-partner.com/docs")

	// Check Form action
	assert.Contains(t, ext.FormActions, "https://app.example.com/api/v1/update")
}

type crawlPermissivePolicy struct{}

func (crawlPermissivePolicy) IsBlockedIP(_ netip.Addr) bool   { return false }
func (crawlPermissivePolicy) IsBlockedHostname(_ string) bool { return false }

func TestCrawlerEndToEnd(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintln(w, `
<html>
<body>
    <a href="/about">About Us</a>
    <a href="/contact">Contact</a>
    <script src="/static/main.js"></script>
</body>
</html>`)
	})

	mux.HandleFunc("/about", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintln(w, `
<html>
<body>
    <p>About company</p>
    <a href="https://twitter.com/exposureguard">Twitter</a>
    <script src="/static/about.js"></script>
</body>
</html>`)
	})

	mux.HandleFunc("/contact", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintln(w, `
<html>
<body>
    <form action="/send-message"></form>
</body>
</html>`)
	})

	mux.HandleFunc("/static/main.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprintln(w, "console.log('main');")
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	host, portStr, err := net.SplitHostPort(ts.Listener.Addr().String())
	require.NoError(t, err)
	port, err := strconv.ParseUint(portStr, 10, 16)
	require.NoError(t, err)

	limits := model.DefaultLimits()
	limits.MaxDepth = 2
	limits.MaxPages = 10

	resolver := netguard.NewSafeResolverWithPolicy(nil, crawlPermissivePolicy{})
	transport := netguard.NewSafeTransportWithPolicy(resolver, crawlPermissivePolicy{}, limits)
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}

	env := checks.NewEnvironmentWithPolicy(client, resolver, crawlPermissivePolicy{}, limits, nil)
	targetModel := model.Target{
		Raw:    ts.URL,
		URL:    ts.URL + "/",
		Host:   host,
		Scheme: "http",
		Port:   uint16(port),
	}

	crawler := NewCrawler(env, targetModel)
	res, err := crawler.Run(t.Context())
	require.NoError(t, err)

	// Verify crawled pages
	assert.GreaterOrEqual(t, len(res.PagesVisited), 3)

	// Verify discovered assets
	var discoveredJS, discoveredExt bool
	for _, a := range res.DiscoveredAssets {
		if a.Kind == model.AssetKindJavaScript && a.Value == ts.URL+"/static/main.js" {
			discoveredJS = true
		}
		if a.Kind == model.AssetKindExternal && a.Value == "https://twitter.com/exposureguard" {
			discoveredExt = true
		}
	}

	assert.True(t, discoveredJS, "JavaScript asset /static/main.js must be discovered")
	assert.True(t, discoveredExt, "External reference twitter.com must be discovered")
}

func TestCrawlerMaxPagesEnforced(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body>`)
		for i := 1; i <= 20; i++ {
			fmt.Fprintf(w, `<a href="/page/%d">Page %d</a> `, i, i)
		}
		fmt.Fprintf(w, `</body></html>`)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	limits := model.DefaultLimits()
	limits.MaxPages = 4
	limits.MaxDepth = 2

	env := checks.NewEnvironmentWithPolicy(ts.Client(), nil, crawlPermissivePolicy{}, limits, nil)
	tgt, _ := target.Parse(ts.URL)

	crawler := NewCrawler(env, tgt)
	res, err := crawler.Run(t.Context())
	require.NoError(t, err)

	assert.LessOrEqual(t, len(res.PagesVisited), 4, "pages crawled must not exceed configured MaxPages budget")
}

func TestCrawlerMaxAssetsEnforced(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><head>`)
		for i := 1; i <= 30; i++ {
			fmt.Fprintf(w, `<script src="/static/app%d.js"></script>`, i)
		}
		fmt.Fprintf(w, `</head><body>Content</body></html>`)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	limits := model.DefaultLimits()
	limits.MaxAssets = 7
	limits.MaxPages = 2

	env := checks.NewEnvironmentWithPolicy(ts.Client(), nil, crawlPermissivePolicy{}, limits, nil)
	tgt, _ := target.Parse(ts.URL)

	crawler := NewCrawler(env, tgt)
	res, err := crawler.Run(t.Context())
	require.NoError(t, err)

	assert.LessOrEqual(t, len(res.DiscoveredAssets), 7, "discovered assets must not exceed MaxAssets limit")
}

func TestCrawlerMaxDepthEnforced(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintln(w, `<a href="/d1">Depth 1</a>`)
	})
	mux.HandleFunc("/d1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintln(w, `<a href="/d2">Depth 2</a>`)
	})
	mux.HandleFunc("/d2", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintln(w, `<a href="/d3">Depth 3</a>`)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	limits := model.DefaultLimits()
	limits.MaxDepth = 1
	limits.MaxPages = 10

	env := checks.NewEnvironmentWithPolicy(ts.Client(), nil, crawlPermissivePolicy{}, limits, nil)
	tgt, _ := target.Parse(ts.URL)

	crawler := NewCrawler(env, tgt)
	res, err := crawler.Run(t.Context())
	require.NoError(t, err)

	for _, p := range res.PagesVisited {
		assert.LessOrEqual(t, p.Depth, 1, "crawled page depth must not exceed MaxDepth")
	}
}

func TestCrawlerCrawlTraps(t *testing.T) {
	mux := http.NewServeMux()

	// 1. Calendar query trap
	mux.HandleFunc("/calendar", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body><a href="/calendar?m=next&nonce=%d">Next Month</a></body></html>`, time.Now().UnixNano())
	})

	// 2. Self link
	mux.HandleFunc("/self", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintln(w, `<html><body><a href="/self">Loop</a></body></html>`)
	})

	// 3. Cyclic paths
	mux.HandleFunc("/dir/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body><a href="%s/sub/">Deeper</a></body></html>`, r.URL.Path)
	})

	// 4. Redirect loop
	mux.HandleFunc("/loop1", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/loop2", http.StatusFound)
	})
	mux.HandleFunc("/loop2", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/loop1", http.StatusFound)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintln(w, `
<html><body>
  <a href="/calendar?m=1">Calendar</a>
  <a href="/self">Self</a>
  <a href="/dir/">Cyclic</a>
  <a href="/loop1">Redirect Loop</a>
</body></html>`)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	limits := model.DefaultLimits()
	limits.MaxDepth = 3
	limits.MaxPages = 15
	limits.TotalTimeoutSeconds = 5

	env := checks.NewEnvironmentWithPolicy(ts.Client(), nil, crawlPermissivePolicy{}, limits, nil)
	tgt, _ := target.Parse(ts.URL)

	crawler := NewCrawler(env, tgt)
	res, err := crawler.Run(t.Context())
	require.NoError(t, err)

	assert.LessOrEqual(t, len(res.PagesVisited), limits.MaxPages, "crawler must remain strictly bounded against traps")
}
