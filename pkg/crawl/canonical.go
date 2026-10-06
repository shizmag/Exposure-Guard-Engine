package crawl

import (
	"net/url"
	"path"
	"strings"
)

var trackingParams = map[string]bool{
	"utm_source":   true,
	"utm_medium":   true,
	"utm_campaign": true,
	"utm_term":     true,
	"utm_content":  true,
	"fbclid":       true,
	"gclid":        true,
	"gclsrc":       true,
	"dclid":        true,
	"msclkid":      true,
	"mc_cid":       true,
	"mc_eid":       true,
}

// CanonicalizeURL resolves a reference relative to base and normalizes it.
func CanonicalizeURL(base *url.URL, rawRef string) (*url.URL, error) {
	trimmed := strings.TrimSpace(rawRef)
	if trimmed == "" || strings.HasPrefix(trimmed, "javascript:") || strings.HasPrefix(trimmed, "mailto:") || strings.HasPrefix(trimmed, "tel:") {
		return nil, nil
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return nil, err
	}

	resolved := base.ResolveReference(parsed)
	// Lowercase scheme and host
	resolved.Scheme = strings.ToLower(resolved.Scheme)
	resolved.Host = strings.ToLower(resolved.Host)
	// Strip fragment
	resolved.Fragment = ""

	// Normalize default ports
	if (resolved.Scheme == "http" && resolved.Port() == "80") ||
		(resolved.Scheme == "https" && resolved.Port() == "443") {
		resolved.Host = resolved.Hostname()
	}

	// Normalize path dots
	if resolved.Path == "" {
		resolved.Path = "/"
	} else {
		resolved.Path = path.Clean(resolved.Path)
		if strings.HasSuffix(trimmed, "/") && !strings.HasSuffix(resolved.Path, "/") {
			resolved.Path += "/"
		}
	}

	return resolved, nil
}

// CrawlKey produces a deduplication key by removing known tracking parameters.
func CrawlKey(u *url.URL) string {
	clone := *u
	q := clone.Query()
	modified := false
	for k := range q {
		if trackingParams[strings.ToLower(k)] {
			q.Del(k)
			modified = true
		}
	}
	if modified {
		clone.RawQuery = q.Encode()
	}
	return clone.String()
}
