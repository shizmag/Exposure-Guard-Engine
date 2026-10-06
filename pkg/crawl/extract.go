package crawl

import (
	"bytes"
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/exposureguard/exposureguard/pkg/target"
)

// ExtractionResult holds all URLs and assets extracted from an HTML page.
type ExtractionResult struct {
	CrawlCandidates    []*url.URL
	JavaScriptURLs     []*url.URL
	ExternalReferences []string
	FormActions        []string
}

// ExtractHTML parses raw HTML content and extracts categorized links and assets.
func ExtractHTML(baseURL *url.URL, htmlBody []byte, scope target.Scope) (*ExtractionResult, error) {
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(htmlBody))
	if err != nil {
		return nil, err
	}

	res := &ExtractionResult{}
	seenCrawl := make(map[string]bool)
	seenJS := make(map[string]bool)
	seenExt := make(map[string]bool)

	// Helper to process a link
	processLink := func(rawRef string, isScript bool) {
		resolved, err := CanonicalizeURL(baseURL, rawRef)
		if err != nil || resolved == nil {
			return
		}

		rawStr := resolved.String()
		rel := scope.CheckHostname(resolved.Hostname())

		if isScript {
			if !seenJS[rawStr] {
				seenJS[rawStr] = true
				res.JavaScriptURLs = append(res.JavaScriptURLs, resolved)
			}
			return
		}

		if rel == target.RelationSameHost {
			// Check candidate extension — skip images, media, binaries from crawl queue
			lowerPath := strings.ToLower(resolved.Path)
			if !hasNonHTMLExtension(lowerPath) && !seenCrawl[rawStr] {
				seenCrawl[rawStr] = true
				res.CrawlCandidates = append(res.CrawlCandidates, resolved)
			}
		} else {
			if !seenExt[rawStr] {
				seenExt[rawStr] = true
				res.ExternalReferences = append(res.ExternalReferences, rawStr)
			}
		}
	}

	// 1. <script src>
	doc.Find("script[src]").Each(func(_ int, s *goquery.Selection) {
		if src, exists := s.Attr("src"); exists {
			processLink(src, true)
		}
	})

	// 2. <link rel="preload" as="script"> / <link rel="modulepreload">
	doc.Find("link").Each(func(_ int, s *goquery.Selection) {
		rel, _ := s.Attr("rel")
		as, _ := s.Attr("as")
		href, exists := s.Attr("href")
		if !exists {
			return
		}

		relLower := strings.ToLower(rel)
		if relLower == "modulepreload" || (relLower == "preload" && strings.ToLower(as) == "script") {
			processLink(href, true)
		} else {
			processLink(href, false)
		}
	})

	// 3. <a href>
	doc.Find("a[href]").Each(func(_ int, s *goquery.Selection) {
		if href, exists := s.Attr("href"); exists {
			processLink(href, false)
		}
	})

	// 4. <iframe src>
	doc.Find("iframe[src]").Each(func(_ int, s *goquery.Selection) {
		if src, exists := s.Attr("src"); exists {
			processLink(src, false)
		}
	})

	// 5. <form action> (never submitted, recorded as discovery)
	doc.Find("form[action]").Each(func(_ int, s *goquery.Selection) {
		if action, exists := s.Attr("action"); exists {
			resolved, err := CanonicalizeURL(baseURL, action)
			if err == nil && resolved != nil {
				res.FormActions = append(res.FormActions, resolved.String())
			}
		}
	})

	return res, nil
}

func hasNonHTMLExtension(p string) bool {
	exts := []string{
		".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".bmp",
		".mp4", ".webm", ".mp3", ".wav", ".ogg",
		".pdf", ".zip", ".tar", ".gz", ".7z",
		".woff", ".woff2", ".ttf", ".eot",
		".css",
	}
	for _, ext := range exts {
		if strings.HasSuffix(p, ext) {
			return true
		}
	}
	return false
}
