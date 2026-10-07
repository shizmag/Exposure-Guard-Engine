package crawl

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
	"sync"
	"sync/atomic"

	"github.com/exposureguard/exposureguard/pkg/checks"
	"github.com/exposureguard/exposureguard/pkg/model"
	"github.com/exposureguard/exposureguard/pkg/snapshot"
	"github.com/exposureguard/exposureguard/pkg/target"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
)

// VisitedPage records metadata of a crawled HTTP response.
type VisitedPage struct {
	URL             string `json:"url"`
	StatusCode      int    `json:"status_code"`
	ContentType     string `json:"content_type"`
	ContentLength   int    `json:"content_length"`
	BodyFingerprint string `json:"body_fingerprint"`
	Depth           int    `json:"depth"`
}

// CrawlResult contains all assets and observations discovered by the crawler.
type CrawlResult struct {
	PagesVisited     []VisitedPage
	DiscoveredAssets []model.Asset
	Observations     []model.Observation
	TotalBytes       int64
}

type queueItem struct {
	u     *url.URL
	depth int
}

// Crawler coordinates bounded BFS crawling of same-host websites.
type Crawler struct {
	env    *checks.Environment
	target model.Target
	scope  target.Scope
}

// NewCrawler constructs a crawler for target.
func NewCrawler(env *checks.Environment, t model.Target) *Crawler {
	return &Crawler{
		env:    env,
		target: t,
		scope:  target.NewScope(t),
	}
}

// Run executes the bounded crawl.
func (c *Crawler) Run(ctx context.Context) (*CrawlResult, error) {
	rootURL, err := url.Parse(c.target.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid root crawl URL: %w", err)
	}

	limits := c.env.Limits
	limits.Clamp()

	rps := limits.RequestsPerSecondPerHost
	if rps <= 0 {
		rps = 2.0
	}
	limiter := rate.NewLimiter(rate.Limit(rps), 2)

	var (
		mu               sync.Mutex
		visitedKeys      = make(map[string]bool)
		pathCounts       = make(map[string]int)
		seenAssetIDs     = make(map[string]bool)
		discoveredAssets []model.Asset
		visitedPages     []VisitedPage
		observations     []model.Observation
		totalDownloaded  atomic.Int64
		pagesCount       atomic.Int32
	)

	addAsset := func(a model.Asset) {
		mu.Lock()
		defer mu.Unlock()
		if len(discoveredAssets) >= limits.MaxAssets {
			return
		}
		if !seenAssetIDs[a.ID] {
			seenAssetIDs[a.ID] = true
			discoveredAssets = append(discoveredAssets, a)
		}
	}

	queue := []queueItem{{u: rootURL, depth: 0}}
	visitedKeys[CrawlKey(rootURL)] = true

	// Concurrency worker pool using errgroup
	conc := limits.MaxConcurrency
	if conc <= 0 {
		conc = 8
	}

	for len(queue) > 0 {
		if ctx.Err() != nil {
			break
		}
		if int(pagesCount.Load()) >= limits.MaxPages {
			break
		}
		if totalDownloaded.Load() >= limits.MaxTotalDownloadBytes {
			break
		}

		currentBatch := queue
		queue = nil

		g, gCtx := errgroup.WithContext(ctx)
		g.SetLimit(conc)

		var nextMu sync.Mutex
		var nextQueue []queueItem

		for _, item := range currentBatch {
			item := item
			if int(pagesCount.Load()) >= limits.MaxPages || totalDownloaded.Load() >= limits.MaxTotalDownloadBytes {
				break
			}

			g.Go(func() error {
				if gCtx.Err() != nil {
					return nil
				}
				if totalDownloaded.Load() >= limits.MaxTotalDownloadBytes {
					return nil
				}
				if int(pagesCount.Add(1)) > limits.MaxPages {
					return nil
				}

				// Rate limiting per host
				if err := limiter.Wait(gCtx); err != nil {
					return nil
				}

				req, err := http.NewRequestWithContext(gCtx, http.MethodGet, item.u.String(), nil)
				if err != nil {
					return nil
				}
				req.Header.Set("User-Agent", "ExposureGuard/0.1.0 (+https://github.com/exposureguard/exposureguard)")

				resp, err := c.env.HTTP.Do(req)
				if err != nil {
					return nil
				}
				defer resp.Body.Close()

				limitReader := io.LimitReader(resp.Body, limits.MaxResponseBytes)
				bodyBytes, err := io.ReadAll(limitReader)
				if err != nil {
					return nil
				}

				downloadedNow := totalDownloaded.Add(int64(len(bodyBytes)))

				bodyHash := sha256.Sum256(bodyBytes)
				bodyFp := hex.EncodeToString(bodyHash[:])

				page := VisitedPage{
					URL:             item.u.String(),
					StatusCode:      resp.StatusCode,
					ContentType:     resp.Header.Get("Content-Type"),
					ContentLength:   len(bodyBytes),
					BodyFingerprint: bodyFp,
					Depth:           item.depth,
				}

				mu.Lock()
				visitedPages = append(visitedPages, page)

				obsData := map[string]any{
					"url": page.URL, "status_code": page.StatusCode, "content_type": page.ContentType,
					"content_length": page.ContentLength, "body_fingerprint": page.BodyFingerprint, "depth": page.Depth,
				}
				obsID := snapshot.ComputeObservationID("crawled_page", item.u.String(), obsData)
				observations = append(observations, model.Observation{
					ID: obsID, Kind: "crawled_page", Scope: "crawl", Subject: item.u.String(), Data: obsData,
				})
				mu.Unlock()

				// If not HTML or depth reached max, don't parse links
				contentType := strings.ToLower(resp.Header.Get("Content-Type"))
				if !strings.Contains(contentType, "text/html") && !strings.Contains(contentType, "application/xhtml+xml") {
					return nil
				}

				// Extract links, scripts, assets
				extraction, err := ExtractHTML(item.u, bodyBytes, c.scope)
				if err != nil {
					return nil
				}

				// Process JS assets
				for _, jsURL := range extraction.JavaScriptURLs {
					jsStr := jsURL.String()
					jsID := snapshot.ComputeAssetID(model.AssetKindJavaScript, jsStr)
					addAsset(model.Asset{
						ID:            jsID,
						Kind:          model.AssetKindJavaScript,
						Value:         jsStr,
						URL:           jsStr,
						Source:        item.u.String(),
						DiscoveredVia: "html_script_tag",
					})
				}

				// Process External References
				for _, extRef := range extraction.ExternalReferences {
					extID := snapshot.ComputeAssetID(model.AssetKindExternal, extRef)
					addAsset(model.Asset{
						ID:            extID,
						Kind:          model.AssetKindExternal,
						Value:         extRef,
						URL:           extRef,
						Source:        item.u.String(),
						DiscoveredVia: "html_link",
					})
				}

				// Enqueue crawl candidates if within max depth
				if item.depth < limits.MaxDepth && downloadedNow < limits.MaxTotalDownloadBytes {
					nextMu.Lock()
					defer nextMu.Unlock()

					for _, cand := range extraction.CrawlCandidates {
						ck := CrawlKey(cand)
						mu.Lock()
						pCount := pathCounts[cand.Path]
						alreadyVisited := visitedKeys[ck]
						if !alreadyVisited && pCount < 10 {
							visitedKeys[ck] = true
							pathCounts[cand.Path] = pCount + 1
							mu.Unlock()
							nextQueue = append(nextQueue, queueItem{
								u:     cand,
								depth: item.depth + 1,
							})
						} else {
							mu.Unlock()
						}
					}
				}

				return nil
			})
		}

		_ = g.Wait()
		queue = nextQueue
	}

	// Sort assets deterministically
	sort.Slice(discoveredAssets, func(i, j int) bool {
		return discoveredAssets[i].Value < discoveredAssets[j].Value
	})

	// Sort observations deterministically
	sort.Slice(observations, func(i, j int) bool {
		return observations[i].Subject < observations[j].Subject
	})

	return &CrawlResult{
		PagesVisited:     visitedPages,
		DiscoveredAssets: discoveredAssets,
		Observations:     observations,
		TotalBytes:       totalDownloaded.Load(),
	}, nil
}
