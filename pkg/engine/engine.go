package engine

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/exposureguard/exposureguard/pkg/checks"
	dnscheck "github.com/exposureguard/exposureguard/pkg/checks/dns"
	httpcheck "github.com/exposureguard/exposureguard/pkg/checks/http"
	jscheck "github.com/exposureguard/exposureguard/pkg/checks/javascript"
	tlscheck "github.com/exposureguard/exposureguard/pkg/checks/tls"
	"github.com/exposureguard/exposureguard/pkg/crawl"
	"github.com/exposureguard/exposureguard/pkg/diff"
	"github.com/exposureguard/exposureguard/pkg/model"
	"github.com/exposureguard/exposureguard/pkg/netguard"
	"github.com/exposureguard/exposureguard/pkg/protocol"
	"github.com/exposureguard/exposureguard/pkg/snapshot"
	"github.com/exposureguard/exposureguard/pkg/target"
)

// Engine orchestrates the outside-in scanning pipeline.
type Engine struct {
	env    *checks.Environment
	events *protocol.Encoder
}

// NewEngine creates a new Engine instance.
func NewEngine(env *checks.Environment, events *protocol.Encoder) *Engine {
	return &Engine{
		env:    env,
		events: events,
	}
}

// Options passes runtime inputs to the engine execution.
type Options struct {
	Request          model.ScanRequest
	PreviousSnapshot *model.Snapshot
}

// Run executes the full defensive scanning workflow.
func (e *Engine) Run(ctx context.Context, opts Options) (*model.ScanResult, error) {
	start := time.Now().UTC()
	req := opts.Request
	req.Limits.Clamp()

	var errorsList []string

	// 1. Target normalization and scope validation
	tgt, err := target.Parse(req.Target)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", netguard.ErrBlockedScheme, err)
	}

	if e.env == nil {
		e.env = checks.NewEnvironment(nil, nil, req.Limits, e.events)
	}

	policy := e.env.Policy
	if policy == nil {
		policy = netguard.DefaultNetworkPolicy{}
	}

	// Immediate SSRF hostname rejection
	if policy.IsBlockedHostname(tgt.Host) {
		return nil, fmt.Errorf("%w: %s", netguard.ErrBlockedHostname, tgt.Host)
	}

	e.emit(protocol.EventScanStarted, map[string]any{
		"target":  tgt.URL,
		"scan_id": req.ScanID,
		"mode":    req.Mode,
	})

	var (
		allAssets       []model.Asset
		allObservations []model.Observation
		allFindings     []model.Finding
		stats           model.ScanStats
		stageDurations  = make(map[string]time.Duration)
	)

	// Helper to track and emit
	addAssets := func(assets []model.Asset) {
		for _, a := range assets {
			allAssets = append(allAssets, a)
			e.emit(protocol.EventAssetDiscovered, a)
		}
	}
	addObservations := func(obs []model.Observation) {
		for _, o := range obs {
			allObservations = append(allObservations, o)
			e.emit(protocol.EventObservation, o)
		}
	}
	addFindings := func(findings []model.Finding) {
		for _, f := range findings {
			allFindings = append(allFindings, f)
			e.emit(protocol.EventFinding, f)
		}
	}

	// -----------------------------------------------------------------
	// Stage 1: DNS
	// -----------------------------------------------------------------
	if isModuleEnabled("dns", req.Modules, req.DisableModules) && ctx.Err() == nil {
		e.emit(protocol.EventStageStarted, map[string]string{"stage": "dns"})
		sStart := time.Now()
		check := dnscheck.NewCheck()
		res, err := check.Run(ctx, e.env, tgt)
		stageDurations["dns"] = time.Since(sStart)
		if err != nil {
			errorsList = append(errorsList, fmt.Sprintf("dns check failed: %v", err))
		} else {
			addAssets(res.Assets)
			addObservations(res.Observations)
		}
		e.emit(protocol.EventStageCompleted, map[string]string{"stage": "dns"})
	}

	// -----------------------------------------------------------------
	// Stage 2: TLS
	// -----------------------------------------------------------------
	if isModuleEnabled("tls", req.Modules, req.DisableModules) && ctx.Err() == nil && (tgt.Scheme == "https" || tgt.Port == 443) {
		e.emit(protocol.EventStageStarted, map[string]string{"stage": "tls"})
		sStart := time.Now()
		check := tlscheck.NewCheck()
		res, err := check.Run(ctx, e.env, tgt)
		stageDurations["tls"] = time.Since(sStart)
		if err != nil {
			errorsList = append(errorsList, fmt.Sprintf("tls check failed: %v", err))
		} else {
			addObservations(res.Observations)
			addFindings(res.Findings)
		}
		e.emit(protocol.EventStageCompleted, map[string]string{"stage": "tls"})
	}

	// -----------------------------------------------------------------
	// Stage 3: HTTP Root, Headers, Cookies, Well-Known
	// -----------------------------------------------------------------
	if isModuleEnabled("http", req.Modules, req.DisableModules) && ctx.Err() == nil {
		e.emit(protocol.EventStageStarted, map[string]string{"stage": "http"})
		sStart := time.Now()
		check := httpcheck.NewCheck()
		res, err := check.Run(ctx, e.env, tgt)
		stageDurations["http"] = time.Since(sStart)
		if err != nil {
			errorsList = append(errorsList, fmt.Sprintf("http check failed: %v", err))
		} else {
			addAssets(res.Assets)
			addObservations(res.Observations)
			addFindings(res.Findings)
		}
		e.emit(protocol.EventStageCompleted, map[string]string{"stage": "http"})
	}

	// -----------------------------------------------------------------
	// Stage 4: Bounded Crawl
	// -----------------------------------------------------------------
	var discoveredJSAssets []model.Asset
	if isModuleEnabled("crawl", req.Modules, req.DisableModules) && ctx.Err() == nil {
		e.emit(protocol.EventStageStarted, map[string]string{"stage": "crawl"})
		sStart := time.Now()
		crawler := crawl.NewCrawler(e.env, tgt)
		crawlRes, err := crawler.Run(ctx)
		stageDurations["crawl"] = time.Since(sStart)
		if err != nil {
			errorsList = append(errorsList, fmt.Sprintf("crawl failed: %v", err))
		} else {
			stats.PagesCrawled = len(crawlRes.PagesVisited)
			stats.BytesDownloaded += crawlRes.TotalBytes
			addAssets(crawlRes.DiscoveredAssets)
			addObservations(crawlRes.Observations)

			for _, a := range crawlRes.DiscoveredAssets {
				if a.Kind == model.AssetKindJavaScript {
					discoveredJSAssets = append(discoveredJSAssets, a)
				}
			}
		}
		e.emit(protocol.EventStageCompleted, map[string]string{"stage": "crawl"})
	}

	// -----------------------------------------------------------------
	// Stage 5: JavaScript & Source Maps Inspection
	// -----------------------------------------------------------------
	if isModuleEnabled("javascript", req.Modules, req.DisableModules) && ctx.Err() == nil && len(discoveredJSAssets) > 0 {
		e.emit(protocol.EventStageStarted, map[string]string{"stage": "javascript"})
		sStart := time.Now()
		check := jscheck.NewCheck(discoveredJSAssets)
		res, err := check.Run(ctx, e.env, tgt)
		stageDurations["javascript"] = time.Since(sStart)
		if err != nil {
			errorsList = append(errorsList, fmt.Sprintf("javascript inspection failed: %v", err))
		} else {
			stats.JSFilesAnalyzed = len(discoveredJSAssets)
			addAssets(res.Assets)
			addObservations(res.Observations)
			addFindings(res.Findings)

			for _, a := range res.Assets {
				if a.Kind == model.AssetKindSourceMap {
					stats.SourceMapsDetected++
				}
			}
		}
		e.emit(protocol.EventStageCompleted, map[string]string{"stage": "javascript"})
	}

	// -----------------------------------------------------------------
	// Finalization: Snapshot & Diff
	// -----------------------------------------------------------------
	completedAt := time.Now().UTC()
	snap := snapshot.Build(tgt, allAssets, allObservations, allFindings, completedAt)

	var changes []model.Change
	if opts.PreviousSnapshot != nil {
		changes = diff.Compare(opts.PreviousSnapshot, &snap)
		for _, ch := range changes {
			e.emit(protocol.EventChange, ch)
		}
	}

	stats.AssetsDiscovered = len(snap.Assets)
	stats.TotalObservations = len(snap.Observations)
	stats.TotalFindings = len(snap.Findings)
	stats.TotalChanges = len(changes)
	stats.DurationPerStage = stageDurations
	stats.TotalDuration = completedAt.Sub(start)

	status := model.ScanStatusComplete
	if ctx.Err() != nil {
		status = model.ScanStatusFailed
	} else if len(errorsList) > 0 {
		status = model.ScanStatusPartial
	}

	result := &model.ScanResult{
		Status:      status,
		ScanID:      req.ScanID,
		Target:      tgt,
		Snapshot:    snap,
		Changes:     changes,
		Summary:     stats,
		StartedAt:   start,
		CompletedAt: completedAt,
		Errors:      errorsList,
	}

	e.emit(protocol.EventScanSummary, stats)
	if status == model.ScanStatusFailed {
		e.emit(protocol.EventScanFailed, map[string]any{"errors": errorsList})
	} else {
		e.emit(protocol.EventScanCompleted, map[string]any{"status": status, "findings": len(snap.Findings)})
	}

	return result, nil
}

func (e *Engine) emit(eventType protocol.EventType, data any) {
	if e.events != nil {
		_ = e.events.Emit(eventType, data)
	}
}

func isModuleEnabled(mod string, modules, disable []string) bool {
	for _, d := range disable {
		if strings.EqualFold(d, mod) {
			return false
		}
	}
	if len(modules) == 0 {
		return true
	}
	for _, m := range modules {
		if strings.EqualFold(m, mod) {
			return true
		}
	}
	return false
}
