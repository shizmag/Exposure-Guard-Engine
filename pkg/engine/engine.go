package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/exposureguard/exposureguard/pkg/checks"
	dnscheck "github.com/exposureguard/exposureguard/pkg/checks/dns"
	httpcheck "github.com/exposureguard/exposureguard/pkg/checks/http"
	jscheck "github.com/exposureguard/exposureguard/pkg/checks/javascript"
	tlscheck "github.com/exposureguard/exposureguard/pkg/checks/tls"
	"github.com/exposureguard/exposureguard/pkg/crawl"
	"github.com/exposureguard/exposureguard/pkg/diff"
	"github.com/exposureguard/exposureguard/pkg/integration"
	"github.com/exposureguard/exposureguard/pkg/model"
	"github.com/exposureguard/exposureguard/pkg/netguard"
	"github.com/exposureguard/exposureguard/pkg/protocol"
	"github.com/exposureguard/exposureguard/pkg/snapshot"
	"github.com/exposureguard/exposureguard/pkg/target"
)

// Engine orchestrates the outside-in scanning pipeline.
type Engine struct {
	env      *checks.Environment
	events   *protocol.Encoder
	registry *integration.Registry
	runner   integration.Runner
}

// NewEngine creates a new Engine instance using default registry and OS runner.
func NewEngine(env *checks.Environment, events *protocol.Encoder) *Engine {
	return NewEngineWithIntegrations(env, events, integration.DefaultRegistry(), integration.NewOSRunner(""))
}

// NewEngineWithIntegrations initializes an Engine with custom registry and runner.
func NewEngineWithIntegrations(env *checks.Environment, events *protocol.Encoder, reg *integration.Registry, runner integration.Runner) *Engine {
	if reg == nil {
		reg = integration.DefaultRegistry()
	}
	if runner == nil {
		runner = integration.NewOSRunner("")
	}
	return &Engine{
		env:      env,
		events:   events,
		registry: reg,
		runner:   runner,
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

	// Validate required integrations up-front
	for _, reqInt := range req.RequireIntegrations {
		adapter, ok := e.registry.Get(reqInt)
		if !ok {
			return nil, fmt.Errorf("required integration %q is not registered", reqInt)
		}
		inst, err := adapter.Detect(ctx, e.runner)
		if err != nil || !inst.Installed || !inst.Compatible {
			warn := inst.Warning
			if warn == "" && err != nil {
				warn = err.Error()
			}
			return nil, fmt.Errorf("required integration %q is unavailable: %s", reqInt, warn)
		}
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
		candidateHosts  []string
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
	// Integration Stage: Subfinder (Passive Asset Discovery)
	// -----------------------------------------------------------------
	if e.shouldRunIntegration("subfinder", req) && ctx.Err() == nil {
		if subAdapter, ok := e.registry.Get("subfinder"); ok {
			var subAssets []model.Asset
			err := e.runIntegration(ctx, subAdapter, req, tgt, nil, &stats, stageDurations,
				func(as []model.Asset) {
					subAssets = append(subAssets, as...)
					addAssets(as)
				},
				addObservations,
				addFindings,
			)
			if err != nil {
				errorsList = append(errorsList, fmt.Sprintf("subfinder integration failed: %v", err))
			} else {
				// Validate scope and network safety for discovered candidates
				for _, a := range subAssets {
					if a.Kind == model.AssetKindHostname {
						h := strings.ToLower(a.Value)
						if (h == tgt.Domain || strings.HasSuffix(h, "."+tgt.Domain)) && !policy.IsBlockedHostname(h) {
							if !slices.Contains(candidateHosts, h) {
								candidateHosts = append(candidateHosts, h)
							}
						}
					}
				}
			}
		}
	}

	// -----------------------------------------------------------------
	// Integration Stage: httpx (HTTP Probe & Reachability Enrichment)
	// -----------------------------------------------------------------
	if e.shouldRunIntegration("httpx", req) && ctx.Err() == nil {
		if httpxAdapter, ok := e.registry.Get("httpx"); ok {
			probeTargets := candidateHosts
			if len(probeTargets) == 0 {
				probeTargets = []string{tgt.Host}
			}
			err := e.runIntegration(ctx, httpxAdapter, req, tgt, probeTargets, &stats, stageDurations,
				addAssets,
				addObservations,
				addFindings,
			)
			if err != nil {
				errorsList = append(errorsList, fmt.Sprintf("httpx integration failed: %v", err))
			}
		}
	}

	// -----------------------------------------------------------------
	// Stage 4: Crawling (Native or Katana)
	// -----------------------------------------------------------------
	var discoveredJSAssets []model.Asset

	if e.shouldRunIntegration("katana", req) && ctx.Err() == nil {
		// Deep owned crawling via Katana
		if katanaAdapter, ok := e.registry.Get("katana"); ok {
			err := e.runIntegration(ctx, katanaAdapter, req, tgt, nil, &stats, stageDurations,
				func(as []model.Asset) {
					addAssets(as)
					for _, a := range as {
						if a.Kind == model.AssetKindJavaScript {
							discoveredJSAssets = append(discoveredJSAssets, a)
						}
					}
				},
				addObservations,
				addFindings,
			)
			if err != nil {
				errorsList = append(errorsList, fmt.Sprintf("katana crawler failed: %v", err))
			}
		}
	} else if isModuleEnabled("crawl", req.Modules, req.DisableModules) && ctx.Err() == nil {
		// Standard / Quick crawling via native engine
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
	// Stage 5: JavaScript & Source Maps Inspection (Native)
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
	// Integration Stage: Nuclei (Curated Defensive Security Checks)
	// -----------------------------------------------------------------
	if e.shouldRunIntegration("nuclei", req) && ctx.Err() == nil {
		if nucleiAdapter, ok := e.registry.Get("nuclei"); ok {
			err := e.runIntegration(ctx, nucleiAdapter, req, tgt, nil, &stats, stageDurations,
				addAssets,
				addObservations,
				addFindings,
			)
			if err != nil {
				errorsList = append(errorsList, fmt.Sprintf("nuclei integration failed: %v", err))
			}
		}
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

func (e *Engine) shouldRunIntegration(id string, req model.ScanRequest) bool {
	adapter, ok := e.registry.Get(id)
	if !ok {
		return false
	}
	meta := adapter.Metadata()

	// 1. Explicitly required
	if slices.Contains(req.RequireIntegrations, id) {
		return true
	}

	// 2. Explicitly disabled
	if slices.Contains(req.DisableIntegrations, id) {
		return false
	}

	// 3. Global disable
	if strings.EqualFold(req.Integrations, "none") {
		return false
	}

	// 4. Explicit integration selection list
	if req.Integrations != "" && !strings.EqualFold(req.Integrations, "auto") {
		parts := strings.Split(req.Integrations, ",")
		matched := false
		for _, p := range parts {
			if strings.EqualFold(strings.TrimSpace(p), id) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// 5. Scan mode permission
	if !meta.SupportsMode(req.Mode) {
		return false
	}

	// 6. Profile default mapping
	switch strings.ToLower(req.Profile) {
	case "quick":
		return false
	case "standard":
		// standard enables subfinder in public mode; httpx in owned mode
		if id == "subfinder" {
			return true
		}
		if id == "httpx" && req.Mode == model.ScanModeOwned {
			return true
		}
		return false
	case "deep":
		// deep owned enables all tools
		return req.Mode == model.ScanModeOwned
	default:
		// default profile ("website")
		if req.Mode == model.ScanModePublic {
			return id == "subfinder"
		}
		return true
	}
}

type engineEmitter struct {
	addAsset       func([]model.Asset)
	addObservation func([]model.Observation)
	addFinding     func([]model.Finding)
}

func (ee *engineEmitter) EmitAsset(a model.Asset) {
	ee.addAsset([]model.Asset{a})
}

func (ee *engineEmitter) EmitObservation(o model.Observation) {
	ee.addObservation([]model.Observation{o})
}

func (ee *engineEmitter) EmitFinding(f model.Finding) {
	ee.addFinding([]model.Finding{f})
}

func (e *Engine) runIntegration(
	ctx context.Context,
	adapter integration.Adapter,
	req model.ScanRequest,
	tgt model.Target,
	inputHosts []string,
	stats *model.ScanStats,
	stageDurations map[string]time.Duration,
	addAssets func([]model.Asset),
	addObservations func([]model.Observation),
	addFindings func([]model.Finding),
) error {
	id := adapter.ID()

	// 1. Probe installation
	inst, err := adapter.Detect(ctx, e.runner)
	if err != nil || !inst.Installed || !inst.Compatible {
		if slices.Contains(req.RequireIntegrations, id) {
			return fmt.Errorf("required integration %q unavailable: %v", id, err)
		}
		stats.IntegrationsSkipped = append(stats.IntegrationsSkipped, id)
		return nil
	}

	// 2. Prepare isolated working directory
	workDir := filepath.Join(os.TempDir(), "exposureguard", req.ScanID, id)
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return fmt.Errorf("creating work directory failed: %w", err)
	}
	defer func() {
		_ = os.RemoveAll(workDir)
	}()

	intReq := integration.Request{
		Target:     tgt,
		Mode:       req.Mode,
		Profile:    req.Profile,
		WorkDir:    workDir,
		InputHosts: inputHosts,
		Limits:     req.Limits,
		Timeout:    time.Duration(req.Limits.TotalTimeoutSeconds) * time.Second,
	}

	plan, err := adapter.Plan(ctx, intReq)
	if err != nil {
		stats.IntegrationsFailed = append(stats.IntegrationsFailed, id)
		return fmt.Errorf("plan error: %w", err)
	}

	// 3. Execute
	stageKey := "integration." + id
	e.emit(protocol.EventStageStarted, map[string]string{"stage": stageKey})
	sStart := time.Now()

	res, err := e.runner.Run(ctx, plan)
	stageDurations[stageKey] = time.Since(sStart)

	if err != nil {
		stats.IntegrationsFailed = append(stats.IntegrationsFailed, id)
		e.emit(protocol.EventStageCompleted, map[string]string{"stage": stageKey, "status": "failed"})
		return fmt.Errorf("execution error: %w", err)
	}
	defer res.Stdout.Close()

	// 4. Parse
	emitter := &engineEmitter{
		addAsset:       addAssets,
		addObservation: addObservations,
		addFinding:     addFindings,
	}

	if err := adapter.Parse(ctx, res.Stdout, emitter); err != nil {
		stats.IntegrationsFailed = append(stats.IntegrationsFailed, id)
		e.emit(protocol.EventStageCompleted, map[string]string{"stage": stageKey, "status": "parse_error"})
		return fmt.Errorf("parse error: %w", err)
	}

	stats.IntegrationsRan = append(stats.IntegrationsRan, id)
	e.emit(protocol.EventStageCompleted, map[string]string{"stage": stageKey, "status": "completed"})
	return nil
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
