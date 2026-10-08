package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/exposureguard/exposureguard/internal/buildinfo"
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
	"github.com/exposureguard/exposureguard/pkg/profile"
	"github.com/exposureguard/exposureguard/pkg/protocol"
	"github.com/exposureguard/exposureguard/pkg/snapshot"
	"github.com/exposureguard/exposureguard/pkg/target"
)

func newScanID() string {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return fmt.Sprintf("scan-%d", time.Now().UnixNano())
	}
	bytes[6] = bytes[6]&0x0f | 0x40
	bytes[8] = bytes[8]&0x3f | 0x80
	hexID := hex.EncodeToString(bytes[:])
	return hexID[:8] + "-" + hexID[8:12] + "-" + hexID[12:16] + "-" + hexID[16:20] + "-" + hexID[20:]
}

// Engine orchestrates the outside-in scanning pipeline.
type Engine struct {
	env            *checks.Environment
	events         *protocol.Encoder
	registry       *integration.Registry
	runner         integration.Runner
	tempRoot       string
	maxConcurrency int
	maxRate        float64
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
	maxConcurrency := 0
	if value := os.Getenv("EXPOSUREGUARD_MAX_CONCURRENCY"); value != "" {
		maxConcurrency, _ = strconv.Atoi(value)
	}
	maxRate := 0.0
	if value := os.Getenv("EXPOSUREGUARD_MAX_RATE_LIMIT"); value != "" {
		maxRate, _ = strconv.ParseFloat(value, 64)
	}
	return &Engine{
		env: env, events: events, registry: reg, runner: runner,
		maxConcurrency: maxConcurrency, maxRate: maxRate,
	}
}

// Options passes runtime inputs to the engine execution.
type Options struct {
	Request                 model.ScanRequest
	PreviousSnapshot        *model.Snapshot
	IncludeResultInTerminal bool
	MaxSnapshotBytes        int64
	TempRoot                string
}

// Plan computes the preview execution plan for a scan request without performing any network traffic.
func (e *Engine) Plan(req model.ScanRequest) (*model.ScanPlan, error) {
	req.Limits.Clamp()

	tgt, err := target.Parse(req.Target)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", netguard.ErrBlockedScheme, err)
	}

	var policy netguard.NetworkPolicy = netguard.DefaultNetworkPolicy{}
	if e.env != nil && e.env.Policy != nil {
		policy = e.env.Policy
	}
	if policy.IsBlockedHostname(tgt.Host) {
		return nil, fmt.Errorf("%w: %s", netguard.ErrBlockedHostname, tgt.Host)
	}

	profDef, err := profile.Resolve(req.Profile)
	if err != nil {
		return nil, err
	}
	req.Profile = string(profDef.ID)
	if profDef.RequiredMode != "" && req.Mode != profDef.RequiredMode {
		return nil, fmt.Errorf("profile %q requires %s mode (current mode: %s)", profDef.ID, profDef.RequiredMode, req.Mode)
	}

	// Calculate enabled native modules
	allNativeCandidates := profDef.NativeChecks
	if len(req.Modules) > 0 {
		allNativeCandidates = req.Modules
	}
	var activeModules []string
	for _, m := range allNativeCandidates {
		if isModuleEnabled(m, allNativeCandidates, req.DisableModules) {
			activeModules = append(activeModules, m)
		}
	}

	// Calculate enabled integrations
	var activeIntegrations []string
	if e.registry != nil {
		for _, adapter := range e.registry.List() {
			id := adapter.ID()
			if e.shouldRunIntegration(id, req) {
				activeIntegrations = append(activeIntegrations, id)
			}
		}
	}

	return &model.ScanPlan{
		Target:        tgt.URL,
		Host:          tgt.Host,
		Scheme:        tgt.Scheme,
		Profile:       req.Profile,
		Mode:          req.Mode,
		NativeModules: activeModules,
		Integrations:  activeIntegrations,
		Limits:        req.Limits,
	}, nil
}

// Run executes the full defensive scanning workflow.
func (e *Engine) Run(ctx context.Context, opts Options) (*model.ScanResult, error) {
	start := time.Now().UTC()
	req := opts.Request
	runEngine := *e
	runEngine.tempRoot = opts.TempRoot
	e = &runEngine
	req.Limits.Clamp()
	if req.ScanID == "" {
		req.ScanID = newScanID()
	}
	if req.SchemaVersion == "" {
		req.SchemaVersion = buildinfo.ProtocolVersion
	}
	if e.maxConcurrency > 0 {
		req.Limits.MaxConcurrency = min(req.Limits.MaxConcurrency, e.maxConcurrency)
	}
	if e.maxRate > 0 {
		req.Limits.RequestsPerSecondPerHost = min(req.Limits.RequestsPerSecondPerHost, e.maxRate)
	}

	if req.ScanID != "" {
		tempRoot := e.tempRoot
		if tempRoot == "" {
			tempRoot = filepath.Join(os.TempDir(), "exposureguard")
		}
		scanTempDir := filepath.Clean(filepath.Join(tempRoot, req.ScanID))
		defer func() {
			_ = os.RemoveAll(scanTempDir)
		}()
	}

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

	// 2. Resolve profile and enforce policy boundaries
	profDef, err := profile.Resolve(req.Profile)
	if err != nil {
		return nil, err
	}
	req.Profile = string(profDef.ID)
	if profDef.RequiredMode != "" && req.Mode != profDef.RequiredMode {
		return nil, fmt.Errorf("profile %q requires %s mode (current mode: %s)", profDef.ID, profDef.RequiredMode, req.Mode)
	}
	if len(req.Modules) == 0 {
		req.Modules = profDef.NativeChecks
	}

	// Validate requested integrations policy and availability up-front
	if req.Integrations != "" && !strings.EqualFold(req.Integrations, "auto") && !strings.EqualFold(req.Integrations, "none") {
		parts := strings.Split(req.Integrations, ",")
		for _, p := range parts {
			id := strings.ToLower(strings.TrimSpace(p))
			if id == "" {
				continue
			}
			adapter, ok := e.registry.Get(id)
			if !ok {
				return nil, fmt.Errorf("requested integration %q is not registered", id)
			}
			meta := adapter.Metadata()
			if !meta.SupportsMode(req.Mode) {
				return nil, fmt.Errorf("integration policy violation: integration %q is not allowed in %s mode (requires mode: %s)", id, req.Mode, formatSupportedModes(meta.SupportedModes))
			}
		}
	}

	for _, reqInt := range req.RequireIntegrations {
		id := strings.ToLower(strings.TrimSpace(reqInt))
		if id == "" {
			continue
		}
		adapter, ok := e.registry.Get(id)
		if !ok {
			return nil, fmt.Errorf("required integration %q is not registered", id)
		}
		meta := adapter.Metadata()
		if !meta.SupportsMode(req.Mode) {
			return nil, fmt.Errorf("integration policy violation: required integration %q is not allowed in %s mode (requires mode: %s)", id, req.Mode, formatSupportedModes(meta.SupportedModes))
		}
		inst, err := adapter.Detect(ctx, e.runner)
		if err != nil || !inst.Installed || !inst.Compatible {
			warn := inst.Warning
			if warn == "" && err != nil {
				warn = err.Error()
			}
			return nil, fmt.Errorf("required integration %q is unavailable: %s", id, warn)
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
		coverageStages  = make(map[string]struct{})
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
	addAssetsFrom := func(stage string, assets []model.Asset) {
		for i := range assets {
			assets[i].Coverage = append(assets[i].Coverage, stage)
		}
		addAssets(assets)
	}
	addObservationsFrom := func(stage string, observations []model.Observation) {
		for i := range observations {
			observations[i].Coverage = append(observations[i].Coverage, stage)
		}
		addObservations(observations)
	}
	addFindingsFrom := func(stage string, findings []model.Finding) {
		for i := range findings {
			findings[i].Coverage = append(findings[i].Coverage, stage)
		}
		addFindings(findings)
	}
	markCoverage := func(stage string) { coverageStages[stage] = struct{}{} }

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
			addAssetsFrom("dns", res.Assets)
			addObservationsFrom("dns", res.Observations)
			markCoverage("dns")
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
			addObservationsFrom("tls", res.Observations)
			addFindingsFrom("tls", res.Findings)
			markCoverage("tls")
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
			addAssetsFrom("http", res.Assets)
			addObservationsFrom("http", res.Observations)
			addFindingsFrom("http", res.Findings)
			markCoverage("http")
		}
		e.emit(protocol.EventStageCompleted, map[string]string{"stage": "http"})
	}

	// -----------------------------------------------------------------
	// Integration Stage: Subfinder (Passive Asset Discovery)
	// -----------------------------------------------------------------
	if e.shouldRunIntegration("subfinder", req) && ctx.Err() == nil {
		if parsedIP, err := netip.ParseAddr(tgt.Host); err == nil && parsedIP.IsValid() {
			// Skip subdomain discovery on IP address targets (IPs cannot have subdomains)
			stats.IntegrationsSkipped = append(stats.IntegrationsSkipped, "subfinder")
		} else if subAdapter, ok := e.registry.Get("subfinder"); ok {
			var subAssets []model.Asset
			err := e.runIntegration(ctx, subAdapter, req, tgt, nil, &stats, stageDurations,
				func(as []model.Asset) {
					subAssets = append(subAssets, as...)
					addAssetsFrom("integration.subfinder", as)
				},
				func(observations []model.Observation) { addObservationsFrom("integration.subfinder", observations) },
				func(findings []model.Finding) { addFindingsFrom("integration.subfinder", findings) },
			)
			if err != nil {
				errorsList = append(errorsList, fmt.Sprintf("subfinder integration failed: %v", err))
			} else {
				if slices.Contains(stats.IntegrationsRan, "subfinder") {
					markCoverage("integration.subfinder")
				}
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
				func(assets []model.Asset) { addAssetsFrom("integration.httpx", assets) },
				func(observations []model.Observation) { addObservationsFrom("integration.httpx", observations) },
				func(findings []model.Finding) { addFindingsFrom("integration.httpx", findings) },
			)
			if err != nil {
				errorsList = append(errorsList, fmt.Sprintf("httpx integration failed: %v", err))
			} else if slices.Contains(stats.IntegrationsRan, "httpx") {
				markCoverage("integration.httpx")
			}
		}
	}

	// -----------------------------------------------------------------
	// Stage 4: Crawling (Native or Katana)
	// -----------------------------------------------------------------
	var discoveredJSAssets []model.Asset
	javascriptDiscoveryComplete := false

	if e.shouldRunIntegration("katana", req) && ctx.Err() == nil {
		// Deep owned crawling via Katana
		if katanaAdapter, ok := e.registry.Get("katana"); ok {
			err := e.runIntegration(ctx, katanaAdapter, req, tgt, nil, &stats, stageDurations,
				func(as []model.Asset) {
					addAssetsFrom("integration.katana", as)
					for _, a := range as {
						if a.Kind == model.AssetKindJavaScript {
							discoveredJSAssets = append(discoveredJSAssets, a)
						}
					}
				},
				func(observations []model.Observation) { addObservationsFrom("integration.katana", observations) },
				func(findings []model.Finding) { addFindingsFrom("integration.katana", findings) },
			)
			if err != nil {
				errorsList = append(errorsList, fmt.Sprintf("katana crawler failed: %v", err))
			} else if slices.Contains(stats.IntegrationsRan, "katana") {
				markCoverage("integration.katana")
				javascriptDiscoveryComplete = true
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
			addAssetsFrom("crawl", crawlRes.DiscoveredAssets)
			addObservationsFrom("crawl", crawlRes.Observations)
			markCoverage("crawl")
			javascriptDiscoveryComplete = true

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
			addAssetsFrom("javascript", res.Assets)
			addObservationsFrom("javascript", res.Observations)
			addFindingsFrom("javascript", res.Findings)
			markCoverage("javascript")

			for _, a := range res.Assets {
				if a.Kind == model.AssetKindSourceMap {
					stats.SourceMapsDetected++
				}
			}
		}
		e.emit(protocol.EventStageCompleted, map[string]string{"stage": "javascript"})
	} else if isModuleEnabled("javascript", req.Modules, req.DisableModules) && ctx.Err() == nil && javascriptDiscoveryComplete && len(discoveredJSAssets) == 0 {
		// A successful discovery stage with no JavaScript inputs is complete
		// negative coverage for source-map analysis; quick profiles do not run
		// discovery and therefore cannot resolve JavaScript findings this way.
		e.emit(protocol.EventStageStarted, map[string]string{"stage": "javascript"})
		stageDurations["javascript"] = 0
		markCoverage("javascript")
		e.emit(protocol.EventStageCompleted, map[string]string{"stage": "javascript", "status": "no_candidates"})
	}

	// -----------------------------------------------------------------
	// Integration Stage: Nuclei (Curated Defensive Security Checks)
	// -----------------------------------------------------------------
	if e.shouldRunIntegration("nuclei", req) && ctx.Err() == nil {
		if nucleiAdapter, ok := e.registry.Get("nuclei"); ok {
			err := e.runIntegration(ctx, nucleiAdapter, req, tgt, nil, &stats, stageDurations,
				func(assets []model.Asset) { addAssetsFrom("integration.nuclei", assets) },
				func(observations []model.Observation) { addObservationsFrom("integration.nuclei", observations) },
				func(findings []model.Finding) { addFindingsFrom("integration.nuclei", findings) },
			)
			if err != nil {
				errorsList = append(errorsList, fmt.Sprintf("nuclei integration failed: %v", err))
			} else if slices.Contains(stats.IntegrationsRan, "nuclei") {
				markCoverage("integration.nuclei")
			}
		}
	}

	// -----------------------------------------------------------------
	// Finalization: Snapshot & Diff
	// -----------------------------------------------------------------
	completedAt := time.Now().UTC()
	coverage := make([]string, 0, len(coverageStages))
	for stage := range coverageStages {
		coverage = append(coverage, stage)
	}
	snap := snapshot.BuildWithCoverage(tgt, allAssets, allObservations, allFindings, completedAt, coverage)

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
		status = model.ScanStatusCancelled
	} else if len(errorsList) > 0 {
		status = model.ScanStatusPartial
	}

	if opts.MaxSnapshotBytes > 0 {
		if encoded, err := json.Marshal(snap); err != nil || int64(len(encoded)) > opts.MaxSnapshotBytes {
			errorsList = append(errorsList, "Snapshot exceeds batch storage budget")
			status = model.ScanStatusFailed
		}
	}
	if ctx.Err() != nil {
		status = model.ScanStatusCancelled
	}
	result := resultForTerminal(status, req.ScanID, tgt, snap, changes, stats, start, completedAt, errorsList)
	if opts.IncludeResultInTerminal {
		if encoded, err := json.Marshal(result); err != nil || int64(len(encoded)) > opts.MaxSnapshotBytes {
			errorsList = append(errorsList, "ScanResult exceeds batch output budget")
			status = model.ScanStatusFailed
			if ctx.Err() != nil {
				status = model.ScanStatusCancelled
			}
			result = resultForTerminal(status, req.ScanID, tgt, snap, changes, stats, start, completedAt, errorsList)
		}
	}

	e.emit(protocol.EventScanSummary, stats)
	if e.events != nil {
		if err := e.events.Error(); err != nil {
			return nil, fmt.Errorf("writing scan event stream failed: %w", err)
		}
	}
	terminalData := map[string]any{"status": status, "findings": len(snap.Findings)}
	if opts.IncludeResultInTerminal {
		terminalData["result"] = result
	}
	if ctx.Err() != nil {
		terminalData["status"] = status
		terminalData["errors"] = errorsList
		e.emit(protocol.EventScanCancelled, terminalData)
	} else if status == model.ScanStatusFailed {
		terminalData["errors"] = errorsList
		e.emit(protocol.EventScanFailed, terminalData)
	} else {
		e.emit(protocol.EventScanCompleted, terminalData)
	}
	if e.events != nil {
		if err := e.events.Error(); err != nil {
			return nil, fmt.Errorf("writing scan terminal event failed: %w", err)
		}
	}

	return result, nil
}

func resultForTerminal(status model.ScanStatus, scanID string, tgt model.Target, snap model.Snapshot, changes []model.Change, stats model.ScanStats, start, completedAt time.Time, errors []string) *model.ScanResult {
	return &model.ScanResult{Status: status, ScanID: scanID, Target: tgt, Snapshot: snap, Changes: changes, Summary: stats, StartedAt: start, CompletedAt: completedAt, Errors: errors}
}

func formatSupportedModes(modes []model.ScanMode) string {
	var strs []string
	for _, m := range modes {
		strs = append(strs, string(m))
	}
	return strings.Join(strs, "/")
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
	profDef, err := profile.Resolve(req.Profile)
	if err != nil {
		return false
	}
	return profDef.SupportsIntegration(id)
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
	if ctx.Err() != nil {
		return ctx.Err()
	}

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
	baseTempDir := filepath.Join(os.TempDir(), "exposureguard")
	if home := integration.DefaultExposureGuardHome(); home != "" {
		baseTempDir = filepath.Join(home, "tmp")
	}
	if e.tempRoot != "" {
		baseTempDir = e.tempRoot
	}
	workDir := filepath.Join(baseTempDir, req.ScanID, id)
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
	if ctx.Err() != nil {
		return ctx.Err()
	}
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
