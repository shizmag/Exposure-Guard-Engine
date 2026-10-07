package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/exposureguard/exposureguard/internal/buildinfo"
	"github.com/exposureguard/exposureguard/internal/config"
	"github.com/exposureguard/exposureguard/pkg/checks"
	"github.com/exposureguard/exposureguard/pkg/engine"
	"github.com/exposureguard/exposureguard/pkg/model"
	"github.com/exposureguard/exposureguard/pkg/netguard"
	"github.com/exposureguard/exposureguard/pkg/protocol"
	"github.com/exposureguard/exposureguard/pkg/render/human"
	"github.com/spf13/cobra"
)

func generateScanID() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(raw[:])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
}

type scanOptions struct {
	target              string
	format              string
	output              string
	profile             string
	mode                string
	modules             []string
	disableModules      []string
	integrations        string
	disableIntegrations []string
	requireIntegrations []string
	timeout             time.Duration
	requestTimeout      time.Duration
	dnsTimeout          time.Duration
	concurrency         int
	perHostConc         int
	rateLimit           float64
	maxDepth            int
	maxPages            int
	maxAssets           int
	maxResponseBytes    int64
	maxTotalBytes       int64
	maxRedirects        int
	userAgent           string
	previousSnapshot    string
	snapshotOut         string
	requestJSON         string
	logLevel            string
	allowPrivate        bool
	plan                bool
	quiet               bool
}

func newScanCmd() *cobra.Command {
	opts := &scanOptions{}

	cmd := &cobra.Command{
		Use:   "scan [target]",
		Short: "Perform an outside-in defensive scan of a target website",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				opts.target = args[0]
			}
			if opts.target == "" && opts.requestJSON == "" {
				return &ExitCodeError{Code: 2, Err: fmt.Errorf("target argument or --request-json is required")}
			}
			return runScan(cmd.Context(), opts)
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&opts.format, "format", "human", "output format: human, json, jsonl")
	flags.StringVarP(&opts.output, "output", "o", "", "file path to write results (default stdout)")
	flags.BoolVarP(&opts.quiet, "quiet", "q", false, "display only high-level summary (human mode only)")
	flags.StringVar(&opts.profile, "profile", "standard", "scanning profile (quick, standard, deep)")
	flags.StringVar(&opts.mode, "mode", "public", "scan authorization mode: public (safe, non-intrusive) or owned (caller declares authorization for extended active discovery)")
	flags.BoolVar(&opts.plan, "plan", false, "preview execution plan without making network requests")
	flags.StringSliceVar(&opts.modules, "modules", nil, "comma-separated modules to run")
	flags.StringSliceVar(&opts.disableModules, "disable-module", nil, "modules to disable")
	flags.StringVar(&opts.integrations, "integrations", "auto", "external integrations: auto, none, or comma-separated list")
	flags.StringSliceVar(&opts.disableIntegrations, "disable-integration", nil, "external integration to disable")
	flags.StringSliceVar(&opts.requireIntegrations, "require-integration", nil, "require specific integration to be available")

	flags.DurationVar(&opts.timeout, "timeout", 120*time.Second, "total scan timeout")
	flags.DurationVar(&opts.requestTimeout, "request-timeout", 10*time.Second, "per-request timeout")
	flags.DurationVar(&opts.dnsTimeout, "dns-timeout", 5*time.Second, "DNS query timeout")

	flags.IntVar(&opts.concurrency, "concurrency", 8, "total concurrent workers")
	flags.IntVar(&opts.perHostConc, "per-host-concurrency", 4, "max concurrency per host")
	flags.Float64Var(&opts.rateLimit, "rate-limit", 2.0, "max requests per second per host")

	flags.IntVar(&opts.maxDepth, "max-depth", 2, "maximum crawl depth")
	flags.IntVar(&opts.maxPages, "max-pages", 100, "maximum HTML pages to crawl")
	flags.IntVar(&opts.maxAssets, "max-assets", 500, "maximum discovered assets")
	flags.Int64Var(&opts.maxResponseBytes, "max-response-bytes", 4*1024*1024, "max single response bytes")
	flags.Int64Var(&opts.maxTotalBytes, "max-total-bytes", 50*1024*1024, "max total downloaded bytes")
	flags.IntVar(&opts.maxRedirects, "max-redirects", 8, "maximum redirect hops")

	flags.StringVar(&opts.userAgent, "user-agent", "", "custom User-Agent string")
	flags.StringVar(&opts.previousSnapshot, "previous-snapshot", "", "path to previous snapshot for diffing")
	flags.StringVar(&opts.snapshotOut, "snapshot-out", "", "path to save generated snapshot")
	flags.StringVar(&opts.requestJSON, "request-json", "", "path or '-' for stdin JSON ScanRequest")
	flags.StringVar(&opts.logLevel, "log-level", "info", "log level: error, warn, info, debug")
	flags.BoolVar(&opts.allowPrivate, "allow-private", false, "allow private and loopback targets for controlled local testing (cloud metadata remains strictly blocked)")

	return cmd
}

func runScan(ctx context.Context, opts *scanOptions) error {
	// Signal handling for graceful termination
	sigCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, _ := config.Load(cfgFile)

	var req model.ScanRequest
	if opts.requestJSON != "" {
		var reqBytes []byte
		var err error
		if opts.requestJSON == "-" {
			reqBytes, err = io.ReadAll(io.LimitReader(os.Stdin, 8<<20+1))
		} else {
			reqBytes, err = os.ReadFile(opts.requestJSON)
		}
		if err != nil {
			return &ExitCodeError{Code: 2, Err: fmt.Errorf("reading request JSON failed: %w", err)}
		}
		if len(reqBytes) > 8<<20 {
			return &ExitCodeError{Code: 2, Err: errors.New("ScanRequest exceeds 8 MiB")}
		}
		if err := json.Unmarshal(reqBytes, &req); err != nil {
			return &ExitCodeError{Code: 2, Err: fmt.Errorf("unmarshaling request JSON failed: %w", err)}
		}
	} else {
		req = model.NewDefaultScanRequest(opts.target)
		req.Profile = opts.profile
		req.Mode = model.ScanMode(opts.mode)
		req.Modules = opts.modules
		req.DisableModules = opts.disableModules
		req.Integrations = opts.integrations
		req.DisableIntegrations = opts.disableIntegrations
		req.RequireIntegrations = opts.requireIntegrations
		req.Limits = cfg.Limits

		// Override with explicit flags if set
		if opts.timeout > 0 {
			req.Limits.TotalTimeoutSeconds = int(opts.timeout.Seconds())
		}
		if opts.requestTimeout > 0 {
			req.Limits.RequestTimeoutSeconds = int(opts.requestTimeout.Seconds())
		}
		if opts.dnsTimeout > 0 {
			req.Limits.DNSTimeoutSeconds = int(opts.dnsTimeout.Seconds())
		}
		if opts.concurrency > 0 {
			req.Limits.MaxConcurrency = opts.concurrency
		}
		if opts.perHostConc > 0 {
			req.Limits.MaxPerHostConcurrency = opts.perHostConc
		}
		if opts.rateLimit > 0 {
			req.Limits.RequestsPerSecondPerHost = opts.rateLimit
		}
		if opts.maxDepth >= 0 {
			req.Limits.MaxDepth = opts.maxDepth
		}
		if opts.maxPages > 0 {
			req.Limits.MaxPages = opts.maxPages
		}
		if opts.maxAssets > 0 {
			req.Limits.MaxAssets = opts.maxAssets
		}
		if opts.maxResponseBytes > 0 {
			req.Limits.MaxResponseBytes = opts.maxResponseBytes
		}
		if opts.maxTotalBytes > 0 {
			req.Limits.MaxTotalDownloadBytes = opts.maxTotalBytes
		}
		if opts.maxRedirects > 0 {
			req.Limits.MaxRedirects = opts.maxRedirects
		}
	}

	if req.ScanID == "" {
		req.ScanID = generateScanID()
	}
	if req.SchemaVersion == "" {
		req.SchemaVersion = buildinfo.ProtocolVersion
	}
	if req.Profile == "" {
		req.Profile = "standard"
	}
	if req.Mode == "" {
		req.Mode = model.ScanModePublic
	}
	if req.Limits.TotalTimeoutSeconds == 0 {
		req.Limits = cfg.Limits
	}
	if req.Integrations == "" {
		req.Integrations = "auto"
	}
	req.Limits.Clamp()

	// Apply timeout to context
	scanTimeout := time.Duration(req.Limits.TotalTimeoutSeconds) * time.Second
	timeoutCtx, cancel := context.WithTimeout(sigCtx, scanTimeout)
	defer cancel()

	// Setup previous snapshot if provided
	prevSnap := req.PreviousSnapshot
	if opts.previousSnapshot != "" {
		pBytes, err := os.ReadFile(opts.previousSnapshot)
		if err != nil {
			return &ExitCodeError{Code: 2, Err: fmt.Errorf("reading previous snapshot failed: %w", err)}
		}
		var ps model.Snapshot
		if err := json.Unmarshal(pBytes, &ps); err != nil {
			return &ExitCodeError{Code: 2, Err: fmt.Errorf("parsing previous snapshot failed: %w", err)}
		}
		prevSnap = &ps
	}

	// Setup output writer
	outWriter := os.Stdout
	if opts.output != "" {
		f, err := os.Create(opts.output)
		if err != nil {
			return &ExitCodeError{Code: 1, Err: fmt.Errorf("creating output file failed: %w", err)}
		}
		defer f.Close()
		outWriter = f
	}

	format := opts.format
	if format == "" {
		format = cfg.Format
	}

	var encoder *protocol.Encoder
	if format == "jsonl" {
		encoder = protocol.NewEncoder(outWriter, req.ScanID)
	}

	var netPolicy netguard.NetworkPolicy = netguard.DefaultNetworkPolicy{}
	if opts.allowPrivate || os.Getenv("EXPOSUREGUARD_ALLOW_PRIVATE") == "true" || os.Getenv("EXPOSUREGUARD_ALLOW_PRIVATE") == "1" {
		netPolicy = netguard.AllowPrivateNetworkPolicy{}
	}

	if opts.plan {
		scanEnv := checks.NewEnvironmentWithPolicy(nil, nil, netPolicy, req.Limits, nil)
		eng := engine.NewEngine(scanEnv, nil)
		plan, err := eng.Plan(req)
		if err != nil {
			return &ExitCodeError{Code: 2, Err: err}
		}

		if strings.EqualFold(format, "json") {
			enc := json.NewEncoder(outWriter)
			enc.SetIndent("", "  ")
			return enc.Encode(plan)
		}
		return renderHumanPlan(outWriter, plan)
	}

	scanEnv := checks.NewEnvironmentWithPolicy(nil, nil, netPolicy, req.Limits, encoder)
	eng := engine.NewEngine(scanEnv, encoder)
	result, err := eng.Run(timeoutCtx, engine.Options{
		Request:          req,
		PreviousSnapshot: prevSnap,
	})

	if err != nil {
		if errors.Is(err, netguard.ErrBlockedIP) ||
			errors.Is(err, netguard.ErrBlockedHostname) ||
			errors.Is(err, netguard.ErrBlockedScheme) {
			return &ExitCodeError{Code: 3, Err: err}
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return &ExitCodeError{Code: 4, Err: err}
		}
		return &ExitCodeError{Code: 1, Err: err}
	}

	if opts.allowPrivate || os.Getenv("EXPOSUREGUARD_ALLOW_PRIVATE") == "true" || os.Getenv("EXPOSUREGUARD_ALLOW_PRIVATE") == "1" {
		result.UnsafePrivateNetworkAccess = true
	}

	// Persist snapshot if requested
	if opts.snapshotOut != "" {
		snapBytes, err := json.MarshalIndent(result.Snapshot, "", "  ")
		if err == nil {
			_ = os.WriteFile(opts.snapshotOut, snapBytes, 0o600)
		}
	}

	// Final render
	switch format {
	case "jsonl":
		// Already streamed in real-time
		return nil
	case "json":
		enc := json.NewEncoder(outWriter)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	default: // human
		return human.Render(outWriter, result, human.Options{NoColor: noColor, Quiet: opts.quiet})
	}
}

func renderHumanPlan(w io.Writer, p *model.ScanPlan) error {
	fmt.Fprintf(w, "\nExposureGuard Scan Plan (Dry Run)\n\n")
	fmt.Fprintf(w, "Target:   %s\n", p.Target)
	fmt.Fprintf(w, "Host:     %s\n", p.Host)
	fmt.Fprintf(w, "Profile:  %s\n", p.Profile)
	fmt.Fprintf(w, "Mode:     %s\n\n", p.Mode)

	fmt.Fprintln(w, "Native Modules:")
	for _, m := range p.NativeModules {
		fmt.Fprintf(w, "  • %s\n", m)
	}

	fmt.Fprintln(w, "\nExternal Integrations:")
	if len(p.Integrations) == 0 {
		fmt.Fprintln(w, "  • none (pure native execution)")
	} else {
		for _, i := range p.Integrations {
			fmt.Fprintf(w, "  • %s\n", i)
		}
	}

	fmt.Fprintln(w, "\nEffective Limits:")
	fmt.Fprintf(w, "  • Total Timeout:          %ds\n", p.Limits.TotalTimeoutSeconds)
	fmt.Fprintf(w, "  • Request Timeout:        %ds\n", p.Limits.RequestTimeoutSeconds)
	fmt.Fprintf(w, "  • Max Concurrency:        %d\n", p.Limits.MaxConcurrency)
	fmt.Fprintf(w, "  • Max Pages:              %d\n", p.Limits.MaxPages)
	fmt.Fprintf(w, "  • Max Depth:              %d\n", p.Limits.MaxDepth)
	fmt.Fprintf(w, "  • Max Assets:             %d\n", p.Limits.MaxAssets)
	fmt.Fprintf(w, "  • Max Response Size:      %d bytes\n", p.Limits.MaxResponseBytes)
	fmt.Fprintf(w, "  • Max Total Download:     %d bytes\n\n", p.Limits.MaxTotalDownloadBytes)

	return nil
}
