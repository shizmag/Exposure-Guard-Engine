package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/exposureguard/exposureguard/internal/config"
	"github.com/exposureguard/exposureguard/pkg/engine"
	"github.com/exposureguard/exposureguard/pkg/model"
	"github.com/exposureguard/exposureguard/pkg/netguard"
	"github.com/exposureguard/exposureguard/pkg/protocol"
	"github.com/exposureguard/exposureguard/pkg/render/human"
	"github.com/spf13/cobra"
)

type scanOptions struct {
	target           string
	format           string
	output           string
	profile          string
	mode             string
	modules          []string
	disableModules   []string
	timeout          time.Duration
	requestTimeout   time.Duration
	dnsTimeout       time.Duration
	concurrency      int
	perHostConc      int
	rateLimit        float64
	maxDepth         int
	maxPages         int
	maxAssets        int
	maxResponseBytes int64
	maxTotalBytes    int64
	maxRedirects     int
	userAgent        string
	previousSnapshot string
	snapshotOut      string
	requestJSON      string
	logLevel         string
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
	flags.StringVar(&opts.profile, "profile", "website", "scanning profile")
	flags.StringVar(&opts.mode, "mode", "public", "scan mode: public or owned")
	flags.StringSliceVar(&opts.modules, "modules", nil, "comma-separated modules to run")
	flags.StringSliceVar(&opts.disableModules, "disable-module", nil, "modules to disable")

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
			reqBytes, err = io.ReadAll(os.Stdin)
		} else {
			reqBytes, err = os.ReadFile(opts.requestJSON)
		}
		if err != nil {
			return &ExitCodeError{Code: 2, Err: fmt.Errorf("reading request JSON failed: %w", err)}
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

	req.Limits.Clamp()

	// Apply timeout to context
	scanTimeout := time.Duration(req.Limits.TotalTimeoutSeconds) * time.Second
	timeoutCtx, cancel := context.WithTimeout(sigCtx, scanTimeout)
	defer cancel()

	// Setup previous snapshot if provided
	var prevSnap *model.Snapshot
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

	eng := engine.NewEngine(nil, encoder)
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
		return human.Render(outWriter, result, human.Options{NoColor: noColor})
	}
}
