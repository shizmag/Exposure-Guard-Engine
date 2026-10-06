package cli

import (
	"context"
	"fmt"
	"time"

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
				return fmt.Errorf("target argument or --request-json is required")
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

func runScan(_ context.Context, opts *scanOptions) error {
	// Stub until engine pipeline is wired
	fmt.Printf("Scanning target: %s (mode: %s)\n", opts.target, opts.mode)
	return nil
}
