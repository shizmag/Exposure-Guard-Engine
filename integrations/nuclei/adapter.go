package nuclei

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/exposureguard/exposureguard/pkg/integration"
)

// Adapter implements the integration.Adapter interface for Nuclei.
type Adapter struct {
	meta   integration.Metadata
	policy CuratedPolicy
}

// NewAdapter creates a new Nuclei adapter with default curated policy.
func NewAdapter() *Adapter {
	return &Adapter{
		meta:   DefaultMetadata(),
		policy: DefaultCuratedPolicy(),
	}
}

// ID returns the canonical identifier for Nuclei.
func (a *Adapter) ID() string {
	return ID
}

// Metadata returns the declarative metadata.
func (a *Adapter) Metadata() integration.Metadata {
	return a.meta
}

// Detect checks if the Nuclei binary is installed and verifies version compatibility.
func (a *Adapter) Detect(ctx context.Context, runner integration.Runner) (integration.Installation, error) {
	path, err := runner.LookPath(a.meta.Binary)
	if err != nil {
		return integration.Installation{
			Installed:  false,
			Compatible: false,
			Warning:    fmt.Sprintf("binary %q not found", a.meta.Binary),
		}, nil
	}

	version, err := runner.DetectVersion(ctx, a.meta.Binary, []string{"-version"})
	if err != nil {
		return integration.Installation{
			Installed:  true,
			Path:       path,
			Compatible: true,
			Warning:    fmt.Sprintf("version detection warning: %v", err),
		}, nil
	}

	compatible := true
	var warning string
	if a.meta.MinimumSupportedVersion != "" && integration.CompareVersions(version, a.meta.MinimumSupportedVersion) < 0 {
		compatible = false
		warning = fmt.Sprintf("detected version %s is below minimum supported version %s", version, a.meta.MinimumSupportedVersion)
	}

	return integration.Installation{
		Installed:  true,
		Path:       path,
		Version:    version,
		Compatible: compatible,
		Warning:    warning,
	}, nil
}

// Plan prepares the execution plan enforcing the curated defensive policy.
func (a *Adapter) Plan(ctx context.Context, req integration.Request) (integration.ExecutionPlan, error) {
	if !a.meta.SupportsMode(req.Mode) {
		return integration.ExecutionPlan{}, integration.NewError(
			integration.ErrPolicyDenied,
			ID,
			fmt.Sprintf("Nuclei is restricted to owned scan mode (attempted with %s)", req.Mode),
			nil,
		)
	}

	targetURL := req.Target.URL
	if targetURL == "" && req.Target.Host != "" {
		targetURL = "https://" + req.Target.Host
	}
	if targetURL == "" {
		return integration.ExecutionPlan{}, integration.NewError(
			integration.ErrInvalidConfig,
			ID,
			"valid target URL required for Nuclei probe",
			nil,
		)
	}

	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}

	args := []string{
		"-u", targetURL,
		"-j",
		"-silent",
		"-duc",
		"-or",
		"-ot",
	}

	// 1. Resolve templates path
	templatesPath := req.TemplatesPath
	if templatesPath == "" {
		templatesPath = resolveDefaultTemplatesPath()
	}
	if templatesPath != "" {
		args = append(args, "-t", templatesPath)
	}

	// 2. Append curated policy flags (tags, protocol filters, no-interactsh)
	args = append(args, a.policy.BuildCLIArgs()...)

	// 3. Concurrency and rate limits
	concurrency := 4
	if req.Limits.MaxConcurrency > 0 && req.Limits.MaxConcurrency < concurrency {
		concurrency = req.Limits.MaxConcurrency
	}
	args = append(args, "-c", strconv.Itoa(concurrency))

	rateLimit := a.policy.MaxRateLimit
	if req.Limits.RequestsPerSecondPerHost > 0 && int(req.Limits.RequestsPerSecondPerHost) < rateLimit {
		rateLimit = int(req.Limits.RequestsPerSecondPerHost)
	}
	args = append(args, "-rl", strconv.Itoa(rateLimit))

	return integration.ExecutionPlan{
		Command: integration.CommandSpec{
			Binary:         a.meta.Binary,
			Args:           args,
			Timeout:        timeout,
			MaxStdoutBytes: 25 * 1024 * 1024,
			MaxStderrBytes: 2 * 1024 * 1024,
		},
		OutputSource: integration.OutputSourceStdout,
	}, nil
}

// Parse extracts observations and findings from Nuclei JSONL output.
func (a *Adapter) Parse(ctx context.Context, input io.Reader, emit integration.Emitter) error {
	return Parse(ctx, input, emit)
}

func resolveDefaultTemplatesPath() string {
	candidates := []string{
		os.Getenv("EXPOSUREGUARD_NUCLEI_TEMPLATES"),
		os.Getenv("NUCLEI_TEMPLATES_PATH"),
		filepath.Join(integration.DefaultExposureGuardHome(), "share", "nuclei-templates"),
		filepath.Join(integration.DefaultExposureGuardHome(), "tools", "nuclei", "templates"),
		"/opt/exposureguard/share/nuclei-templates",
		"/opt/exposureguard/nuclei-templates",
	}

	if userHome, err := os.UserHomeDir(); err == nil && userHome != "" {
		candidates = append(candidates,
			filepath.Join(userHome, "nuclei-templates"),
			filepath.Join(userHome, ".local", "nuclei-templates"),
		)
	}

	for _, c := range candidates {
		if c == "" {
			continue
		}
		if fi, err := os.Stat(c); err == nil && fi.IsDir() {
			return c
		}
	}
	return ""
}
