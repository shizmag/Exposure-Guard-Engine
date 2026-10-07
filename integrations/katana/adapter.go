package katana

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/exposureguard/exposureguard/pkg/integration"
)

// Adapter implements the integration.Adapter interface for Katana.
type Adapter struct {
	meta integration.Metadata
}

// NewAdapter creates a new Katana adapter.
func NewAdapter() *Adapter {
	return &Adapter{
		meta: DefaultMetadata(),
	}
}

// ID returns the canonical identifier for Katana.
func (a *Adapter) ID() string {
	return ID
}

// Metadata returns the declarative metadata.
func (a *Adapter) Metadata() integration.Metadata {
	return a.meta
}

// Detect checks if the Katana binary is installed and verifies version compatibility.
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

// Plan prepares the execution plan for bounded deep crawling.
func (a *Adapter) Plan(ctx context.Context, req integration.Request) (integration.ExecutionPlan, error) {
	if !a.meta.SupportsMode(req.Mode) {
		return integration.ExecutionPlan{}, integration.NewError(
			integration.ErrPolicyDenied,
			ID,
			fmt.Sprintf("Katana crawler is restricted to owned scan mode (attempted with %s)", req.Mode),
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
			"valid target URL required for crawler",
			nil,
		)
	}

	depth := req.Limits.MaxDepth
	if depth <= 0 {
		depth = 2
	}
	concurrency := min(req.Limits.MaxConcurrency, 4)
	if concurrency <= 0 {
		concurrency = 4
	}
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}

	args := []string{
		"-u", targetURL,
		"-d", strconv.Itoa(depth),
		"-c", strconv.Itoa(concurrency),
		"-jc",
		"-kf", "all",
		"-fs", "dn",
		"-j",
		"-or",
		"-ob",
		"-silent",
		"-duc",
	}

	if req.Limits.RequestsPerSecondPerHost > 0 {
		args = append(args, "-rl", strconv.Itoa(max(1, int(req.Limits.RequestsPerSecondPerHost))))
	}
	if req.Limits.RequestTimeoutSeconds > 0 {
		args = append(args, "-timeout", strconv.Itoa(req.Limits.RequestTimeoutSeconds))
	}
	args = append(args, "-ct", fmt.Sprintf("%ds", int(timeout.Seconds())))

	return integration.ExecutionPlan{
		Command: integration.CommandSpec{
			Binary:         a.meta.Binary,
			Args:           args,
			Timeout:        timeout + 5*time.Second,
			MaxStdoutBytes: 30 * 1024 * 1024,
			MaxStderrBytes: 2 * 1024 * 1024,
		},
		OutputSource: integration.OutputSourceStdout,
	}, nil
}

// Parse extracts assets and observations from Katana JSONL output.
func (a *Adapter) Parse(ctx context.Context, input io.Reader, emit integration.Emitter) error {
	return Parse(ctx, input, "", emit)
}
