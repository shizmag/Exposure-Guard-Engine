package subfinder

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/exposureguard/exposureguard/pkg/integration"
)

// Adapter implements the integration.Adapter interface for Subfinder.
type Adapter struct {
	meta integration.Metadata
}

// NewAdapter creates a new Subfinder adapter.
func NewAdapter() *Adapter {
	return &Adapter{
		meta: DefaultMetadata(),
	}
}

// ID returns the canonical identifier for Subfinder.
func (a *Adapter) ID() string {
	return ID
}

// Metadata returns the declarative metadata.
func (a *Adapter) Metadata() integration.Metadata {
	return a.meta
}

// Detect checks if the Subfinder binary is installed and verifies version compatibility.
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
			Compatible: true, // Installed, but version banner format may differ
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

// Plan prepares the safe execution plan for passive subdomain discovery.
func (a *Adapter) Plan(ctx context.Context, req integration.Request) (integration.ExecutionPlan, error) {
	targetDomain := req.Target.Domain
	if targetDomain == "" {
		targetDomain = req.Target.Host
	}
	if targetDomain == "" {
		return integration.ExecutionPlan{}, integration.NewError(integration.ErrInvalidConfig, ID, "target domain or host is required", nil)
	}

	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 45 * time.Second
	}

	args := []string{
		"-d", targetDomain,
		"-json",
		"-silent",
		"-disable-update-check",
	}

	if req.Limits.RequestsPerSecondPerHost > 0 {
		args = append(args, "-rl", strconv.Itoa(int(req.Limits.RequestsPerSecondPerHost)))
	}

	maxStdout := int64(25 * 1024 * 1024) // 25MB
	maxStderr := int64(2 * 1024 * 1024)  // 2MB

	return integration.ExecutionPlan{
		Command: integration.CommandSpec{
			Binary:         a.meta.Binary,
			Args:           args,
			Timeout:        timeout,
			MaxStdoutBytes: maxStdout,
			MaxStderrBytes: maxStderr,
		},
		OutputSource: integration.OutputSourceStdout,
	}, nil
}

// Parse extracts assets and observations from Subfinder JSONL output.
func (a *Adapter) Parse(ctx context.Context, input io.Reader, emit integration.Emitter) error {
	return Parse(ctx, input, emit)
}

func init() {
	_ = integration.Register(NewAdapter())
}
