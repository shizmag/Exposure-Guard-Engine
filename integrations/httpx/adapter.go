package httpx

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/exposureguard/exposureguard/pkg/integration"
)

// Adapter implements the integration.Adapter interface for httpx.
type Adapter struct {
	meta integration.Metadata
}

// NewAdapter creates a new httpx adapter.
func NewAdapter() *Adapter {
	return &Adapter{
		meta: DefaultMetadata(),
	}
}

// ID returns the canonical identifier for httpx.
func (a *Adapter) ID() string {
	return ID
}

// Metadata returns the declarative metadata.
func (a *Adapter) Metadata() integration.Metadata {
	return a.meta
}

// Detect checks if the httpx binary is installed and verifies version compatibility.
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

// Plan prepares the execution plan for probing HTTP targets.
func (a *Adapter) Plan(ctx context.Context, req integration.Request) (integration.ExecutionPlan, error) {
	if !a.meta.SupportsMode(req.Mode) {
		return integration.ExecutionPlan{}, integration.NewError(
			integration.ErrPolicyDenied,
			ID,
			fmt.Sprintf("httpx is restricted to owned scan mode (attempted with %s)", req.Mode),
			nil,
		)
	}

	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 45 * time.Second
	}

	args := []string{
		"-sc",
		"-title",
		"-server",
		"-td",
		"-location",
		"-ct",
		"-cl",
		"-j",
		"-silent",
		"-disable-update-check",
	}

	if req.Limits.MaxConcurrency > 0 {
		args = append(args, "-t", strconv.Itoa(req.Limits.MaxConcurrency))
	}
	if req.Limits.RequestsPerSecondPerHost > 0 {
		args = append(args, "-rl", strconv.Itoa(int(req.Limits.RequestsPerSecondPerHost)))
	}
	if req.Limits.RequestTimeoutSeconds > 0 {
		args = append(args, "-timeout", strconv.Itoa(req.Limits.RequestTimeoutSeconds))
	}

	// Target input handling
	if len(req.InputHosts) > 0 && req.WorkDir != "" {
		listFile := filepath.Join(req.WorkDir, "httpx_targets.txt")
		content := strings.Join(req.InputHosts, "\n") + "\n"
		if err := os.WriteFile(listFile, []byte(content), 0o600); err != nil {
			return integration.ExecutionPlan{}, integration.NewError(
				integration.ErrInternal,
				ID,
				"failed to write httpx target hosts file",
				err,
			)
		}
		args = append(args, "-l", listFile)
	} else if req.Target.URL != "" {
		args = append(args, "-u", req.Target.URL)
	} else if req.Target.Host != "" {
		args = append(args, "-u", req.Target.Host)
	} else {
		return integration.ExecutionPlan{}, integration.NewError(
			integration.ErrInvalidConfig,
			ID,
			"no valid targets provided for httpx probe",
			nil,
		)
	}

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

// Parse extracts assets and observations from httpx JSONL output.
func (a *Adapter) Parse(ctx context.Context, input io.Reader, emit integration.Emitter) error {
	return Parse(ctx, input, emit)
}
