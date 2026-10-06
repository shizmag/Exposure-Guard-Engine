// Package example provides a reference adapter skeleton for community contributors.
// This package is NOT imported in the production binary.
package example

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/exposureguard/exposureguard/pkg/integration"
	"github.com/exposureguard/exposureguard/pkg/model"
)

// ExampleAdapter demonstrates how external CLI tools integrate into ExposureGuard.
type ExampleAdapter struct{}

func NewAdapter() *ExampleAdapter {
	return &ExampleAdapter{}
}

func (a *ExampleAdapter) ID() string {
	return "example"
}

func (a *ExampleAdapter) Metadata() integration.Metadata {
	return integration.Metadata{
		ID:          "example",
		DisplayName: "Example Security Probe",
		Description: "Reference skeleton for contributors implementing new adapters",
		Binary:      "example-tool",
		Capabilities: []integration.Capability{
			integration.CapabilityAssetDiscovery,
		},
		SupportedModes: []model.ScanMode{
			model.ScanModeOwned,
		},
		MinimumSupportedVersion: "1.0.0",
		TestedVersion:           "1.0.0",
		RiskClass:               integration.RiskClassLowImpact,
	}
}

func (a *ExampleAdapter) Detect(ctx context.Context, runner integration.Runner) (integration.Installation, error) {
	path, err := runner.LookPath("example-tool")
	if err != nil {
		return integration.Installation{Installed: false}, nil
	}
	ver, _ := runner.DetectVersion(ctx, "example-tool", []string{"--version"})
	return integration.Installation{
		Installed:  true,
		Path:       path,
		Version:    ver,
		Compatible: true,
	}, nil
}

func (a *ExampleAdapter) Plan(ctx context.Context, req integration.Request) (integration.ExecutionPlan, error) {
	return integration.ExecutionPlan{
		Command: integration.CommandSpec{
			Binary:         "example-tool",
			Args:           []string{"--target", req.Target.Host, "--json"},
			Timeout:        30 * time.Second,
			MaxStdoutBytes: 10 * 1024 * 1024,
			MaxStderrBytes: 1 * 1024 * 1024,
		},
		OutputSource: integration.OutputSourceStdout,
	}, nil
}

func (a *ExampleAdapter) Parse(ctx context.Context, input io.Reader, emit integration.Emitter) error {
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var record struct {
			Host string `json:"host"`
		}
		if err := json.Unmarshal([]byte(line), &record); err == nil && record.Host != "" {
			emit.EmitAsset(model.Asset{
				Kind:   model.AssetKindHostname,
				Value:  record.Host,
				Source: "example",
			})
		}
	}
	return scanner.Err()
}
