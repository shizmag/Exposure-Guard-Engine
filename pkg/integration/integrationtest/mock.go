package integrationtest

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/exposureguard/exposureguard/pkg/integration"
)

// MockRunner simulates a Runner for unit and contract testing.
type MockRunner struct {
	LookPathFunc      func(binary string) (string, error)
	DetectVersionFunc func(ctx context.Context, binary string, args []string) (string, error)
	RunFunc           func(ctx context.Context, plan integration.ExecutionPlan) (*integration.RunResult, error)
}

func (m *MockRunner) LookPath(binary string) (string, error) {
	if m.LookPathFunc != nil {
		return m.LookPathFunc(binary)
	}
	return "/mock/bin/" + binary, nil
}

func (m *MockRunner) DetectVersion(ctx context.Context, binary string, args []string) (string, error) {
	if m.DetectVersionFunc != nil {
		return m.DetectVersionFunc(ctx, binary, args)
	}
	return "1.0.0", nil
}

func (m *MockRunner) Run(ctx context.Context, plan integration.ExecutionPlan) (*integration.RunResult, error) {
	if m.RunFunc != nil {
		return m.RunFunc(ctx, plan)
	}
	return &integration.RunResult{
		ExitCode: 0,
		Stdout:   io.NopCloser(strings.NewReader("")),
		Stderr:   "",
		Duration: 10 * time.Millisecond,
	}, nil
}

// Ensure MockRunner implements integration.Runner.
var _ integration.Runner = (*MockRunner)(nil)

// NewMockRunnerWithVersion creates a MockRunner that reports a fixed binary path and version.
func NewMockRunnerWithVersion(binary, version string) *MockRunner {
	return &MockRunner{
		LookPathFunc: func(b string) (string, error) {
			if b == binary {
				return "/opt/mock/bin/" + binary, nil
			}
			return "", fmt.Errorf("binary %q not found", b)
		},
		DetectVersionFunc: func(ctx context.Context, b string, args []string) (string, error) {
			if b == binary {
				return version, nil
			}
			return "", fmt.Errorf("version detection failed for %s", b)
		},
	}
}
