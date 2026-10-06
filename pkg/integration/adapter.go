package integration

import (
	"context"
	"io"
)

// Adapter encapsulates tool-specific configuration, planning, execution options, and parsing.
// It is intentionally decoupled from process lifecycle and OS execution details.
type Adapter interface {
	// ID returns the unique canonical identifier for the integration (e.g. "subfinder", "httpx").
	ID() string

	// Metadata returns the declarative description, capabilities, and compatibility contract.
	Metadata() Metadata

	// Detect probes whether the required binary is installed and inspects its version/compatibility.
	Detect(ctx context.Context, runner Runner) (Installation, error)

	// Plan builds the safe command arguments and environment based on the scan request and policy.
	Plan(ctx context.Context, req Request) (ExecutionPlan, error)

	// Parse reads the structured tool output (e.g. JSONL) and emits canonical assets, observations, and findings.
	Parse(ctx context.Context, input io.Reader, emit Emitter) error
}

