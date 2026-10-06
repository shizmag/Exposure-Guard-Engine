package integration

import (
	"io"
	"time"

	"github.com/exposureguard/exposureguard/pkg/model"
)

// OutputSource indicates where the adapter expects the tool's structured output.
type OutputSource string

const (
	OutputSourceStdout OutputSource = "stdout"
	OutputSourceFile   OutputSource = "file"
)

// CommandSpec defines a subprocess command specification to execute.
type CommandSpec struct {
	Binary         string        `json:"binary"`
	Args           []string      `json:"args"`
	Env            []string      `json:"env,omitempty"`
	Timeout        time.Duration `json:"timeout"`
	MaxStdoutBytes int64         `json:"max_stdout_bytes"`
	MaxStderrBytes int64         `json:"max_stderr_bytes"`
	WorkingDir     string        `json:"working_dir,omitempty"`
}

// ExecutionPlan outlines how the runner should invoke the external command and locate output.
type ExecutionPlan struct {
	Command        CommandSpec  `json:"command"`
	OutputSource   OutputSource `json:"output_source"`
	OutputFilePath string       `json:"output_file_path,omitempty"`
}

// Installation holds discovery and compatibility status for a tool on the host.
type Installation struct {
	Installed  bool   `json:"installed"`
	Path       string `json:"path"`
	Version    string `json:"version"`
	Compatible bool   `json:"compatible"`
	Warning    string `json:"warning,omitempty"`
}

// Emitter is the callback interface that parsers invoke to stream discovered entities into the engine.
type Emitter interface {
	EmitAsset(model.Asset)
	EmitObservation(model.Observation)
	EmitFinding(model.Finding)
}

// CollectEmitter gathers emitted entities in-memory for testing or batch inspection.
type CollectEmitter struct {
	Assets       []model.Asset
	Observations []model.Observation
	Findings     []model.Finding
}

// EmitAsset appends an asset.
func (c *CollectEmitter) EmitAsset(a model.Asset) {
	c.Assets = append(c.Assets, a)
}

// EmitObservation appends an observation.
func (c *CollectEmitter) EmitObservation(o model.Observation) {
	c.Observations = append(c.Observations, o)
}

// EmitFinding appends a finding.
func (c *CollectEmitter) EmitFinding(f model.Finding) {
	c.Findings = append(c.Findings, f)
}

// RunResult contains the terminal execution artifacts from a Runner run.
type RunResult struct {
	ExitCode int
	Stdout   io.ReadCloser
	Stderr   string
	Duration time.Duration
}
