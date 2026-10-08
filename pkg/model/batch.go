package model

import (
	"encoding/json"
	"time"
)

// BatchRequest is the bounded Batch Protocol v1 execution envelope.
type BatchRequest struct {
	ProtocolVersion string        `json:"batch_protocol_version"`
	BatchID         string        `json:"batch_id"`
	Limits          BatchLimits   `json:"limits,omitempty"`
	Scans           []ScanRequest `json:"scans"`
}

// BatchLimits bound batch execution and aggregate resource use.
type BatchLimits struct {
	MaxBatchSize                 int   `json:"max_batch_size,omitempty"`
	MaxParallelScans             int   `json:"max_parallel_scans,omitempty"`
	MaxParallelExternalProcesses int   `json:"max_parallel_external_processes,omitempty"`
	MaxTempBytes                 int64 `json:"max_temp_bytes,omitempty"`
	MaxOutputBytes               int64 `json:"max_output_bytes,omitempty"`
}

// BatchStatus is the aggregate Batch Protocol v1 outcome. BatchResult counts
// describe accepted items; workload statuses do not set the process exit code.
type BatchStatus string

const (
	BatchStatusComplete  BatchStatus = "complete"
	BatchStatusPartial   BatchStatus = "partial"
	BatchStatusFailed    BatchStatus = "failed"
	BatchStatusCancelled BatchStatus = "cancelled"
)

// BatchResult summarizes isolated scan outcomes without merging Snapshots.
type BatchResult struct {
	ProtocolVersion string            `json:"batch_protocol_version"`
	BatchID         string            `json:"batch_id"`
	Status          BatchStatus       `json:"status"`
	ScanCount       int               `json:"scan_count"`
	CompletedCount  int               `json:"completed_count"`
	PartialCount    int               `json:"partial_count"`
	FailedCount     int               `json:"failed_count"`
	CancelledCount  int               `json:"cancelled_count"`
	Scans           []BatchScanResult `json:"scans"`
	Summary         BatchSummary      `json:"summary"`
}

// BatchSummary aggregates counts and execution provenance.
type BatchSummary struct {
	Total         int       `json:"total"`
	Completed     int       `json:"completed"`
	Partial       int       `json:"partial"`
	Failed        int       `json:"failed"`
	Cancelled     int       `json:"cancelled"`
	StartedAt     time.Time `json:"started_at"`
	FinishedAt    time.Time `json:"finished_at"`
	Duration      int64     `json:"duration"`
	Assets        int       `json:"assets"`
	Observations  int       `json:"observations"`
	Findings      int       `json:"findings"`
	Changes       int       `json:"changes"`
	EngineVersion string    `json:"engine_version"`
	GitCommit     string    `json:"git_commit"`
}

// BatchScanResult carries one scan's status, result and optional diagnostic.
type BatchScanResult struct {
	ScanID  string          `json:"scan_id"`
	Status  string          `json:"status"`
	Result  *ScanResult     `json:"result,omitempty"`
	Summary json.RawMessage `json:"summary,omitempty"`
	Error   string          `json:"error,omitempty"`
}
