package model

import "time"

// SnapshotSummary provides high-level aggregation of snapshot items.
type SnapshotSummary struct {
	TotalAssets       int `json:"total_assets"`
	TotalObservations int `json:"total_observations"`
	TotalFindings     int `json:"total_findings"`
	CriticalFindings  int `json:"critical_findings"`
	HighFindings      int `json:"high_findings"`
	MediumFindings    int `json:"medium_findings"`
	LowFindings       int `json:"low_findings"`
	InfoFindings      int `json:"info_findings"`
}

// Snapshot represents a normalized, deterministic point-in-time state of an asset/target.
type Snapshot struct {
	SchemaVersion string          `json:"schema_version"`
	Target        Target          `json:"target"`
	CapturedAt    time.Time       `json:"captured_at,omitzero"`
	Assets        []Asset         `json:"assets"`
	Observations  []Observation   `json:"observations"`
	Findings      []Finding       `json:"findings"`
	Summary       SnapshotSummary `json:"summary"`
}
