package model

import (
	"encoding/json"
	"time"
)

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
	Fingerprint   string          `json:"fingerprint,omitempty"`
	Target        Target          `json:"target"`
	CapturedAt    time.Time       `json:"captured_at,omitzero"`
	Coverage      []string        `json:"coverage,omitempty"`
	Assets        []Asset         `json:"assets"`
	Observations  []Observation   `json:"observations"`
	Findings      []Finding       `json:"findings"`
	Summary       SnapshotSummary `json:"summary"`
}

// MarshalJSON preserves Snapshot v1 bytes while ensuring Snapshot v2 always
// carries its coverage field, including an empty array when every stage failed.
func (s Snapshot) MarshalJSON() ([]byte, error) {
	type snapshotAlias Snapshot
	encoded, err := json.Marshal(snapshotAlias(s))
	if err != nil || s.SchemaVersion != "2" || len(s.Coverage) > 0 {
		return encoded, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		return nil, err
	}
	fields["coverage"] = json.RawMessage("[]")
	return json.Marshal(fields)
}
