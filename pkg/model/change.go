package model

// Importance classifies significance of a detected change.
type Importance string

const (
	ImportanceInfo   Importance = "info"
	ImportanceLow    Importance = "low"
	ImportanceMedium Importance = "medium"
	ImportanceHigh   Importance = "high"
)

// Change represents a state transition detected between two snapshots.
type Change struct {
	ID         string     `json:"id"`
	Type       string     `json:"type"`
	Subject    string     `json:"subject"`
	Old        any        `json:"old,omitempty"`
	New        any        `json:"new,omitempty"`
	Importance Importance `json:"importance"`
	Reason     string     `json:"reason,omitempty"`
}
