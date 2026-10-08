package model

// Severity defines finding impact levels.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Confidence defines certainty of a finding.
type Confidence string

const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

// Finding represents an actionable defensive issue discovered during the scan.
type Finding struct {
	ID             string     `json:"id"`
	CheckID        string     `json:"check_id"`
	Coverage       []string   `json:"coverage,omitempty"`
	CarriedForward bool       `json:"carried_forward,omitempty"`
	RuleID         string     `json:"rule_id"`
	Severity       Severity   `json:"severity"`
	Confidence     Confidence `json:"confidence"`
	Title          string     `json:"title"`
	Description    string     `json:"description"`
	Asset          string     `json:"asset"`
	Evidence       Evidence   `json:"evidence"`
	Remediation    string     `json:"remediation,omitempty"`
}
