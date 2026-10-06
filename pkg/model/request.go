package model

// ScanMode defines operational boundaries (e.g. public safe checks vs owned deep checks).
type ScanMode string

const (
	ScanModePublic ScanMode = "public"
	ScanModeOwned  ScanMode = "owned"
)

// ScanRequest represents the structured input contract for an exposure scan.
type ScanRequest struct {
	SchemaVersion       string   `json:"schema_version"`
	ScanID              string   `json:"scan_id"`
	Target              string   `json:"target"`
	Profile             string   `json:"profile,omitempty"`
	Mode                ScanMode `json:"mode,omitempty"`
	Modules             []string `json:"modules,omitempty"`
	DisableModules      []string `json:"disable_modules,omitempty"`
	Integrations        string   `json:"integrations,omitempty"`
	DisableIntegrations []string `json:"disable_integrations,omitempty"`
	RequireIntegrations []string `json:"require_integrations,omitempty"`
	Limits              Limits   `json:"limits"`
}

// NewDefaultScanRequest creates a valid request with safe defaults.
func NewDefaultScanRequest(target string) ScanRequest {
	return ScanRequest{
		SchemaVersion: "1",
		Target:        target,
		Profile:       "standard",
		Mode:          ScanModePublic,
		Limits:        DefaultLimits(),
	}
}
