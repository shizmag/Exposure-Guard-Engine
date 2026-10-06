package nuclei

import (
	"github.com/exposureguard/exposureguard/pkg/integration"
	"github.com/exposureguard/exposureguard/pkg/model"
)

const (
	ID                      = "nuclei"
	Binary                  = "nuclei"
	TestedVersion           = "3.11.1"
	MinimumSupportedVersion = "3.0.0"
)

// DefaultMetadata returns canonical metadata for Nuclei.
func DefaultMetadata() integration.Metadata {
	pinned := integration.PinnedToolVersion(ID)
	tested := TestedVersion
	if pinned != "" {
		tested = pinned
	}

	return integration.Metadata{
		ID:          ID,
		DisplayName: "Nuclei (Curated Defensive Profile)",
		Description: "Defensive template-based scanner for configuration exposure and public artifacts",
		Binary:      Binary,
		Capabilities: []integration.Capability{
			integration.CapabilitySecurityCheck,
		},
		SupportedModes: []model.ScanMode{
			model.ScanModeOwned,
		},
		MinimumSupportedVersion: MinimumSupportedVersion,
		TestedVersion:           tested,
		UpstreamURL:             "https://github.com/projectdiscovery/nuclei",
		RiskClass:               integration.RiskClassActive,
	}
}
