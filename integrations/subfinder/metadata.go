package subfinder

import (
	"github.com/exposureguard/exposureguard/pkg/integration"
	"github.com/exposureguard/exposureguard/pkg/model"
)

const (
	ID                      = "subfinder"
	Binary                  = "subfinder"
	TestedVersion           = "2.16.0"
	MinimumSupportedVersion = "2.6.0"
)

// DefaultMetadata returns canonical metadata for Subfinder.
func DefaultMetadata() integration.Metadata {
	pinned := integration.PinnedToolVersion(ID)
	tested := TestedVersion
	if pinned != "" {
		tested = pinned
	}

	return integration.Metadata{
		ID:          ID,
		DisplayName: "Subfinder",
		Description: "Fast passive subdomain discovery engine using OSINT sources",
		Binary:      Binary,
		Capabilities: []integration.Capability{
			integration.CapabilityAssetDiscovery,
		},
		SupportedModes: []model.ScanMode{
			model.ScanModePublic,
			model.ScanModeOwned,
		},
		MinimumSupportedVersion: MinimumSupportedVersion,
		TestedVersion:           tested,
		UpstreamURL:             "https://github.com/projectdiscovery/subfinder",
		RiskClass:               integration.RiskClassPassive,
	}
}
