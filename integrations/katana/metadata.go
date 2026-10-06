package katana

import (
	"github.com/exposureguard/exposureguard/pkg/integration"
	"github.com/exposureguard/exposureguard/pkg/model"
)

const (
	ID                      = "katana"
	Binary                  = "katana"
	TestedVersion           = "1.8.0"
	MinimumSupportedVersion = "1.0.0"
)

// DefaultMetadata returns canonical metadata for Katana.
func DefaultMetadata() integration.Metadata {
	pinned := integration.PinnedToolVersion(ID)
	tested := TestedVersion
	if pinned != "" {
		tested = pinned
	}

	return integration.Metadata{
		ID:          ID,
		DisplayName: "Katana",
		Description: "Next-generation crawling and endpoint discovery engine",
		Binary:      Binary,
		Capabilities: []integration.Capability{
			integration.CapabilityCrawler,
			integration.CapabilityEndpointDiscovery,
		},
		SupportedModes: []model.ScanMode{
			model.ScanModeOwned,
		},
		MinimumSupportedVersion: MinimumSupportedVersion,
		TestedVersion:           tested,
		UpstreamURL:             "https://github.com/projectdiscovery/katana",
		RiskClass:               integration.RiskClassActive,
	}
}
