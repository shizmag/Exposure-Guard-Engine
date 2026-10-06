package httpx

import (
	"github.com/exposureguard/exposureguard/pkg/integration"
	"github.com/exposureguard/exposureguard/pkg/model"
)

const (
	ID                      = "httpx"
	Binary                  = "httpx"
	TestedVersion           = "1.12.0"
	MinimumSupportedVersion = "1.3.0"
)

// DefaultMetadata returns canonical metadata for httpx.
func DefaultMetadata() integration.Metadata {
	pinned := integration.PinnedToolVersion(ID)
	tested := TestedVersion
	if pinned != "" {
		tested = pinned
	}

	return integration.Metadata{
		ID:          ID,
		DisplayName: "httpx",
		Description: "Fast multi-purpose HTTP probe and asset metadata enrichment toolkit",
		Binary:      Binary,
		Capabilities: []integration.Capability{
			integration.CapabilityHTTPProbe,
			integration.CapabilityAssetEnrichment,
		},
		SupportedModes: []model.ScanMode{
			model.ScanModeOwned,
		},
		MinimumSupportedVersion: MinimumSupportedVersion,
		TestedVersion:           tested,
		UpstreamURL:             "https://github.com/projectdiscovery/httpx",
		RiskClass:               integration.RiskClassLowImpact,
	}
}
