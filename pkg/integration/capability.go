package integration

// Capability defines functional traits provided by an integration.
type Capability string

const (
	CapabilityAssetDiscovery    Capability = "asset-discovery"
	CapabilityHTTPProbe         Capability = "http-probe"
	CapabilityCrawler           Capability = "crawler"
	CapabilitySecurityCheck     Capability = "security-check"
	CapabilityEndpointDiscovery Capability = "endpoint-discovery"
	CapabilityAssetEnrichment   Capability = "asset-enrichment"
)
