package model

// AssetKind defines categories of discovered assets.
type AssetKind string

const (
	AssetKindHostname   AssetKind = "hostname"
	AssetKindURL        AssetKind = "url"
	AssetKindJavaScript AssetKind = "javascript"
	AssetKindSourceMap  AssetKind = "source_map"
	AssetKindEndpoint   AssetKind = "endpoint_candidate"
	AssetKindExternal   AssetKind = "external_reference"
)

// Asset represents a discovered resource or reference.
type Asset struct {
	ID            string            `json:"id"`
	Kind          AssetKind         `json:"kind"`
	Value         string            `json:"value"`
	URL           string            `json:"url,omitempty"`
	Source        string            `json:"source,omitempty"`
	DiscoveredVia string            `json:"discovered_via,omitempty"`
	Attributes    map[string]string `json:"attributes,omitempty"`
}
