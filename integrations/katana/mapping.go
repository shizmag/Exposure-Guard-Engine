package katana

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/exposureguard/exposureguard/pkg/integration"
	"github.com/exposureguard/exposureguard/pkg/model"
)

// RequestInfo contains request metadata reported by Katana.
type RequestInfo struct {
	Method   string `json:"method"`
	Endpoint string `json:"endpoint"`
	Source   string `json:"source,omitempty"`
}

// ResponseInfo contains response headers and status reported by Katana.
type ResponseInfo struct {
	StatusCode int               `json:"status_code,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
}

// Record models a single crawl event from Katana.
type Record struct {
	Timestamp string       `json:"timestamp,omitempty"`
	Request   RequestInfo  `json:"request"`
	Response  ResponseInfo `json:"response"`
}

// MapRecord converts a Katana record into ExposureGuard canonical asset and observation models.
func MapRecord(rec Record, targetDomain string, emit integration.Emitter) {
	endpoint := strings.TrimSpace(rec.Request.Endpoint)
	if endpoint == "" {
		return
	}

	u, err := url.Parse(endpoint)
	if err != nil {
		return
	}

	contentType := ""
	if rec.Response.Headers != nil {
		for k, v := range rec.Response.Headers {
			if strings.EqualFold(k, "content_type") || strings.EqualFold(k, "content-type") {
				contentType = v
				break
			}
		}
	}

	var kind model.AssetKind
	host := strings.ToLower(u.Hostname())
	isThirdParty := false

	if targetDomain != "" && host != "" && host != targetDomain && !strings.HasSuffix(host, "."+targetDomain) {
		isThirdParty = true
	}

	if isThirdParty {
		kind = model.AssetKindExternal
	} else if strings.HasSuffix(strings.ToLower(u.Path), ".js") || strings.Contains(strings.ToLower(contentType), "javascript") {
		kind = model.AssetKindJavaScript
	} else if strings.Contains(u.Path, "/api/") || u.RawQuery != "" || strings.HasSuffix(u.Path, ".json") {
		kind = model.AssetKindEndpoint
	} else {
		kind = model.AssetKindURL
	}

	attrs := map[string]string{
		"source": "katana",
	}
	if rec.Request.Method != "" {
		attrs["method"] = rec.Request.Method
	}
	if rec.Response.StatusCode > 0 {
		attrs["status_code"] = strconv.Itoa(rec.Response.StatusCode)
	}
	if contentType != "" {
		attrs["content_type"] = contentType
	}

	asset := model.Asset{
		Kind:          kind,
		Value:         endpoint,
		URL:           endpoint,
		Source:        "katana",
		DiscoveredVia: rec.Request.Source,
		Attributes:    attrs,
	}
	emit.EmitAsset(asset)

	obs := model.Observation{
		Kind:    "crawler.endpoint_discovered",
		Subject: endpoint,
		Data: map[string]any{
			"endpoint":     endpoint,
			"source":       rec.Request.Source,
			"method":       rec.Request.Method,
			"status_code":  rec.Response.StatusCode,
			"content_type": contentType,
			"asset_kind":   string(kind),
			"third_party":  isThirdParty,
			"crawler":      "katana",
		},
	}
	emit.EmitObservation(obs)
}
