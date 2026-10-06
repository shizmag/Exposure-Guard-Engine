package subfinder

import (
	"strings"

	"github.com/exposureguard/exposureguard/pkg/integration"
	"github.com/exposureguard/exposureguard/pkg/model"
)

// Record represents a single JSONL event emitted by Subfinder.
type Record struct {
	Host    string   `json:"host"`
	Input   string   `json:"input"`
	Source  string   `json:"source,omitempty"`
	Sources []string `json:"sources,omitempty"`
}

// MapRecord converts a raw Subfinder record into ExposureGuard Asset and Observation events.
func MapRecord(rec Record, emit integration.Emitter) {
	host := strings.ToLower(strings.TrimSpace(rec.Host))
	if host == "" {
		return
	}

	sourceStr := rec.Source
	if len(rec.Sources) > 0 {
		if sourceStr == "" {
			sourceStr = strings.Join(rec.Sources, ",")
		}
	}
	if sourceStr == "" {
		sourceStr = "passive"
	}

	asset := model.Asset{
		Kind:          model.AssetKindHostname,
		Value:         host,
		Source:        "subfinder",
		DiscoveredVia: sourceStr,
		Attributes: map[string]string{
			"input":     rec.Input,
			"source":    sourceStr,
			"candidate": "true",
		},
	}
	emit.EmitAsset(asset)

	obs := model.Observation{
		Kind:    "subdomain.passive_discovery",
		Subject: host,
		Data: map[string]any{
			"domain":    rec.Input,
			"subdomain": host,
			"source":    sourceStr,
			"sources":   rec.Sources,
			"passive":   true,
		},
	}
	emit.EmitObservation(obs)
}
