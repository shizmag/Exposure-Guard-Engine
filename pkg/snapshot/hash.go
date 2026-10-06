package snapshot

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/exposureguard/exposureguard/pkg/model"
)

// canonicalAsset captures identity fields for fingerprint hashing.
type canonicalAsset struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// canonicalObservation captures identity fields for fingerprint hashing.
type canonicalObservation struct {
	Kind    string         `json:"kind"`
	Subject string         `json:"subject"`
	Data    map[string]any `json:"data"`
}

// canonicalFinding captures identity fields for fingerprint hashing.
type canonicalFinding struct {
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Asset       string `json:"asset"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

type canonicalSnapshotRepresentation struct {
	Target       string                 `json:"target"`
	Assets       []canonicalAsset       `json:"assets"`
	Observations []canonicalObservation `json:"observations"`
	Findings     []canonicalFinding     `json:"findings"`
}

// ComputeCanonicalHash produces a stable, deterministic SHA-256 fingerprint for a snapshot.
// The hash is completely invariant to captured_at timestamps, durations, goroutine concurrency,
// memory addresses, and execution platform.
func ComputeCanonicalHash(s *model.Snapshot) string {
	if s == nil {
		return ""
	}

	// 1. Canonical Assets
	canonAssets := make([]canonicalAsset, 0, len(s.Assets))
	for _, a := range s.Assets {
		canonAssets = append(canonAssets, canonicalAsset{
			Kind:  string(a.Kind),
			Value: strings.TrimSpace(a.Value),
		})
	}
	sort.Slice(canonAssets, func(i, j int) bool {
		if canonAssets[i].Kind != canonAssets[j].Kind {
			return canonAssets[i].Kind < canonAssets[j].Kind
		}
		return canonAssets[i].Value < canonAssets[j].Value
	})

	// 2. Canonical Observations
	canonObs := make([]canonicalObservation, 0, len(s.Observations))
	for _, o := range s.Observations {
		stableData := make(map[string]any)
		for k, v := range o.Data {
			if !volatileKeys[strings.ToLower(k)] {
				// Normalize strings if any
				if str, ok := v.(string); ok {
					stableData[strings.ToLower(k)] = strings.TrimSpace(str)
				} else {
					stableData[strings.ToLower(k)] = v
				}
			}
		}
		canonObs = append(canonObs, canonicalObservation{
			Kind:    o.Kind,
			Subject: strings.TrimSpace(o.Subject),
			Data:    stableData,
		})
	}
	sort.Slice(canonObs, func(i, j int) bool {
		if canonObs[i].Kind != canonObs[j].Kind {
			return canonObs[i].Kind < canonObs[j].Kind
		}
		return canonObs[i].Subject < canonObs[j].Subject
	})

	// 3. Canonical Findings
	canonFindings := make([]canonicalFinding, 0, len(s.Findings))
	for _, f := range s.Findings {
		canonFindings = append(canonFindings, canonicalFinding{
			RuleID:      f.RuleID,
			Severity:    string(f.Severity),
			Asset:       strings.TrimSpace(f.Asset),
			Fingerprint: f.Evidence.Fingerprint,
		})
	}
	sort.Slice(canonFindings, func(i, j int) bool {
		if canonFindings[i].RuleID != canonFindings[j].RuleID {
			return canonFindings[i].RuleID < canonFindings[j].RuleID
		}
		if canonFindings[i].Asset != canonFindings[j].Asset {
			return canonFindings[i].Asset < canonFindings[j].Asset
		}
		return canonFindings[i].Fingerprint < canonFindings[j].Fingerprint
	})

	repr := canonicalSnapshotRepresentation{
		Target:       fmt.Sprintf("%s://%s:%d", s.Target.Scheme, s.Target.Host, s.Target.Port),
		Assets:       canonAssets,
		Observations: canonObs,
		Findings:     canonFindings,
	}

	payload, _ := json.Marshal(repr)
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}
