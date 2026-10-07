package snapshot

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"

	"github.com/exposureguard/exposureguard/pkg/model"
)

// Volatile observation keys excluded from deterministic comparison/identity hashing.
var volatileKeys = map[string]bool{
	"response_time_ms": true,
	"ttl":              true,
	"timestamp":        true,
	"captured_at":      true,
}

// ComputeAssetID generates a deterministic full SHA-256 identity for an asset.
func ComputeAssetID(kind model.AssetKind, value string) string {
	h := sha256.Sum256([]byte(string(kind) + ":" + strings.TrimSpace(value)))
	return hex.EncodeToString(h[:])
}

// ComputeObservationID generates a deterministic full SHA-256 identity for an observation.
func ComputeObservationID(kind, subject string, data map[string]any) string {
	stableData := make(map[string]any)
	for k, v := range data {
		if !volatileKeys[strings.ToLower(k)] {
			stableData[k] = v
		}
	}
	encoded, _ := json.Marshal(stableData)
	h := sha256.Sum256([]byte(kind + ":" + subject + ":" + string(encoded)))
	return hex.EncodeToString(h[:])
}

// ComputeFindingID generates a deterministic full SHA-256 identity for a finding.
func ComputeFindingID(ruleID, asset, fingerprint string) string {
	h := sha256.Sum256([]byte(ruleID + ":" + asset + ":" + fingerprint))
	return hex.EncodeToString(h[:])
}

// SortAssets sorts an asset slice deterministically.
func SortAssets(assets []model.Asset) {
	sort.Slice(assets, func(i, j int) bool {
		if assets[i].Kind != assets[j].Kind {
			return assets[i].Kind < assets[j].Kind
		}
		if assets[i].Value != assets[j].Value {
			return assets[i].Value < assets[j].Value
		}
		return assets[i].ID < assets[j].ID
	})
}

// SortObservations sorts observations deterministically.
func SortObservations(obs []model.Observation) {
	sort.Slice(obs, func(i, j int) bool {
		if obs[i].Kind != obs[j].Kind {
			return obs[i].Kind < obs[j].Kind
		}
		if obs[i].Subject != obs[j].Subject {
			return obs[i].Subject < obs[j].Subject
		}
		return obs[i].ID < obs[j].ID
	})
}

var severityWeights = map[model.Severity]int{
	model.SeverityCritical: 5,
	model.SeverityHigh:     4,
	model.SeverityMedium:   3,
	model.SeverityLow:      2,
	model.SeverityInfo:     1,
}

// SortFindings sorts findings deterministically: highest severity first, then rule, then asset.
func SortFindings(findings []model.Finding) {
	sort.Slice(findings, func(i, j int) bool {
		wI := severityWeights[findings[i].Severity]
		wJ := severityWeights[findings[j].Severity]
		if wI != wJ {
			return wI > wJ // higher severity first
		}
		if findings[i].RuleID != findings[j].RuleID {
			return findings[i].RuleID < findings[j].RuleID
		}
		if findings[i].Asset != findings[j].Asset {
			return findings[i].Asset < findings[j].Asset
		}
		return findings[i].ID < findings[j].ID
	})
}
