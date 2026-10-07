package snapshot

import (
	"crypto/sha256"
	"encoding/binary"
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

// StableID hashes identity fields with a versioned, domain-separated SHA-256 input.
func StableID(domain string, fields ...string) string {
	h := sha256.New()
	_, _ = h.Write([]byte("exposureguard:stable-id:v1\x00"))
	writeIdentityField(h, domain)
	for _, field := range fields {
		writeIdentityField(h, field)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func writeIdentityField(h interface{ Write([]byte) (int, error) }, field string) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(field)))
	_, _ = h.Write(length[:])
	_, _ = h.Write([]byte(field))
}

// ComputeAssetID generates a deterministic full SHA-256 identity for an asset.
func ComputeAssetID(kind model.AssetKind, value string) string {
	return StableID("asset", string(kind), strings.TrimSpace(value))
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
	return StableID("observation", kind, subject, string(encoded))
}

// ComputeFindingID generates a deterministic full SHA-256 identity for a finding.
func ComputeFindingID(ruleID, asset, fingerprint string) string {
	return StableID("finding", ruleID, asset, fingerprint)
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

func severityRank(severity model.Severity) int {
	switch severity {
	case model.SeverityCritical:
		return 5
	case model.SeverityHigh:
		return 4
	case model.SeverityMedium:
		return 3
	case model.SeverityLow:
		return 2
	case model.SeverityInfo:
		return 1
	default:
		return 0
	}
}

// SortFindings sorts findings deterministically.
func SortFindings(findings []model.Finding) {
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return severityRank(findings[i].Severity) > severityRank(findings[j].Severity)
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
