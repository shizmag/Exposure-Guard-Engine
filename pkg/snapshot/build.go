package snapshot

import (
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/exposureguard/exposureguard/internal/buildinfo"
	"github.com/exposureguard/exposureguard/pkg/model"
)

// Build constructs a deterministic, normalized Snapshot with deduplication.
func Build(target model.Target, assets []model.Asset, obs []model.Observation, findings []model.Finding, capturedAt time.Time) model.Snapshot {
	return build(target, assets, obs, findings, capturedAt, nil, "1")
}

// BuildWithCoverage constructs a v2 Snapshot with the successful Engine stages
// that produced its observations. An absent stage means its absence in this
// Snapshot is not evidence that the corresponding state was removed.
func BuildWithCoverage(target model.Target, assets []model.Asset, obs []model.Observation, findings []model.Finding, capturedAt time.Time, coverage []string) model.Snapshot {
	return build(target, assets, obs, findings, capturedAt, coverage, buildinfo.SnapshotSchemaVersion)
}

func build(target model.Target, assets []model.Asset, obs []model.Observation, findings []model.Finding, capturedAt time.Time, coverage []string, schemaVersion string) model.Snapshot {
	coverage = normalizeCoverage(coverage)
	// Normalize and assign stable IDs with deduplication
	seenAssets := make(map[string]int)
	normAssets := make([]model.Asset, 0, len(assets))
	for _, a := range assets {
		a.Coverage = normalizeCoverage(a.Coverage)
		id := a.ID
		if id == "" {
			id = ComputeAssetID(a.Kind, a.Value)
			a.ID = id
		}
		if idx, exists := seenAssets[id]; exists {
			existing := &normAssets[idx]
			existing.Coverage = mergeCoverage(existing.Coverage, a.Coverage)
			if a.Source != "" && !strings.Contains(existing.Source, a.Source) {
				if existing.Source == "" {
					existing.Source = a.Source
				} else {
					existing.Source = existing.Source + "," + a.Source
				}
			}
			if a.Attributes != nil {
				if existing.Attributes == nil {
					existing.Attributes = make(map[string]string)
				}
				for k, v := range a.Attributes {
					if existing.Attributes[k] == "" {
						existing.Attributes[k] = v
					}
				}
			}
		} else {
			seenAssets[id] = len(normAssets)
			normAssets = append(normAssets, a)
		}
	}
	SortAssets(normAssets)

	seenObs := make(map[string]int)
	normObs := make([]model.Observation, 0, len(obs))
	for _, o := range obs {
		o.Coverage = normalizeCoverage(o.Coverage)
		id := o.ID
		if id == "" {
			id = ComputeObservationID(o.Kind, o.Subject, o.Data)
			o.ID = id
		}
		if idx, exists := seenObs[id]; !exists {
			seenObs[id] = len(normObs)
			normObs = append(normObs, o)
		} else {
			normObs[idx].Coverage = mergeCoverage(normObs[idx].Coverage, o.Coverage)
		}
	}
	SortObservations(normObs)

	seenFindings := make(map[string]int)
	normFindings := make([]model.Finding, 0, len(findings))
	for _, f := range findings {
		f.Coverage = normalizeCoverage(f.Coverage)
		id := f.ID
		if id == "" {
			id = ComputeFindingID(f.RuleID, f.Asset, f.Evidence.Fingerprint)
			f.ID = id
		}
		if idx, exists := seenFindings[id]; !exists {
			seenFindings[id] = len(normFindings)
			normFindings = append(normFindings, f)
		} else {
			normFindings[idx].Coverage = mergeCoverage(normFindings[idx].Coverage, f.Coverage)
		}
	}
	SortFindings(normFindings)

	// Summary aggregation
	summary := model.SnapshotSummary{
		TotalAssets:       len(normAssets),
		TotalObservations: len(normObs),
		TotalFindings:     len(normFindings),
	}
	for _, f := range normFindings {
		switch f.Severity {
		case model.SeverityCritical:
			summary.CriticalFindings++
		case model.SeverityHigh:
			summary.HighFindings++
		case model.SeverityMedium:
			summary.MediumFindings++
		case model.SeverityLow:
			summary.LowFindings++
		case model.SeverityInfo:
			summary.InfoFindings++
		}
	}

	if capturedAt.IsZero() {
		capturedAt = time.Now().UTC()
	}

	snap := model.Snapshot{
		SchemaVersion: schemaVersion,
		Target:        target,
		CapturedAt:    capturedAt,
		Coverage:      coverage,
		Assets:        normAssets,
		Observations:  normObs,
		Findings:      normFindings,
		Summary:       summary,
	}
	snap.Fingerprint = ComputeCanonicalHash(&snap)
	return snap
}

func normalizeCoverage(stages []string) []string {
	result := make([]string, 0, len(stages))
	if len(stages) == 0 {
		return result
	}
	seen := make(map[string]struct{}, len(stages))
	for _, stage := range stages {
		stage = strings.TrimSpace(stage)
		if stage == "" {
			continue
		}
		if _, ok := seen[stage]; ok {
			continue
		}
		seen[stage] = struct{}{}
		result = append(result, stage)
	}
	sort.Strings(result)
	return result
}

func mergeCoverage(left, right []string) []string {
	return normalizeCoverage(slices.Concat(left, right))
}
