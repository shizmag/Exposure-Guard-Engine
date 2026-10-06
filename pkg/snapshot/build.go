package snapshot

import (
	"strings"
	"time"

	"github.com/exposureguard/exposureguard/internal/buildinfo"
	"github.com/exposureguard/exposureguard/pkg/model"
)

// Build constructs a deterministic, normalized Snapshot with deduplication.
func Build(target model.Target, assets []model.Asset, obs []model.Observation, findings []model.Finding, capturedAt time.Time) model.Snapshot {
	// Normalize and assign stable IDs with deduplication
	seenAssets := make(map[string]int)
	var normAssets []model.Asset
	for _, a := range assets {
		id := a.ID
		if id == "" {
			id = ComputeAssetID(a.Kind, a.Value)
			a.ID = id
		}
		if idx, exists := seenAssets[id]; exists {
			existing := &normAssets[idx]
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
	var normObs []model.Observation
	for _, o := range obs {
		id := o.ID
		if id == "" {
			id = ComputeObservationID(o.Kind, o.Subject, o.Data)
			o.ID = id
		}
		if _, exists := seenObs[id]; !exists {
			seenObs[id] = len(normObs)
			normObs = append(normObs, o)
		}
	}
	SortObservations(normObs)

	seenFindings := make(map[string]int)
	var normFindings []model.Finding
	for _, f := range findings {
		id := f.ID
		if id == "" {
			id = ComputeFindingID(f.RuleID, f.Asset, f.Evidence.Fingerprint)
			f.ID = id
		}
		if _, exists := seenFindings[id]; !exists {
			seenFindings[id] = len(normFindings)
			normFindings = append(normFindings, f)
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

	return model.Snapshot{
		SchemaVersion: buildinfo.SnapshotSchemaVersion,
		Target:        target,
		CapturedAt:    capturedAt,
		Assets:        normAssets,
		Observations:  normObs,
		Findings:      normFindings,
		Summary:       summary,
	}
}
