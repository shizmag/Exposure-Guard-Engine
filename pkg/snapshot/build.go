package snapshot

import (
	"time"

	"github.com/exposureguard/exposureguard/internal/buildinfo"
	"github.com/exposureguard/exposureguard/pkg/model"
)

// Build constructs a deterministic, normalized Snapshot.
func Build(target model.Target, assets []model.Asset, obs []model.Observation, findings []model.Finding, capturedAt time.Time) model.Snapshot {
	// Normalize and assign stable IDs
	normAssets := make([]model.Asset, len(assets))
	copy(normAssets, assets)
	for i := range normAssets {
		if normAssets[i].ID == "" {
			normAssets[i].ID = ComputeAssetID(normAssets[i].Kind, normAssets[i].Value)
		}
	}
	SortAssets(normAssets)

	normObs := make([]model.Observation, len(obs))
	copy(normObs, obs)
	for i := range normObs {
		if normObs[i].ID == "" {
			normObs[i].ID = ComputeObservationID(normObs[i].Kind, normObs[i].Subject, normObs[i].Data)
		}
	}
	SortObservations(normObs)

	normFindings := make([]model.Finding, len(findings))
	copy(normFindings, findings)
	for i := range normFindings {
		if normFindings[i].ID == "" {
			normFindings[i].ID = ComputeFindingID(normFindings[i].RuleID, normFindings[i].Asset, normFindings[i].Evidence.Fingerprint)
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
