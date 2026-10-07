package diff

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/exposureguard/exposureguard/pkg/model"
)

var importanceWeights = map[model.Importance]int{
	model.ImportanceHigh:   4,
	model.ImportanceMedium: 3,
	model.ImportanceLow:    2,
	model.ImportanceInfo:   1,
}

// Compare computes state transitions between two normalized Snapshots.
func Compare(oldSnap, newSnap *model.Snapshot) []model.Change {
	if oldSnap == nil || newSnap == nil {
		return nil
	}

	var changes []model.Change

	// 1. Diff Assets
	changes = append(changes, diffAssets(oldSnap.Assets, newSnap.Assets)...)

	// 2. Diff Findings
	changes = append(changes, diffFindings(oldSnap.Findings, newSnap.Findings)...)

	// 3. Diff Observations (DNS, TLS, HTTP, Headers)
	changes = append(changes, diffObservations(oldSnap.Observations, newSnap.Observations)...)

	// Deterministic sorting of changes
	sort.Slice(changes, func(i, j int) bool {
		wI := importanceWeights[changes[i].Importance]
		wJ := importanceWeights[changes[j].Importance]
		if wI != wJ {
			return wI > wJ // higher importance first
		}
		if changes[i].Type != changes[j].Type {
			return changes[i].Type < changes[j].Type
		}
		return changes[i].Subject < changes[j].Subject
	})

	return changes
}

func diffAssets(oldAssets, newAssets []model.Asset) []model.Change {
	var changes []model.Change
	oldMap := make(map[string]model.Asset)
	newMap := make(map[string]model.Asset)

	for _, a := range oldAssets {
		oldMap[a.ID] = a
	}
	for _, a := range newAssets {
		newMap[a.ID] = a
	}

	// Assets added
	for id, a := range newMap {
		if _, exists := oldMap[id]; !exists {
			changeType := "asset.added"
			importance := model.ImportanceInfo
			reason := fmt.Sprintf("New asset %s (%s) discovered", a.Value, a.Kind)

			switch a.Kind {
			case model.AssetKindSourceMap:
				changeType = "frontend.source_map_appeared"
				importance = model.ImportanceMedium
				reason = "Public source map appeared in production"
			case model.AssetKindJavaScript:
				changeType = "frontend.javascript_added"
			case model.AssetKindEndpoint:
				changeType = "frontend.endpoint_candidate_added"
			}

			chID := computeChangeID(changeType, a.Value)
			changes = append(changes, model.Change{
				ID:         chID,
				Type:       changeType,
				Subject:    a.Value,
				Old:        nil,
				New:        a,
				Importance: importance,
				Reason:     reason,
			})
		}
	}

	// Assets removed
	for id, a := range oldMap {
		if _, exists := newMap[id]; !exists {
			changeType := "asset.removed"
			importance := model.ImportanceInfo
			reason := fmt.Sprintf("Asset %s (%s) no longer discovered", a.Value, a.Kind)

			if a.Kind == model.AssetKindSourceMap {
				changeType = "frontend.source_map_disappeared"
				importance = model.ImportanceMedium
				reason = "Public source map was removed or is no longer accessible"
			}

			chID := computeChangeID(changeType, a.Value)
			changes = append(changes, model.Change{
				ID:         chID,
				Type:       changeType,
				Subject:    a.Value,
				Old:        a,
				New:        nil,
				Importance: importance,
				Reason:     reason,
			})
		}
	}

	return changes
}

func diffFindings(oldFindings, newFindings []model.Finding) []model.Change {
	var changes []model.Change
	oldMap := make(map[string]model.Finding)
	newMap := make(map[string]model.Finding)

	for _, f := range oldFindings {
		oldMap[f.ID] = f
	}
	for _, f := range newFindings {
		newMap[f.ID] = f
	}

	// Findings appeared
	for id, f := range newMap {
		if _, exists := oldMap[id]; !exists {
			imp := model.ImportanceMedium
			if f.Severity == model.SeverityCritical || f.Severity == model.SeverityHigh {
				imp = model.ImportanceHigh
			} else if f.Severity == model.SeverityLow || f.Severity == model.SeverityInfo {
				imp = model.ImportanceLow
			}

			chID := computeChangeID("finding.appeared", f.RuleID+":"+f.Asset)
			changes = append(changes, model.Change{
				ID:         chID,
				Type:       "finding.appeared",
				Subject:    f.Asset,
				Old:        nil,
				New:        f,
				Importance: imp,
				Reason:     fmt.Sprintf("New finding: %s (%s)", f.Title, f.RuleID),
			})
		}
	}

	// Findings resolved
	for id, f := range oldMap {
		if _, exists := newMap[id]; !exists {
			imp := model.ImportanceLow
			if f.Severity == model.SeverityCritical || f.Severity == model.SeverityHigh {
				imp = model.ImportanceMedium
			}

			chID := computeChangeID("finding.resolved", f.RuleID+":"+f.Asset)
			changes = append(changes, model.Change{
				ID:         chID,
				Type:       "finding.resolved",
				Subject:    f.Asset,
				Old:        f,
				New:        nil,
				Importance: imp,
				Reason:     fmt.Sprintf("Finding resolved: %s (%s)", f.Title, f.RuleID),
			})
		}
	}

	return changes
}

func diffObservations(oldObs, newObs []model.Observation) []model.Change {
	var changes []model.Change

	findObs := func(list []model.Observation, kind, subject string) *model.Observation {
		for i := range list {
			if list[i].Kind == kind && (subject == "" || list[i].Subject == subject) {
				return &list[i]
			}
		}
		return nil
	}

	// Compare TLS
	oldTLS := findObs(oldObs, "tls_certificate", "")
	newTLS := findObs(newObs, "tls_certificate", "")
	if oldTLS != nil && newTLS != nil {
		oldFP := oldTLS.Data["fingerprint_sha256"]
		newFP := newTLS.Data["fingerprint_sha256"]
		if oldFP != newFP {
			changes = append(changes, model.Change{
				ID:         computeChangeID("tls.certificate_changed", newTLS.Subject),
				Type:       "tls.certificate_changed",
				Subject:    newTLS.Subject,
				Old:        oldFP,
				New:        newFP,
				Importance: model.ImportanceInfo,
				Reason:     "TLS leaf certificate was renewed or replaced",
			})
		}

		oldStatus := oldTLS.Data["verification_status"]
		newStatus := newTLS.Data["verification_status"]
		if oldStatus != newStatus {
			changes = append(changes, model.Change{
				ID:         computeChangeID("tls.validation_changed", newTLS.Subject),
				Type:       "tls.validation_changed",
				Subject:    newTLS.Subject,
				Old:        oldStatus,
				New:        newStatus,
				Importance: model.ImportanceHigh,
				Reason:     fmt.Sprintf("TLS certificate validation status changed from %v to %v", oldStatus, newStatus),
			})
		}
	}

	// Compare HTTP Root
	oldHTTP := findObs(oldObs, "http_response", "")
	newHTTP := findObs(newObs, "http_response", "")
	if oldHTTP != nil && newHTTP != nil {
		oldCode := oldHTTP.Data["status_code"]
		newCode := newHTTP.Data["status_code"]
		if oldCode != newCode {
			changes = append(changes, model.Change{
				ID:         computeChangeID("http.status_changed", newHTTP.Subject),
				Type:       "http.status_changed",
				Subject:    newHTTP.Subject,
				Old:        oldCode,
				New:        newCode,
				Importance: model.ImportanceMedium,
				Reason:     fmt.Sprintf("HTTP root status changed from %v to %v", oldCode, newCode),
			})
		}
	}

	// Compare Security Headers
	oldHeaders := findObs(oldObs, "security_headers", "")
	newHeaders := findObs(newObs, "security_headers", "")
	if oldHeaders != nil && newHeaders != nil {
		// Headers in old but missing in new (removed)
		for k, oldV := range oldHeaders.Data {
			newV, exists := newHeaders.Data[k]
			if !exists || newV == "" {
				imp := model.ImportanceLow
				if k == "strict_transport_security" || k == "content_security_policy" {
					imp = model.ImportanceMedium
				}
				changes = append(changes, model.Change{
					ID:         computeChangeID("http.security_header_removed", k),
					Type:       "http.security_header_removed",
					Subject:    k,
					Old:        oldV,
					New:        nil,
					Importance: imp,
					Reason:     fmt.Sprintf("Security header %s was removed", k),
				})
			} else if oldV != newV {
				changes = append(changes, model.Change{
					ID:         computeChangeID("http.security_header_changed", k),
					Type:       "http.security_header_changed",
					Subject:    k,
					Old:        oldV,
					New:        newV,
					Importance: model.ImportanceLow,
					Reason:     fmt.Sprintf("Security header %s value changed", k),
				})
			}
		}

		// Headers missing in old but present in new (added)
		for k, newV := range newHeaders.Data {
			if _, exists := oldHeaders.Data[k]; !exists && newV != "" {
				changes = append(changes, model.Change{
					ID:         computeChangeID("http.security_header_added", k),
					Type:       "http.security_header_added",
					Subject:    k,
					Old:        nil,
					New:        newV,
					Importance: model.ImportanceInfo,
					Reason:     fmt.Sprintf("Security header %s was added", k),
				})
			}
		}
	}

	return changes
}

func computeChangeID(changeType, subject string) string {
	h := sha256.Sum256([]byte(changeType + ":" + subject))
	return hex.EncodeToString(h[:])
}
