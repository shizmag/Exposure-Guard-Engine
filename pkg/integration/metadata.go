package integration

import (
	"slices"

	"github.com/exposureguard/exposureguard/pkg/model"
)

// RiskClass defines the operational risk category of an integration.
type RiskClass string

const (
	RiskClassPassive   RiskClass = "passive"
	RiskClassLowImpact RiskClass = "low-impact"
	RiskClassActive    RiskClass = "active"
)

// Metadata describes an integration's capabilities, requirements, and provenance.
type Metadata struct {
	ID                      string           `json:"id"`
	DisplayName             string           `json:"display_name"`
	Description             string           `json:"description"`
	Binary                  string           `json:"binary"`
	Capabilities            []Capability     `json:"capabilities"`
	SupportedModes          []model.ScanMode `json:"supported_modes"`
	MinimumSupportedVersion string           `json:"minimum_supported_version,omitempty"`
	TestedVersion           string           `json:"tested_version,omitempty"`
	UpstreamURL             string           `json:"upstream_url,omitempty"`
	RiskClass               RiskClass        `json:"risk_class"`
	Required                bool             `json:"required,omitempty"`
}

// SupportsMode checks if the integration is authorized to run in a given scan mode.
func (m Metadata) SupportsMode(mode model.ScanMode) bool {
	return slices.Contains(m.SupportedModes, mode)
}

// HasCapability checks if the integration provides the specified capability.
func (m Metadata) HasCapability(cap Capability) bool {
	return slices.Contains(m.Capabilities, cap)
}
