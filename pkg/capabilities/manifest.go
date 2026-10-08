// Package capabilities exposes the Engine's language-neutral release contract.
package capabilities

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

//go:embed manifest.json
var manifestBytes []byte

type Evidence struct {
	Started          string `json:"started"`
	Finished         string `json:"finished"`
	StatusField      string `json:"status_field"`
	ToolField        string `json:"tool_field,omitempty"`
	VersionField     string `json:"version_field,omitempty"`
	FingerprintField string `json:"fingerprint_field,omitempty"`
}

type Verification struct {
	ScenarioID string   `json:"scenario_id"`
	Checks     []string `json:"checks"`
}

type Capability struct {
	ID                string       `json:"id"`
	SemanticsVersion  string       `json:"semantics_version"`
	Kind              string       `json:"kind"`
	Profiles          []string     `json:"profiles"`
	Module            string       `json:"module,omitempty"`
	Integration       string       `json:"integration,omitempty"`
	Dependencies      []string     `json:"dependencies"`
	OwnershipRequired bool         `json:"ownership_required"`
	Evidence          Evidence     `json:"evidence"`
	Outputs           []string     `json:"outputs"`
	NotApplicable     []string     `json:"not_applicable"`
	Verification      Verification `json:"verification"`
}

type Profile struct {
	ID           string   `json:"id"`
	RequiredMode string   `json:"required_mode"`
	Capabilities []string `json:"capabilities"`
}

type Manifest struct {
	SchemaVersion            string       `json:"schema_version"`
	ContractVersion          string       `json:"contract_version"`
	ProtocolVersion          string       `json:"protocol_version"`
	BatchProtocolVersion     string       `json:"batch_protocol_version"`
	SnapshotSchemaVersion    string       `json:"snapshot_schema_version"`
	IdentityAlgorithmVersion string       `json:"identity_algorithm_version"`
	Capabilities             []Capability `json:"capabilities"`
	Profiles                 []Profile    `json:"profiles"`
}

func Load() (Manifest, error) {
	return Parse(manifestBytes)
}

func Parse(data []byte) (Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return Manifest{}, err
	}
	if err := m.Validate(); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

func JSON() ([]byte, error) {
	m, err := Load()
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(m, "", "  ")
}

func (m Manifest) Validate() error {
	if m.SchemaVersion != "1" || m.ContractVersion == "" || m.ProtocolVersion == "" || m.SnapshotSchemaVersion == "" || m.IdentityAlgorithmVersion == "" {
		return fmt.Errorf("capability manifest is missing a supported contract version")
	}
	capabilities := make(map[string]Capability, len(m.Capabilities))
	for _, c := range m.Capabilities {
		if strings.TrimSpace(c.ID) == "" || c.SemanticsVersion == "" || (c.Kind != "native" && c.Kind != "integration") || c.Verification.ScenarioID == "" || len(c.Verification.Checks) == 0 || len(c.Outputs) == 0 || c.Evidence.Started == "" || c.Evidence.Finished == "" || c.Evidence.StatusField == "" {
			return fmt.Errorf("capability %q is incomplete", c.ID)
		}
		if _, exists := capabilities[c.ID]; exists {
			return fmt.Errorf("duplicate capability %q", c.ID)
		}
		if c.Kind == "integration" && (c.Integration == "" || c.Evidence.ToolField == "" || c.Evidence.VersionField == "" || c.Evidence.FingerprintField == "") {
			return fmt.Errorf("integration capability %q has incomplete execution evidence", c.ID)
		}
		capabilities[c.ID] = c
	}
	profiles := make(map[string]struct{}, len(m.Profiles))
	for _, p := range m.Profiles {
		if p.ID == "" || (p.RequiredMode != "any" && p.RequiredMode != "owned") {
			return fmt.Errorf("profile %q is incomplete", p.ID)
		}
		if _, exists := profiles[p.ID]; exists {
			return fmt.Errorf("duplicate profile %q", p.ID)
		}
		profiles[p.ID] = struct{}{}
		for _, id := range p.Capabilities {
			c, exists := capabilities[id]
			if !exists {
				return fmt.Errorf("profile %q refers to unknown capability %q", p.ID, id)
			}
			if !slices.Contains(c.Profiles, p.ID) {
				return fmt.Errorf("profile %q and capability %q registration disagree", p.ID, id)
			}
		}
	}
	for _, c := range m.Capabilities {
		if len(c.Profiles) == 0 {
			return fmt.Errorf("capability %q has no profile coverage", c.ID)
		}
		for _, profileID := range c.Profiles {
			if _, ok := profiles[profileID]; !ok {
				return fmt.Errorf("capability %q refers to unknown profile %q", c.ID, profileID)
			}
		}
	}
	return nil
}
