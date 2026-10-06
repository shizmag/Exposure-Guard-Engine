package model

import "time"

// Observation represents a normalized established fact about the target or an asset.
type Observation struct {
	ID        string         `json:"id"`
	Kind      string         `json:"kind"`
	Scope     string         `json:"scope,omitempty"`
	Subject   string         `json:"subject"`
	Data      map[string]any `json:"data"`
	Timestamp time.Time      `json:"timestamp,omitzero"`
}
