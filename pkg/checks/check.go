package checks

import (
	"context"

	"github.com/exposureguard/exposureguard/pkg/model"
)

// Result aggregates assets, observations, and findings produced by a check.
type Result struct {
	Assets       []model.Asset
	Observations []model.Observation
	Findings     []model.Finding
}

// Check represents an isolated, safe defensive scanning unit.
type Check interface {
	ID() string
	Name() string
	Stage() string
	Run(ctx context.Context, env *Environment, target model.Target) (Result, error)
}
