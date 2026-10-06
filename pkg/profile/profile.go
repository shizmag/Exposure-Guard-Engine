package profile

import (
	"fmt"
	"slices"
	"strings"

	"github.com/exposureguard/exposureguard/pkg/model"
)

// Profile represents a recognized scan profile identifier.
type Profile string

const (
	ProfileQuick    Profile = "quick"
	ProfileStandard Profile = "standard"
	ProfileDeep     Profile = "deep"
)

// Definition encapsulates the formal execution contract of a scan profile.
type Definition struct {
	ID           Profile        `json:"id"`
	Name         string         `json:"name"`
	Description  string         `json:"description"`
	RequiredMode model.ScanMode `json:"required_mode,omitempty"`
	NativeChecks []string       `json:"native_checks"`
	Integrations []string       `json:"integrations"`
	Limits       model.Limits   `json:"limits"`
}

var registry = map[Profile]Definition{
	ProfileQuick: {
		ID:           ProfileQuick,
		Name:         "Quick",
		Description:  "Fast current-state check without crawling or external integrations",
		RequiredMode: "", // Permitted in any mode
		NativeChecks: []string{"dns", "tls", "http"},
		Integrations: []string{},
		Limits: model.Limits{
			TotalTimeoutSeconds:      30,
			RequestTimeoutSeconds:    5,
			DNSTimeoutSeconds:        3,
			MaxConcurrency:           5,
			MaxPerHostConcurrency:    2,
			RequestsPerSecondPerHost: 5.0,
			MaxDepth:                 0,
			MaxPages:                 1,
			MaxAssets:                50,
			MaxResponseBytes:         1 * 1024 * 1024, // 1MB
			MaxTotalDownloadBytes:    5 * 1024 * 1024, // 5MB
			MaxRedirects:             3,
		},
	},
	ProfileStandard: {
		ID:           ProfileStandard,
		Name:         "Standard",
		Description:  "Default outside-in scan with bounded crawling and passive discovery",
		RequiredMode: "", // Permitted in any mode
		NativeChecks: []string{"dns", "tls", "http", "crawl", "javascript", "sourcemaps"},
		Integrations: []string{"subfinder"},
		Limits: model.Limits{
			TotalTimeoutSeconds:      120,
			RequestTimeoutSeconds:    10,
			DNSTimeoutSeconds:        5,
			MaxConcurrency:           10,
			MaxPerHostConcurrency:    3,
			RequestsPerSecondPerHost: 10.0,
			MaxDepth:                 2,
			MaxPages:                 50,
			MaxAssets:                500,
			MaxResponseBytes:         5 * 1024 * 1024,  // 5MB
			MaxTotalDownloadBytes:    50 * 1024 * 1024, // 50MB
			MaxRedirects:             5,
		},
	},
	ProfileDeep: {
		ID:           ProfileDeep,
		Name:         "Deep",
		Description:  "Comprehensive authorized scan with deep crawling, reachability probing, and curated checks",
		RequiredMode: model.ScanModeOwned,
		NativeChecks: []string{"dns", "tls", "http", "crawl", "javascript", "sourcemaps"},
		Integrations: []string{"subfinder", "httpx", "katana", "nuclei"},
		Limits: model.Limits{
			TotalTimeoutSeconds:      300,
			RequestTimeoutSeconds:    15,
			DNSTimeoutSeconds:        5,
			MaxConcurrency:           15,
			MaxPerHostConcurrency:    5,
			RequestsPerSecondPerHost: 15.0,
			MaxDepth:                 3,
			MaxPages:                 150,
			MaxAssets:                1000,
			MaxResponseBytes:         10 * 1024 * 1024,  // 10MB
			MaxTotalDownloadBytes:    100 * 1024 * 1024, // 100MB
			MaxRedirects:             10,
		},
	},
}

// Get returns the profile definition for a given ID if registered.
func Get(id Profile) (Definition, bool) {
	d, ok := registry[id]
	return d, ok
}

// Default returns the default profile definition (Standard).
func Default() Definition {
	return registry[ProfileStandard]
}

// List returns all defined profiles in canonical order.
func List() []Definition {
	return []Definition{
		registry[ProfileQuick],
		registry[ProfileStandard],
		registry[ProfileDeep],
	}
}

// Resolve normalizes a profile string, resolves aliases (e.g. legacy "website" -> "standard"),
// and returns the matching Definition or an error if unrecognized.
func Resolve(name string) (Definition, error) {
	norm := strings.ToLower(strings.TrimSpace(name))
	if norm == "" || norm == "standard" || norm == "website" {
		return registry[ProfileStandard], nil
	}
	if norm == "quick" {
		return registry[ProfileQuick], nil
	}
	if norm == "deep" {
		return registry[ProfileDeep], nil
	}

	available := []string{string(ProfileQuick), string(ProfileStandard), string(ProfileDeep)}
	return Definition{}, fmt.Errorf("unknown profile %q (available: %s)", name, strings.Join(available, ", "))
}

// SupportsIntegration reports whether the profile by default enables the specified integration ID.
func (d Definition) SupportsIntegration(id string) bool {
	id = strings.ToLower(strings.TrimSpace(id))
	return slices.Contains(d.Integrations, id)
}

// SupportsNativeCheck reports whether the profile by default enables the specified native check module.
func (d Definition) SupportsNativeCheck(mod string) bool {
	mod = strings.ToLower(strings.TrimSpace(mod))
	return slices.Contains(d.NativeChecks, mod)
}
