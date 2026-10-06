package static

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

// RawSourceMap matches v3 source map JSON schema structure.
type RawSourceMap struct {
	Version        int      `json:"version"`
	Sources        []string `json:"sources"`
	Mappings       string   `json:"mappings"`
	SourcesContent []string `json:"sourcesContent,omitempty"`
	File           string   `json:"file,omitempty"`
}

// SourceMapMetadata contains validated facts about a real source map without full code.
type SourceMapMetadata struct {
	Version       int      `json:"version"`
	SourceCount   int      `json:"source_count"`
	HasContent    bool     `json:"has_content"`
	SampleSources []string `json:"sample_sources"`
	Fingerprint   string   `json:"fingerprint"`
	ContentSize   int64    `json:"content_size"`
}

// ValidateSourceMap checks if payload is a genuine v3 JavaScript source map.
// HTML error pages returning 200 or generic JSON are rejected.
func ValidateSourceMap(data []byte) (*SourceMapMetadata, bool) {
	if len(data) == 0 {
		return nil, false
	}

	var sm RawSourceMap
	if err := json.Unmarshal(data, &sm); err != nil {
		return nil, false
	}

	// Must be v3 with sources array and mappings string
	if sm.Version != 3 || len(sm.Sources) == 0 || sm.Mappings == "" {
		return nil, false
	}

	fpBytes := sha256.Sum256(data)
	fp := hex.EncodeToString(fpBytes[:])

	// Collect up to 10 sample source paths
	limit := min(len(sm.Sources), 10)

	sampleSources := make([]string, 0, limit)
	for i := range limit {
		s := strings.TrimSpace(sm.Sources[i])
		if s != "" {
			sampleSources = append(sampleSources, s)
		}
	}
	sort.Strings(sampleSources)

	hasContent := len(sm.SourcesContent) > 0

	return &SourceMapMetadata{
		Version:       sm.Version,
		SourceCount:   len(sm.Sources),
		HasContent:    hasContent,
		SampleSources: sampleSources,
		Fingerprint:   fp,
		ContentSize:   int64(len(data)),
	}, true
}
