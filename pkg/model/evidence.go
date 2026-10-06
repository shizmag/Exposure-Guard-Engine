package model

// Evidence contains safe, sanitized supporting facts for a Finding.
// Plaintext secrets or entire file bodies are NEVER included.
type Evidence struct {
	URL           string            `json:"url,omitempty"`
	MapURL        string            `json:"map_url,omitempty"`
	Fingerprint   string            `json:"fingerprint,omitempty"`
	SourcePaths   []string          `json:"source_paths,omitempty"`
	HasContent    bool              `json:"has_content,omitempty"`
	SourceCount   int               `json:"source_count,omitempty"`
	ContentSize   int64             `json:"content_size,omitempty"`
	MaskedPreview string            `json:"masked_preview,omitempty"`
	Offset        int               `json:"offset,omitempty"`
	Line          int               `json:"line,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
	Details       map[string]any    `json:"details,omitempty"`
}
