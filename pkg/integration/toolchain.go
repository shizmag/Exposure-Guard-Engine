package integration

import (
	_ "embed"
	"encoding/json"
	"sync"
)

//go:embed tools.lock.json
var embeddedToolsLock []byte

// ToolChecksumEntry holds archive filename and cryptographic hash.
type ToolChecksumEntry struct {
	Archive string `json:"archive"`
	SHA256  string `json:"sha256"`
}

// ToolLockEntry defines the pinned version, upstream source, and binary metadata.
type ToolLockEntry struct {
	Version   string                       `json:"version"`
	Module    string                       `json:"module,omitempty"`
	Upstream  string                       `json:"upstream,omitempty"`
	Binary    string                       `json:"binary,omitempty"`
	Checksums map[string]ToolChecksumEntry `json:"checksums,omitempty"`
	Archive   string                       `json:"archive,omitempty"`
	SHA256    string                       `json:"sha256,omitempty"`
}

// ToolsLockManifest models the root tools.lock.json schema.
type ToolsLockManifest struct {
	Version string                   `json:"version"`
	Tools   map[string]ToolLockEntry `json:"tools"`
}

var (
	toolsLockManifest *ToolsLockManifest
	toolsLockOnce     sync.Once
)

// GetToolsLock returns the parsed embedded tools.lock.json manifest.
func GetToolsLock() *ToolsLockManifest {
	toolsLockOnce.Do(func() {
		var m ToolsLockManifest
		if err := json.Unmarshal(embeddedToolsLock, &m); err == nil {
			toolsLockManifest = &m
		} else {
			toolsLockManifest = &ToolsLockManifest{Tools: make(map[string]ToolLockEntry)}
		}
	})
	return toolsLockManifest
}

// PinnedToolVersion returns the pinned version string for a given tool identifier.
func PinnedToolVersion(toolID string) string {
	m := GetToolsLock()
	if entry, ok := m.Tools[toolID]; ok {
		return entry.Version
	}
	return ""
}
