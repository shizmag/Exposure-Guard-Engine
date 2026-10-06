package buildinfo

import "runtime"

var (
	// Version is the current release version of ExposureGuard Engine.
	Version = "0.1.0-dev"
	// GitCommit is the SHA of the git commit.
	GitCommit = "unknown"
	// BuildDate is the RFC3339 build timestamp.
	BuildDate = "unknown"
	// GoVersion is the Go runtime version.
	GoVersion = runtime.Version()
)

const (
	// ProtocolVersion is the machine JSONL protocol version.
	ProtocolVersion = "1"
	// SnapshotSchemaVersion is the normalized snapshot schema version.
	SnapshotSchemaVersion = "1"
	// EngineName is the official CLI/engine identifier.
	EngineName = "exposureguard"
)

// Info holds consolidated version metadata for JSON serialization.
type Info struct {
	Engine                string `json:"engine"`
	Version               string `json:"version"`
	GitCommit             string `json:"git_commit"`
	BuildDate             string `json:"build_date"`
	GoVersion             string `json:"go_version"`
	ProtocolVersion       string `json:"protocol_version"`
	SnapshotSchemaVersion string `json:"snapshot_schema_version"`
}

// Get returns the current BuildInfo.
func Get() Info {
	return Info{
		Engine:                EngineName,
		Version:               Version,
		GitCommit:             GitCommit,
		BuildDate:             BuildDate,
		GoVersion:             GoVersion,
		ProtocolVersion:       ProtocolVersion,
		SnapshotSchemaVersion: SnapshotSchemaVersion,
	}
}
