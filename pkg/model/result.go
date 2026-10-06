package model

import "time"

// ScanStatus represents the terminal state of a scan.
type ScanStatus string

const (
	ScanStatusComplete ScanStatus = "complete"
	ScanStatusPartial  ScanStatus = "partial"
	ScanStatusFailed   ScanStatus = "failed"
)

// ScanStats captures performance and discovery metrics.
type ScanStats struct {
	RequestsAttempted   int64                    `json:"requests_attempted"`
	RequestsSuccessful  int64                    `json:"requests_successful"`
	BytesDownloaded     int64                    `json:"bytes_downloaded"`
	PagesCrawled        int                      `json:"pages_crawled"`
	AssetsDiscovered    int                      `json:"assets_discovered"`
	JSFilesAnalyzed     int                      `json:"js_files_analyzed"`
	SourceMapsDetected  int                      `json:"source_maps_detected"`
	TotalObservations   int                      `json:"total_observations"`
	TotalFindings       int                      `json:"total_findings"`
	TotalChanges        int                      `json:"total_changes"`
	IntegrationsRan     []string                 `json:"integrations_ran,omitempty"`
	IntegrationsSkipped []string                 `json:"integrations_skipped,omitempty"`
	IntegrationsFailed  []string                 `json:"integrations_failed,omitempty"`
	IntegrationMetrics  map[string]any           `json:"integration_metrics,omitempty"`
	DurationPerStage    map[string]time.Duration `json:"duration_per_stage,omitempty"`
	TotalDuration       time.Duration            `json:"total_duration"`
}

// ScanResult is the root machine output payload for `--format json`.
type ScanResult struct {
	Status                     ScanStatus `json:"status"`
	ScanID                     string     `json:"scan_id"`
	UnsafePrivateNetworkAccess bool       `json:"unsafe_private_network_access,omitempty"`
	Target                     Target     `json:"target"`
	Snapshot                   Snapshot   `json:"snapshot"`
	Changes                    []Change   `json:"changes,omitempty"`
	Summary                    ScanStats  `json:"summary"`
	StartedAt                  time.Time  `json:"started_at,omitzero"`
	CompletedAt                time.Time  `json:"completed_at,omitzero"`
	Errors                     []string   `json:"errors,omitempty"`
}
