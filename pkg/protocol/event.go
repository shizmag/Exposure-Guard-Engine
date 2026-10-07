package protocol

import "time"

// EventType enumerates all JSONL streaming event types.
type EventType string

const (
	EventScanStarted     EventType = "scan.started"
	EventStageStarted    EventType = "stage.started"
	EventStageCompleted  EventType = "stage.completed"
	EventAssetDiscovered EventType = "asset.discovered"
	EventObservation     EventType = "observation"
	EventFinding         EventType = "finding"
	EventChange          EventType = "change"
	EventWarning         EventType = "warning"
	EventScanSummary     EventType = "scan.summary"
	EventScanCompleted   EventType = "scan.completed"
	EventScanFailed      EventType = "scan.failed"
	EventScanCancelled   EventType = "scan.cancelled"
)

// Envelope wraps every streaming JSONL event.
type Envelope struct {
	SchemaVersion string    `json:"schema_version"`
	Seq           int64     `json:"seq"`
	Timestamp     time.Time `json:"timestamp"`
	ScanID        string    `json:"scan_id"`
	Type          EventType `json:"type"`
	Data          any       `json:"data"`
}
