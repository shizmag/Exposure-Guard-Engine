package protocol

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/exposureguard/exposureguard/internal/buildinfo"
)

// Encoder streams Envelope events as line-delimited JSON (JSONL).
type Encoder struct {
	w            io.Writer
	mu           sync.Mutex
	seq          int64
	scanID       string
	isTerminated bool
}

// NewEncoder creates a new JSONL encoder writing to w.
func NewEncoder(w io.Writer, scanID string) *Encoder {
	return &Encoder{
		w:      w,
		scanID: scanID,
	}
}

// Emit writes a single event to the underlying stream with monotonically increasing seq.
// Events emitted after EventScanCompleted or EventScanFailed are rejected.
func (e *Encoder) Emit(eventType EventType, data any) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.isTerminated {
		return fmt.Errorf("cannot emit event %q after terminal event", eventType)
	}

	e.seq++
	seq := e.seq

	if eventType == EventScanCompleted || eventType == EventScanFailed {
		e.isTerminated = true
	}

	env := Envelope{
		SchemaVersion: buildinfo.ProtocolVersion,
		Seq:           seq,
		Timestamp:     time.Now().UTC(),
		ScanID:        e.scanID,
		Type:          eventType,
		Data:          data,
	}

	payload, err := json.Marshal(env)
	if err != nil {
		return err
	}
	payload = append(payload, '\n')

	if _, err = e.w.Write(payload); err != nil {
		return err
	}
	if flusher, ok := e.w.(interface{ Flush() error }); ok {
		return flusher.Flush()
	}
	return nil
}
