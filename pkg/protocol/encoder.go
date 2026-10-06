package protocol

import (
	"encoding/json"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/exposureguard/exposureguard/internal/buildinfo"
)

// Encoder streams Envelope events as line-delimited JSON (JSONL).
type Encoder struct {
	w      io.Writer
	mu     sync.Mutex
	seq    atomic.Int64
	scanID string
}

// NewEncoder creates a new JSONL encoder writing to w.
func NewEncoder(w io.Writer, scanID string) *Encoder {
	return &Encoder{
		w:      w,
		scanID: scanID,
	}
}

// Emit writes a single event to the underlying stream with monotonically increasing seq.
func (e *Encoder) Emit(eventType EventType, data any) error {
	seq := e.seq.Add(1)

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

	e.mu.Lock()
	defer e.mu.Unlock()
	if _, err = e.w.Write(payload); err != nil {
		return err
	}
	if flusher, ok := e.w.(interface{ Flush() error }); ok {
		return flusher.Flush()
	}
	return nil
}
