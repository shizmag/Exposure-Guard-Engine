package protocol

import (
	"encoding/json"
	"errors"
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
	err          error
	maxBytes     int64
	written      int64
}

// NewEncoder creates a new JSONL encoder writing to w.
func NewEncoder(w io.Writer, scanID string) *Encoder {
	return NewEncoderWithLimit(w, scanID, 0)
}

// NewEncoderWithLimit creates a scan JSONL encoder with an optional byte limit.
func NewEncoderWithLimit(w io.Writer, scanID string, limit int64) *Encoder {
	return &Encoder{w: w, scanID: scanID, maxBytes: limit}
}

// Error returns the first output failure recorded by this encoder.
func (e *Encoder) Error() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.err
}

// Emit writes a single event to the underlying stream with monotonically increasing seq.
// Events emitted after any scan terminal event are rejected.
func (e *Encoder) Emit(eventType EventType, data any) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.err != nil {
		return e.err
	}
	if e.isTerminated {
		return fmt.Errorf("cannot emit event %q after terminal event", eventType)
	}

	e.seq++
	seq := e.seq

	if eventType == EventScanCompleted || eventType == EventScanFailed || eventType == EventScanCancelled {
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
	if e.maxBytes > 0 && e.written+int64(len(payload)) > e.maxBytes {
		e.err = errors.New("scan event output budget exceeded")
		return e.err
	}

	if _, err = e.w.Write(payload); err != nil {
		e.err = err
		return err
	}
	e.written += int64(len(payload))
	if flusher, ok := e.w.(interface{ Flush() error }); ok {
		if err := flusher.Flush(); err != nil {
			e.err = err
			return err
		}
	}
	return nil
}
