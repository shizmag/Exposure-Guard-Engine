package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncoderSequential(t *testing.T) {
	buf := &bytes.Buffer{}
	enc := NewEncoder(buf, "test-scan-123")

	err := enc.Emit(EventScanStarted, map[string]string{"target": "example.com"})
	require.NoError(t, err)

	err = enc.Emit(EventObservation, map[string]string{"status": "ok"})
	require.NoError(t, err)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	require.Len(t, lines, 2)

	var env1, env2 Envelope
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &env1))
	require.NoError(t, json.Unmarshal([]byte(lines[1]), &env2))

	assert.Equal(t, int64(1), env1.Seq)
	assert.Equal(t, EventScanStarted, env1.Type)
	assert.Equal(t, "test-scan-123", env1.ScanID)

	assert.Equal(t, int64(2), env2.Seq)
	assert.Equal(t, EventObservation, env2.Type)
}

func TestEncoderConcurrentStrictOrder(t *testing.T) {
	buf := &bytes.Buffer{}
	enc := NewEncoder(buf, "scan-concurrent")

	var wg sync.WaitGroup
	count := 100
	wg.Add(count)

	for i := 0; i < count; i++ {
		go func(idx int) {
			defer wg.Done()
			_ = enc.Emit(EventFinding, map[string]int{"index": idx})
		}(i)
	}

	wg.Wait()

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	require.Len(t, lines, count)

	for i, l := range lines {
		var env Envelope
		require.NoError(t, json.Unmarshal([]byte(l), &env), "JSON line %d must be valid", i)
		assert.Equal(t, int64(i+1), env.Seq, "sequence numbers in stream must be strictly monotonically increasing")
		assert.Equal(t, EventFinding, env.Type)
		assert.Equal(t, "scan-concurrent", env.ScanID)
	}
}

func TestEncoderHonorsOutputBudget(t *testing.T) {
	var output bytes.Buffer
	enc := NewEncoderWithLimit(&output, "scan-budget", 1)
	require.Error(t, enc.Emit(EventScanStarted, map[string]string{"target": "x"}))
	assert.LessOrEqual(t, output.Len(), 1)
}

func TestEncoderReturnsStdoutFailure(t *testing.T) {
	enc := NewEncoder(errorWriter{}, "scan-write-fail")
	require.Error(t, enc.Emit(EventScanStarted, nil))
	err := enc.Emit(EventScanSummary, nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errWriterFailure))
}

type errorWriter struct{}

var errWriterFailure = errors.New("stdout failed")

func (errorWriter) Write([]byte) (int, error) { return 0, errWriterFailure }

func TestEncoderTerminalGuarantees(t *testing.T) {
	t.Run("rejects_after_completed", func(t *testing.T) {
		buf := &bytes.Buffer{}
		enc := NewEncoder(buf, "scan-term-1")

		require.NoError(t, enc.Emit(EventScanStarted, map[string]string{"target": "example.com"}))
		require.NoError(t, enc.Emit(EventScanCompleted, map[string]string{"status": "complete"}))

		err := enc.Emit(EventFinding, map[string]string{"item": "late"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot emit event")
	})

	t.Run("rejects_after_failed", func(t *testing.T) {
		buf := &bytes.Buffer{}
		enc := NewEncoder(buf, "scan-term-2")

		require.NoError(t, enc.Emit(EventScanStarted, map[string]string{"target": "example.com"}))
		require.NoError(t, enc.Emit(EventScanFailed, map[string]string{"reason": "timeout"}))

		err := enc.Emit(EventObservation, map[string]string{"item": "late"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot emit event")
	})
}
