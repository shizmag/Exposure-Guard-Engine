package protocol

import (
	"bytes"
	"encoding/json"
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

func TestEncoderConcurrent(t *testing.T) {
	buf := &bytes.Buffer{}
	enc := NewEncoder(buf, "scan-concurrent")

	var wg sync.WaitGroup
	count := 50
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

	seenSeqs := make(map[int64]bool)
	for _, l := range lines {
		var env Envelope
		require.NoError(t, json.Unmarshal([]byte(l), &env))
		assert.False(t, seenSeqs[env.Seq], "sequence numbers must be strictly unique")
		seenSeqs[env.Seq] = true
	}
	assert.Len(t, seenSeqs, count)
}
