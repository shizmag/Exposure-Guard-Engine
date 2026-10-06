package subfinder

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"strings"

	"github.com/exposureguard/exposureguard/pkg/integration"
)

// Parse reads Subfinder JSONL output and streams mapped assets and observations to the emitter.
func Parse(ctx context.Context, input io.Reader, emit integration.Emitter) error {
	if input == nil || emit == nil {
		return nil
	}

	scanner := bufio.NewScanner(input)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024) // up to 1MB per line

	for scanner.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var rec Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			// Skip malformed/banner non-JSON lines defensively
			continue
		}

		MapRecord(rec, emit)
	}

	return scanner.Err()
}
