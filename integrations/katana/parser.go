package katana

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/url"
	"strings"

	"github.com/exposureguard/exposureguard/pkg/integration"
)

// Parse reads Katana JSONL output and streams mapped assets and observations to the emitter.
func Parse(ctx context.Context, input io.Reader, targetDomain string, emit integration.Emitter) error {
	if input == nil || emit == nil {
		return nil
	}

	scanner := bufio.NewScanner(input)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)

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
			// Skip banners or malformed lines defensively
			continue
		}

		if targetDomain == "" {
			if u, err := url.Parse(rec.Request.Endpoint); err == nil && u.Hostname() != "" {
				targetDomain = u.Hostname()
			}
		}

		MapRecord(rec, targetDomain, emit)
	}

	return scanner.Err()
}
