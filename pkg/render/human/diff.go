package human

import (
	"fmt"
	"io"
	"strings"

	"github.com/exposureguard/exposureguard/pkg/model"
)

// RenderDiff formats a slice of Changes into readable terminal text.
func RenderDiff(w io.Writer, changes []model.Change, _opts Options) error {
	var sb strings.Builder

	sb.WriteString("\nExposureGuard Snapshot Diff\n\n")
	if len(changes) == 0 {
		sb.WriteString("No state changes detected between snapshots.\n\n")
		_, err := io.WriteString(w, sb.String())
		return err
	}

	sb.WriteString(fmt.Sprintf("%d change(s) detected:\n\n", len(changes)))
	for _, ch := range changes {
		sb.WriteString(fmt.Sprintf("  [%s] %s\n      Subject: %s\n",
			strings.ToUpper(string(ch.Importance)), ch.Type, ch.Subject))
		if ch.Reason != "" {
			sb.WriteString(fmt.Sprintf("      Reason:  %s\n", ch.Reason))
		}
	}
	sb.WriteString("\n")

	_, err := io.WriteString(w, sb.String())
	return err
}
