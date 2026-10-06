package human

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/exposureguard/exposureguard/pkg/model"
)

// Options controls formatting behavior for human output.
type Options struct {
	NoColor bool
	Quiet   bool
}

// Render prints a user-friendly overview of the scan result.
func Render(w io.Writer, res *model.ScanResult, opts Options) error {
	if res == nil {
		return nil
	}

	duration := res.Summary.TotalDuration.Round(100 * time.Millisecond)
	if duration == 0 && !res.CompletedAt.IsZero() && !res.StartedAt.IsZero() {
		duration = res.CompletedAt.Sub(res.StartedAt).Round(100 * time.Millisecond)
	}

	if opts.Quiet {
		_, err := fmt.Fprintf(w, "Target: %s — Scan completed in %s (%d assets, %d findings, %d changes)\n",
			res.Target.URL,
			duration,
			res.Summary.AssetsDiscovered,
			res.Summary.TotalFindings,
			res.Summary.TotalChanges,
		)
		return err
	}

	var sb strings.Builder

	sb.WriteString("\nExposureGuard\n\n")
	fmt.Fprintf(&sb, "Target\n  %s\n\n", res.Target.URL)

	if res.UnsafePrivateNetworkAccess {
		sb.WriteString("  ⚠ WARNING: Private network access enabled (--allow-private). Forbidden in production!\n\n")
	}

	// Surface breakdown
	var hostCount, pageCount, jsCount, endpointCount int
	for _, a := range res.Snapshot.Assets {
		switch a.Kind {
		case model.AssetKindHostname:
			hostCount++
		case model.AssetKindURL:
			pageCount++
		case model.AssetKindJavaScript:
			jsCount++
		case model.AssetKindEndpoint:
			endpointCount++
		}
	}
	if pageCount == 0 && res.Summary.PagesCrawled > 0 {
		pageCount = res.Summary.PagesCrawled
	}

	sb.WriteString("Surface\n")
	if hostCount > 0 {
		fmt.Fprintf(&sb, "  %d hostname(s)\n", hostCount)
	}
	if pageCount > 0 {
		fmt.Fprintf(&sb, "  %d page(s)\n", pageCount)
	}
	if jsCount > 0 {
		fmt.Fprintf(&sb, "  %d JavaScript asset(s)\n", jsCount)
	}
	if endpointCount > 0 {
		fmt.Fprintf(&sb, "  %d endpoint candidate(s)\n", endpointCount)
	}
	if hostCount == 0 && pageCount == 0 && jsCount == 0 && endpointCount == 0 {
		fmt.Fprintf(&sb, "  %d asset(s) discovered\n", len(res.Snapshot.Assets))
	}

	// TLS
	foundTLS := false
	for _, obs := range res.Snapshot.Observations {
		if obs.Kind == "tls_certificate" {
			foundTLS = true
			status, _ := obs.Data["verification_status"].(string)
			days, _ := obs.Data["days_until_expire"].(int)
			sb.WriteString("\nTLS\n")
			if status == "valid" {
				fmt.Fprintf(&sb, "  ✓ Valid (expires in %d days)\n", days)
			} else {
				fmt.Fprintf(&sb, "  ⚠ Invalid or unverified (%s)\n", status)
			}
			break
		}
	}
	if !foundTLS && (res.Target.Scheme == "https" || res.Target.Port == 443) {
		sb.WriteString("\nTLS\n  - Target TLS not verified\n")
	}

	// Findings summary
	sb.WriteString("\nFindings\n")
	if len(res.Snapshot.Findings) == 0 {
		sb.WriteString("  ✓ Zero exposures identified\n")
	} else {
		if res.Snapshot.Summary.CriticalFindings > 0 {
			fmt.Fprintf(&sb, "  ⚠ %d critical\n", res.Snapshot.Summary.CriticalFindings)
		}
		if res.Snapshot.Summary.HighFindings > 0 {
			fmt.Fprintf(&sb, "  ⚠ %d high\n", res.Snapshot.Summary.HighFindings)
		}
		if res.Snapshot.Summary.MediumFindings > 0 {
			fmt.Fprintf(&sb, "  · %d medium\n", res.Snapshot.Summary.MediumFindings)
		}
		if res.Snapshot.Summary.LowFindings > 0 {
			fmt.Fprintf(&sb, "  · %d low\n", res.Snapshot.Summary.LowFindings)
		}
		if res.Snapshot.Summary.InfoFindings > 0 {
			fmt.Fprintf(&sb, "  · %d info\n", res.Snapshot.Summary.InfoFindings)
		}

		sb.WriteString("\n")
		for _, f := range res.Snapshot.Findings {
			marker := "·"
			if f.Severity == model.SeverityCritical || f.Severity == model.SeverityHigh {
				marker = "⚠"
			}
			fmt.Fprintf(&sb, "  %s [%s] %s (%s)\n", marker, f.Severity, f.Title, f.RuleID)
			fmt.Fprintf(&sb, "    Asset: %s\n", f.Asset)
			if f.Evidence.MaskedPreview != "" {
				fmt.Fprintf(&sb, "    Preview: %s\n", f.Evidence.MaskedPreview)
			}
		}
	}

	// Changes summary if previous snapshot was provided
	if len(res.Changes) > 0 {
		sb.WriteString("\nChanges\n")
		for _, ch := range res.Changes {
			prefix := "~"
			if strings.HasSuffix(ch.Type, ".added") || strings.Contains(ch.Type, "_appeared") {
				prefix = "+"
			} else if strings.HasSuffix(ch.Type, ".removed") || strings.Contains(ch.Type, "_resolved") {
				prefix = "-"
			}
			fmt.Fprintf(&sb, "  %s %s\n", prefix, ch.Reason)
		}
	}

	fmt.Fprintf(&sb, "\nScan completed in %s\n", duration)

	_, err := io.WriteString(w, sb.String())
	return err
}
