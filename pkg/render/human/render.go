package human

import (
	"fmt"
	"io"
	"strings"

	"github.com/exposureguard/exposureguard/pkg/model"
)

// Options controls formatting behavior for human output.
type Options struct {
	NoColor bool
}

// Render prints a user-friendly overview of the scan result.
func Render(w io.Writer, res *model.ScanResult, opts Options) error {
	var sb strings.Builder

	sb.WriteString("\nExposureGuard\n\n")
	fmt.Fprintf(&sb, "Target: %s\n\n", res.Target.URL)

	// DNS Section
	sb.WriteString("DNS\n")
	var aRecords, nsRecords []string
	for _, obs := range res.Snapshot.Observations {
		if obs.Kind == "dns_record" {
			if t, ok := obs.Data["record_type"].(string); ok {
				val, _ := obs.Data["value"].(string)
				if t == "A" || t == "AAAA" {
					aRecords = append(aRecords, val)
				} else if t == "NS" {
					nsRecords = append(nsRecords, val)
				}
			}
		}
	}
	if len(aRecords) > 0 {
		fmt.Fprintf(&sb, "  ✓ resolved (IPs: %s)\n", strings.Join(aRecords, ", "))
	} else {
		sb.WriteString("  - no DNS records recorded\n")
	}

	// TLS Section
	sb.WriteString("\nTLS\n")
	foundTLS := false
	for _, obs := range res.Snapshot.Observations {
		if obs.Kind == "tls_certificate" {
			foundTLS = true
			status, _ := obs.Data["verification_status"].(string)
			days, _ := obs.Data["days_until_expire"].(int)
			if status == "valid" {
				fmt.Fprintf(&sb, "  ✓ certificate valid (expires in %d days)\n", days)
			} else {
				fmt.Fprintf(&sb, "  ⚠ certificate invalid or unverified (%s)\n", status)
			}
		}
	}
	if !foundTLS {
		sb.WriteString("  - non-TLS target or uninspected\n")
	}

	// HTTP Section
	sb.WriteString("\nHTTP\n")
	for _, obs := range res.Snapshot.Observations {
		if obs.Kind == "http_response" {
			status, _ := obs.Data["status_code"].(int)
			fmt.Fprintf(&sb, "  ✓ response status %d\n", status)
		}
	}
	hasCSP := false
	for _, obs := range res.Snapshot.Observations {
		if obs.Kind == "security_headers" {
			if csp, ok := obs.Data["content_security_policy"].(string); ok && csp != "" {
				hasCSP = true
			}
		}
	}
	if hasCSP {
		sb.WriteString("  ✓ Content-Security-Policy present\n")
	} else {
		sb.WriteString("  ⚠ Content-Security-Policy absent\n")
	}

	// Frontend Section
	sb.WriteString("\nFrontend\n")
	var jsCount int
	var mapCount int
	for _, a := range res.Snapshot.Assets {
		if a.Kind == model.AssetKindJavaScript {
			jsCount++
		} else if a.Kind == model.AssetKindSourceMap {
			mapCount++
		}
	}
	sb.WriteString(fmt.Sprintf("  %d JavaScript assets discovered\n", jsCount))
	if mapCount > 0 {
		sb.WriteString(fmt.Sprintf("  ⚠ %d public source map(s) detected\n", mapCount))
	} else {
		sb.WriteString("  ✓ no public source maps detected\n")
	}

	// Summary Section
	sb.WriteString("\nSummary\n")
	sb.WriteString(fmt.Sprintf("  %d findings total (%d critical, %d high, %d medium, %d low)\n",
		res.Snapshot.Summary.TotalFindings,
		res.Snapshot.Summary.CriticalFindings,
		res.Snapshot.Summary.HighFindings,
		res.Snapshot.Summary.MediumFindings,
		res.Snapshot.Summary.LowFindings,
	))
	if len(res.Summary.IntegrationsRan) > 0 {
		fmt.Fprintf(&sb, "  Integrations: %s\n", strings.Join(res.Summary.IntegrationsRan, ", "))
	}
	if len(res.Summary.IntegrationsSkipped) > 0 {
		fmt.Fprintf(&sb, "  Skipped: %s\n", strings.Join(res.Summary.IntegrationsSkipped, ", "))
	}
	if len(res.Changes) > 0 {
		sb.WriteString(fmt.Sprintf("  %d state change(s) detected compared to previous snapshot\n", len(res.Changes)))
	}
	sb.WriteString(fmt.Sprintf("  Duration: %s\n\n", res.Summary.TotalDuration.Round(100*1000*1000))) // round to 100ms

	// Findings listing if any
	if len(res.Snapshot.Findings) > 0 {
		sb.WriteString("Findings:\n")
		for _, f := range res.Snapshot.Findings {
			sb.WriteString(fmt.Sprintf("  [%s] %s (%s)\n      Asset: %s\n",
				strings.ToUpper(string(f.Severity)), f.Title, f.RuleID, f.Asset))
			if f.Evidence.MaskedPreview != "" {
				sb.WriteString(fmt.Sprintf("      Preview: %s\n", f.Evidence.MaskedPreview))
			}
		}
		sb.WriteString("\n")
	}

	_, err := io.WriteString(w, sb.String())
	return err
}
