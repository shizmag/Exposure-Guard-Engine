package tls

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/exposureguard/exposureguard/pkg/checks"
	"github.com/exposureguard/exposureguard/pkg/model"
	"github.com/exposureguard/exposureguard/pkg/snapshot"
)

// Check inspects TLS configuration and certificates.
type Check struct{}

// NewCheck creates a new TLS check instance.
func NewCheck() *Check {
	return &Check{}
}

func (c *Check) ID() string    { return "tls.certificate" }
func (c *Check) Name() string  { return "TLS Certificate Inspection" }
func (c *Check) Stage() string { return "tls" }

func (c *Check) Run(ctx context.Context, env *checks.Environment, target model.Target) (checks.Result, error) {
	var result checks.Result

	if target.Scheme != "https" && target.Port != 443 {
		// Non-TLS target
		return result, nil
	}

	dialTimeout := time.Duration(env.Limits.TLSHandshakeTimeoutSeconds) * time.Second
	safeDialer := env.NewDialer(dialTimeout)

	targetAddr := net.JoinHostPort(target.Host, strconv.Itoa(int(target.Port)))

	rawConn, err := safeDialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return result, fmt.Errorf("TLS dial failed for %s: %w", targetAddr, err)
	}
	defer rawConn.Close()

	tlsConfig := &tls.Config{
		ServerName: target.Host,
		// InsecureSkipVerify is enabled ONLY on this raw probe so we can read and
		// evaluate invalid/expired cert chains manually rather than aborting prematurely.
		InsecureSkipVerify: true, //nolint:gosec
		MinVersion:         tls.VersionTLS12,
	}

	tlsConn := tls.Client(rawConn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return result, fmt.Errorf("TLS handshake failed for %s: %w", targetAddr, err)
	}
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return result, fmt.Errorf("no peer certificates presented by %s", targetAddr)
	}

	leaf := state.PeerCertificates[0]
	now := time.Now().UTC()

	// Compute fingerprint
	fpBytes := sha256.Sum256(leaf.Raw)
	fingerprint := hex.EncodeToString(fpBytes[:])

	daysUntil := int(leaf.NotAfter.Sub(now).Hours() / 24)

	// Validate certificate chain & hostname manually
	verifyOpts := x509.VerifyOptions{
		DNSName:     target.Host,
		CurrentTime: now,
	}
	if len(state.PeerCertificates) > 1 {
		intermediates := x509.NewCertPool()
		for _, cert := range state.PeerCertificates[1:] {
			intermediates.AddCert(cert)
		}
		verifyOpts.Intermediates = intermediates
	}

	var verifyError string
	_, err = leaf.Verify(verifyOpts)
	if err != nil {
		verifyError = err.Error()
	}

	obsData := map[string]any{
		"fingerprint_sha256":  fingerprint,
		"subject":             leaf.Subject.String(),
		"issuer":              leaf.Issuer.String(),
		"serial_number":       leaf.SerialNumber.String(),
		"san_dns_names":       leaf.DNSNames,
		"not_before":          leaf.NotBefore.Format(time.RFC3339),
		"not_after":           leaf.NotAfter.Format(time.RFC3339),
		"days_until_expire":   daysUntil,
		"version":             tls.VersionName(state.Version),
		"cipher_suite":        tls.CipherSuiteName(state.CipherSuite),
		"alpn":                state.NegotiatedProtocol,
		"verification_status": "valid",
	}
	if verifyError != "" {
		obsData["verification_status"] = "invalid"
		obsData["verification_error"] = verifyError
	}

	obsID := snapshot.StableID("observation", "tls_certificate", target.Host, fingerprint)
	result.Observations = append(result.Observations, model.Observation{
		ID:      obsID,
		Kind:    "tls_certificate",
		Scope:   "tls",
		Subject: target.Host,
		Data:    obsData,
	})

	// Derive Findings
	assetRef := target.URL

	// 1. Expired certificate
	if now.After(leaf.NotAfter) {
		findingID := snapshot.ComputeFindingID("tls.expired", target.Host, fingerprint)
		result.Findings = append(result.Findings, model.Finding{
			ID:          findingID,
			CheckID:     c.ID(),
			RuleID:      "tls.expired",
			Severity:    model.SeverityHigh,
			Confidence:  model.ConfidenceHigh,
			Title:       "TLS Certificate Expired",
			Description: fmt.Sprintf("The SSL/TLS certificate expired on %s.", leaf.NotAfter.Format("2006-01-02")),
			Asset:       assetRef,
			Evidence: model.Evidence{
				Fingerprint: fingerprint,
				Details: map[string]any{
					"expired_at": leaf.NotAfter.Format(time.RFC3339),
				},
			},
			Remediation: "Renew and deploy a valid SSL/TLS certificate.",
		})
	} else if daysUntil <= 7 {
		findingID := snapshot.ComputeFindingID("tls.expires_soon", target.Host, fingerprint)
		result.Findings = append(result.Findings, model.Finding{
			ID:          findingID,
			CheckID:     c.ID(),
			RuleID:      "tls.expires_soon",
			Severity:    model.SeverityHigh,
			Confidence:  model.ConfidenceHigh,
			Title:       "TLS Certificate Expires in <= 7 Days",
			Description: fmt.Sprintf("Certificate will expire in %d days on %s.", daysUntil, leaf.NotAfter.Format("2006-01-02")),
			Asset:       assetRef,
			Evidence: model.Evidence{
				Fingerprint: fingerprint,
				Details: map[string]any{
					"days_until_expiration": daysUntil,
				},
			},
			Remediation: "Renew SSL/TLS certificate immediately.",
		})
	} else if daysUntil <= 14 {
		findingID := snapshot.ComputeFindingID("tls.expires_soon", target.Host, fingerprint)
		result.Findings = append(result.Findings, model.Finding{
			ID:          findingID,
			CheckID:     c.ID(),
			RuleID:      "tls.expires_soon",
			Severity:    model.SeverityMedium,
			Confidence:  model.ConfidenceHigh,
			Title:       "TLS Certificate Expires in <= 14 Days",
			Description: fmt.Sprintf("Certificate will expire in %d days on %s.", daysUntil, leaf.NotAfter.Format("2006-01-02")),
			Asset:       assetRef,
			Evidence: model.Evidence{
				Fingerprint: fingerprint,
				Details: map[string]any{
					"days_until_expiration": daysUntil,
				},
			},
			Remediation: "Schedule SSL/TLS certificate renewal.",
		})
	} else if daysUntil <= 30 {
		findingID := snapshot.ComputeFindingID("tls.expires_soon", target.Host, fingerprint)
		result.Findings = append(result.Findings, model.Finding{
			ID:          findingID,
			CheckID:     c.ID(),
			RuleID:      "tls.expires_soon",
			Severity:    model.SeverityLow,
			Confidence:  model.ConfidenceHigh,
			Title:       "TLS Certificate Expires in <= 30 Days",
			Description: fmt.Sprintf("Certificate will expire in %d days on %s.", daysUntil, leaf.NotAfter.Format("2006-01-02")),
			Asset:       assetRef,
			Evidence: model.Evidence{
				Fingerprint: fingerprint,
				Details: map[string]any{
					"days_until_expiration": daysUntil,
				},
			},
			Remediation: "Plan SSL/TLS certificate renewal.",
		})
	}

	// Hostname mismatch finding
	if verifyError != "" && strings.Contains(strings.ToLower(verifyError), "certificate is valid for") {
		findingID := snapshot.ComputeFindingID("tls.hostname_mismatch", target.Host, fingerprint)
		result.Findings = append(result.Findings, model.Finding{
			ID:          findingID,
			CheckID:     c.ID(),
			RuleID:      "tls.hostname_mismatch",
			Severity:    model.SeverityHigh,
			Confidence:  model.ConfidenceHigh,
			Title:       "TLS Certificate Hostname Mismatch",
			Description: fmt.Sprintf("Presented certificate does not match target host %q: %s", target.Host, verifyError),
			Asset:       assetRef,
			Evidence: model.Evidence{
				Fingerprint: fingerprint,
				Details: map[string]any{
					"san_dns_names": leaf.DNSNames,
				},
			},
			Remediation: "Issue and configure a certificate that includes this hostname in its Subject Alternative Names.",
		})
	}

	return result, nil
}
