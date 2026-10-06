package redact

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// MaskSecret returns a safe preview of a secret with the middle replaced by ellipses.
// Sensitive data is NEVER exposed in logs, snapshots, or events.
func MaskSecret(raw string) string {
	clean := strings.TrimSpace(raw)
	n := len(clean)
	if n == 0 {
		return ""
	}
	if n <= 6 {
		return "..."
	}
	if n <= 10 {
		return clean[:2] + "..." + clean[n-2:]
	}
	// For longer tokens (e.g. AKIA..., ghp_...)
	return clean[:4] + "..." + clean[n-4:]
}

// FingerprintSecret returns a deterministic SHA-256 hex digest of the raw secret.
func FingerprintSecret(raw string) string {
	h := sha256.Sum256([]byte(strings.TrimSpace(raw)))
	return hex.EncodeToString(h[:])
}

// SanitizeText replaces all occurrences of known sensitive values in text with their masked version.
func SanitizeText(text string, secrets ...string) string {
	res := text
	for _, sec := range secrets {
		clean := strings.TrimSpace(sec)
		if clean != "" && strings.Contains(res, clean) {
			res = strings.ReplaceAll(res, clean, MaskSecret(clean))
		}
	}
	return res
}
