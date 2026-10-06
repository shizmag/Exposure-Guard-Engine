package redact

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMaskSecret(t *testing.T) {
	assert.Equal(t, "", MaskSecret(""))
	assert.Equal(t, "...", MaskSecret("12345"))
	assert.Equal(t, "12...78", MaskSecret("12345678"))
	assert.Equal(t, "AKIA...MPLE", MaskSecret("AKIAIOSFODNN7EXAMPLE"))
	assert.Equal(t, "ghp_...3456", MaskSecret("ghp_1234567890abcdef1234567890abcdef3456"))
}

func TestFingerprintSecret(t *testing.T) {
	fp1 := FingerprintSecret("AKIAIOSFODNN7EXAMPLE")
	fp2 := FingerprintSecret("AKIAIOSFODNN7EXAMPLE")
	fp3 := FingerprintSecret("OTHER_SECRET_123")

	assert.Equal(t, fp1, fp2, "same secret must produce identical fingerprint")
	assert.NotEqual(t, fp1, fp3, "different secrets must produce distinct fingerprints")
	assert.Len(t, fp1, 64, "sha256 hex must be 64 characters")
}

func TestSanitizeText(t *testing.T) {
	sampleVal := "AKIA" + "IOSFODNN7EXAMPLE"
	rawText := "Discovered secret key: AKIAIOSFODNN7EXAMPLE in bundle.js"

	sanitized := SanitizeText(rawText, sampleVal)
	assert.NotContains(t, sanitized, sampleVal, "sanitized text must NOT contain raw secret")
	assert.Contains(t, sanitized, "AKIA...MPLE")
}

func FuzzMaskSecret(f *testing.F) {
	seeds := []string{
		"AKIAIOSFODNN7EXAMPLE",
		"ghp_1234567890abcdef1234567890abcdef3456",
		"",
		"short",
		"12345678",
		"very_long_secret_value_with_many_tokens_and_entropy_123456789",
	}

	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		masked := MaskSecret(s)
		if len(strings.TrimSpace(s)) > 8 {
			assert.NotEqual(t, s, masked, "masked output should not equal original secret")
		}
	})
}
