package redact

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRedactURL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "no secrets",
			input:    "https://example.com/path?foo=bar",
			expected: "https://example.com/path?foo=bar",
		},
		{
			name:     "userinfo password",
			input:    "https://user:secretpass123@example.com/resource",
			expected: "https://user:REDACTED@example.com/resource",
		},
		{
			name:     "token query param",
			input:    "https://example.com/api?token=secret123&page=2",
			expected: "https://example.com/api?page=2&token=REDACTED",
		},
		{
			name:     "apikey query param",
			input:    "https://example.com/api?apikey=AIzaSy12345",
			expected: "https://example.com/api?apikey=REDACTED",
		},
		{
			name:     "combined userinfo and token",
			input:    "https://admin:mypass@example.com/api?access_token=xyz987&sort=desc",
			expected: "https://admin:REDACTED@example.com/api?access_token=REDACTED&sort=desc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := RedactURL(tt.input)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
