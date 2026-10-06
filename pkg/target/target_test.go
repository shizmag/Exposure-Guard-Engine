package target

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	tests := []struct {
		input       string
		expectedURL string
		host        string
		port        uint16
		domain      string
		scheme      string
		wantErr     bool
	}{
		{
			input:       "example.com",
			expectedURL: "https://example.com/",
			host:        "example.com",
			port:        443,
			domain:      "example.com",
			scheme:      "https",
			wantErr:     false,
		},
		{
			input:       "https://example.com/",
			expectedURL: "https://example.com/",
			host:        "example.com",
			port:        443,
			domain:      "example.com",
			scheme:      "https",
			wantErr:     false,
		},
		{
			input:       "http://sub.example.co.uk:8080/path",
			expectedURL: "http://sub.example.co.uk:8080/path",
			host:        "sub.example.co.uk",
			port:        8080,
			domain:      "example.co.uk",
			scheme:      "http",
			wantErr:     false,
		},
		{
			input:   "ftp://example.com",
			wantErr: true,
		},
		{
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			res, err := Parse(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expectedURL, res.URL)
			assert.Equal(t, tt.host, res.Host)
			assert.Equal(t, tt.port, res.Port)
			assert.Equal(t, tt.domain, res.Domain)
			assert.Equal(t, tt.scheme, res.Scheme)
		})
	}
}

func TestScope(t *testing.T) {
	tgt, err := Parse("https://app.example.com")
	require.NoError(t, err)

	scope := NewScope(tgt)

	assert.Equal(t, RelationSameHost, scope.CheckHostname("app.example.com"))
	assert.Equal(t, RelationSameDomain, scope.CheckHostname("api.example.com"))
	assert.Equal(t, RelationSameDomain, scope.CheckHostname("example.com"))
	assert.Equal(t, RelationThirdParty, scope.CheckHostname("google.com"))
	assert.Equal(t, RelationThirdParty, scope.CheckHostname("cdn.other.com"))

	assert.True(t, scope.IsAllowedCrawl("https://app.example.com/about"))
	assert.False(t, scope.IsAllowedCrawl("https://api.example.com/v1"))
	assert.False(t, scope.IsAllowedCrawl("https://google.com/"))
}
