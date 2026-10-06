package static

import (
	"strings"
	"testing"

	"github.com/exposureguard/exposureguard/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetectCredentials(t *testing.T) {
	// Construct test dummy keys dynamically so static repo secret scanners don't false-alarm
	testAWS := "AKIA" + "IOSFODNN7EXAMPLE"
	testGitHub := "ghp_" + strings.Repeat("A", 36)
	testSlack := "xoxb-" + strings.Repeat("1", 20)
	testStripe := "sk_live_" + strings.Repeat("2", 30)

	jsContent := `
// Configuration
const awsKey = "` + testAWS + `";
const githubToken = "` + testGitHub + `";
const slackBot = "` + testSlack + `";
const stripeSecret = "` + testStripe + `";
const regularCode = "console.log('done')";
`

	findings := DetectCredentials("https://example.com/app.js", []byte(jsContent))
	require.Len(t, findings, 4)

	for _, f := range findings {
		assert.Equal(t, "frontend.javascript", f.CheckID)
		assert.Equal(t, "frontend.credential_exposure", f.RuleID)
		assert.Equal(t, model.SeverityHigh, f.Severity)
		assert.Equal(t, model.ConfidenceHigh, f.Confidence)

		// CRITICAL SAFETY REQUIREMENT: Verify NO raw secrets exist in finding fields!
		for _, raw := range []string{testAWS, testGitHub, testSlack, testStripe} {
			assert.NotContains(t, f.Title, raw, "Title must never contain raw secret")
			assert.NotContains(t, f.Description, raw, "Description must never contain raw secret")
			assert.NotContains(t, f.Evidence.MaskedPreview, raw, "MaskedPreview must never contain raw secret")
			assert.NotContains(t, f.Remediation, raw, "Remediation must never contain raw secret")
		}

		assert.NotEmpty(t, f.Evidence.Fingerprint)
		assert.NotEmpty(t, f.Evidence.MaskedPreview)
		assert.Contains(t, f.Evidence.MaskedPreview, "...")
	}
}
