package checks

import (
	"testing"

	"github.com/exposureguard/exposureguard/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAllRules(t *testing.T) {
	rules := AllRules()
	require.NotEmpty(t, rules)
	assert.GreaterOrEqual(t, len(rules), 8)

	// Verify sorting by ID
	for i := 1; i < len(rules); i++ {
		assert.Less(t, rules[i-1].ID, rules[i].ID, "rules must be sorted deterministically by ID")
	}

	// Verify required fields
	for _, r := range rules {
		assert.NotEmpty(t, r.ID)
		assert.NotEmpty(t, r.Module)
		assert.NotEmpty(t, string(r.Severity))
		assert.NotEmpty(t, string(r.Confidence))
		assert.NotEmpty(t, r.Title)
		assert.NotEmpty(t, r.Description)
		assert.NotEmpty(t, r.Remediation)
	}

	// Test GetRule
	r, ok := GetRule("frontend.public_source_map")
	require.True(t, ok)
	assert.Equal(t, model.SeverityMedium, r.Severity)
	assert.Equal(t, "javascript", r.Module)

	_, ok = GetRule("nonexistent.rule")
	assert.False(t, ok)
}
