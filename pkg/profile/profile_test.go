package profile

import (
	"testing"

	"github.com/exposureguard/exposureguard/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProfileRegistry(t *testing.T) {
	profiles := List()
	require.Len(t, profiles, 3)

	assert.Equal(t, ProfileQuick, profiles[0].ID)
	assert.Equal(t, ProfileStandard, profiles[1].ID)
	assert.Equal(t, ProfileDeep, profiles[2].ID)

	def, ok := Get(ProfileStandard)
	assert.True(t, ok)
	assert.Equal(t, "Standard", def.Name)
	assert.True(t, def.SupportsNativeCheck("dns"))
	assert.True(t, def.SupportsNativeCheck("crawl"))
	assert.True(t, def.SupportsIntegration("subfinder"))
	assert.False(t, def.SupportsIntegration("katana"))

	quickDef, ok := Get(ProfileQuick)
	assert.True(t, ok)
	assert.True(t, quickDef.SupportsNativeCheck("dns"))
	assert.False(t, quickDef.SupportsNativeCheck("crawl"))
	assert.Empty(t, quickDef.Integrations)

	deepDef, ok := Get(ProfileDeep)
	assert.True(t, ok)
	assert.Equal(t, model.ScanModeOwned, deepDef.RequiredMode)
	assert.True(t, deepDef.SupportsIntegration("nuclei"))
	assert.True(t, deepDef.SupportsIntegration("katana"))
}

func TestProfileResolve(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectedID  Profile
		expectError bool
	}{
		{name: "empty defaults to standard", input: "", expectedID: ProfileStandard},
		{name: "standard", input: "standard", expectedID: ProfileStandard},
		{name: "standard uppercase", input: "STANDARD", expectedID: ProfileStandard},
		{name: "legacy website alias", input: "website", expectedID: ProfileStandard},
		{name: "quick", input: "quick", expectedID: ProfileQuick},
		{name: "deep", input: "deep", expectedID: ProfileDeep},
		{name: "unknown profile", input: "aggressive", expectError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			def, err := Resolve(tt.input)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedID, def.ID)
			}
		})
	}
}
