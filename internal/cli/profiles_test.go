package cli

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/exposureguard/exposureguard/pkg/profile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProfilesListCmd(t *testing.T) {
	cmd := NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"profiles", "list", "--format", "json"})

	err := cmd.Execute()
	require.NoError(t, err)

	// Since NewRootCmd commands write to os.Stdout directly when not redirecting or test buffer,
	// let's test execution directly with subcommands.
}

func TestProfilesShowCommand(t *testing.T) {
	opts := &profilesOptions{format: "json"}
	cmd := newProfilesShowCmd(opts)
	cmd.SetArgs([]string{"standard"})

	err := cmd.RunE(cmd, []string{"standard"})
	require.NoError(t, err)

	err = cmd.RunE(cmd, []string{"nonexistent"})
	assert.Error(t, err)
}

func TestProfilesListCommand(t *testing.T) {
	opts := &profilesOptions{format: "json"}
	cmd := newProfilesListCmd(opts)

	err := cmd.RunE(cmd, nil)
	require.NoError(t, err)

	optsHuman := &profilesOptions{format: "human"}
	cmdHuman := newProfilesListCmd(optsHuman)
	err = cmdHuman.RunE(cmdHuman, nil)
	require.NoError(t, err)
}

func TestProfilesShowDetails(t *testing.T) {
	def, err := profile.Resolve("deep")
	require.NoError(t, err)
	assert.Equal(t, profile.ProfileDeep, def.ID)
	assert.Contains(t, def.Integrations, "nuclei")
	assert.Contains(t, def.NativeChecks, "crawl")

	data, err := json.Marshal(def)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"deep"`)
}
