package cli

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestChecksListCmd(t *testing.T) {
	optsJSON := &checksOptions{format: "json"}
	cmdJSON := newChecksListCmd(optsJSON)
	err := cmdJSON.RunE(cmdJSON, nil)
	require.NoError(t, err)

	optsHuman := &checksOptions{format: "human"}
	cmdHuman := newChecksListCmd(optsHuman)
	err = cmdHuman.RunE(cmdHuman, nil)
	require.NoError(t, err)
}
