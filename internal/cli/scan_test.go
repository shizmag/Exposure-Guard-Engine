package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanPlanFlag(t *testing.T) {
	t.Run("plan_human", func(t *testing.T) {
		opts := &scanOptions{
			target:  "example.com",
			profile: "standard",
			mode:    "public",
			plan:    true,
			format:  "human",
		}

		err := runScan(t.Context(), opts)
		require.NoError(t, err)
	})

	t.Run("plan_json", func(t *testing.T) {
		opts := &scanOptions{
			target:  "example.com",
			profile: "standard",
			mode:    "public",
			plan:    true,
			format:  "json",
		}

		err := runScan(t.Context(), opts)
		require.NoError(t, err)
	})

	t.Run("plan_deep_unauthorized", func(t *testing.T) {
		opts := &scanOptions{
			target:  "example.com",
			profile: "deep",
			mode:    "public",
			plan:    true,
			format:  "json",
		}

		err := runScan(t.Context(), opts)
		assert.Error(t, err)
	})
}
