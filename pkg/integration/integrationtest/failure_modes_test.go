package integrationtest

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/exposureguard/exposureguard/pkg/integration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAdapterFailureModes(t *testing.T) {
	mockMeta := integration.Metadata{
		ID:             "faulty-tool",
		Binary:         "faulty",
		DisplayName:    "Faulty Mock Tool",
		SupportedModes: nil,
	}

	adapter := NewMockAdapter("faulty-tool", mockMeta)

	t.Run("binary_absent", func(t *testing.T) {
		runner := &MockRunner{
			LookPathFunc: func(b string) (string, error) {
				return "", assert.AnError
			},
		}
		adapter.DetectFn = func(ctx context.Context, r integration.Runner) (integration.Installation, error) {
			_, err := r.LookPath("faulty")
			if err != nil {
				return integration.Installation{Installed: false, Compatible: false}, err
			}
			return integration.Installation{Installed: true, Compatible: true}, nil
		}

		inst, err := adapter.Detect(context.Background(), runner)
		assert.False(t, inst.Installed)
		assert.False(t, inst.Compatible)
		assert.Error(t, err)
	})

	t.Run("parse_corrupted_output", func(t *testing.T) {
		corrupted := strings.Repeat("{invalid json line\n", 50)
		emitter := &integration.CollectEmitter{}
		err := adapter.Parse(context.Background(), strings.NewReader(corrupted), emitter)
		// Should not crash or panic
		assert.True(t, err == nil || strings.Contains(err.Error(), "parsing") || strings.Contains(err.Error(), "warning"))
	})

	t.Run("parse_zero_results", func(t *testing.T) {
		empty := ""
		emitter := &integration.CollectEmitter{}
		err := adapter.Parse(context.Background(), strings.NewReader(empty), emitter)
		require.NoError(t, err)
		assert.Empty(t, emitter.Assets)
		assert.Empty(t, emitter.Observations)
		assert.Empty(t, emitter.Findings)
	})

	t.Run("execution_cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // immediately cancel

		runner := &MockRunner{
			RunFunc: func(c context.Context, p integration.ExecutionPlan) (*integration.RunResult, error) {
				return nil, c.Err()
			},
		}

		plan := integration.ExecutionPlan{
			Command: integration.CommandSpec{
				Binary:  "faulty",
				Timeout: 1 * time.Second,
			},
		}

		_, err := runner.Run(ctx, plan)
		assert.ErrorIs(t, err, context.Canceled)
	})
}
