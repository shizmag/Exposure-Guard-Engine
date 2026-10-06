package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/exposureguard/exposureguard/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	cfg := Default()
	assert.Equal(t, "human", cfg.Format)
	assert.Equal(t, string(model.ScanModePublic), cfg.Mode)
	assert.Equal(t, 120, cfg.Limits.TotalTimeoutSeconds)
	assert.Equal(t, 8, cfg.Limits.MaxConcurrency)
}

func TestLoadConfigFile(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")
	content := `
format: json
log_level: debug
limits:
  max_concurrency: 12
  total_timeout_seconds: 60
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(content), 0o600))

	cfg, err := Load(cfgPath)
	require.NoError(t, err)
	assert.Equal(t, "json", cfg.Format)
	assert.Equal(t, "debug", cfg.LogLevel)
	assert.Equal(t, 12, cfg.Limits.MaxConcurrency)
	assert.Equal(t, 60, cfg.Limits.TotalTimeoutSeconds)
}
