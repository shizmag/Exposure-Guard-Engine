package config

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/exposureguard/exposureguard/pkg/model"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

// Config holds runtime configuration options for the engine.
type Config struct {
	Format    string       `koanf:"format"`
	LogLevel  string       `koanf:"log_level"`
	NoColor   bool         `koanf:"no_color"`
	Profile   string       `koanf:"profile"`
	Mode      string       `koanf:"mode"`
	UserAgent string       `koanf:"user_agent"`
	Modules   []string     `koanf:"modules"`
	Disable   []string     `koanf:"disable_modules"`
	Limits    model.Limits `koanf:"limits"`
}

// Default returns a Config initialized with safe production defaults.
func Default() Config {
	return Config{
		Format:    "human",
		LogLevel:  "info",
		NoColor:   false,
		Profile:   "website",
		Mode:      string(model.ScanModePublic),
		UserAgent: "ExposureGuard/0.1.0 (+https://github.com/exposureguard/exposureguard)",
		Modules:   []string{"dns", "tls", "http", "headers", "cookies", "crawl", "javascript", "sourcemaps"},
		Limits:    model.DefaultLimits(),
	}
}

// Load reads and merges configuration from defaults, config file, and environment.
func Load(explicitPath string) (Config, error) {
	k := koanf.New(".")
	cfg := Default()

	// 1. Load config file if explicit or exists at default path
	path := explicitPath
	if path == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			defaultPath := filepath.Join(home, ".config", "exposureguard", "config.yaml")
			if _, err := os.Stat(defaultPath); err == nil {
				path = defaultPath
			}
		}
	}

	if path != "" {
		if err := k.Load(file.Provider(path), yaml.Parser()); err != nil && explicitPath != "" {
			return cfg, err
		}
	}

	// 2. Load environment variables EXPOSUREGUARD_*
	_ = k.Load(env.Provider("EXPOSUREGUARD_", ".", func(s string) string {
		return strings.ToLower(strings.TrimPrefix(s, "EXPOSUREGUARD_"))
	}), nil)

	// 3. Unmarshal onto cfg
	if err := k.Unmarshal("", &cfg); err != nil {
		return cfg, err
	}

	cfg.Limits.Clamp()
	return cfg, nil
}
