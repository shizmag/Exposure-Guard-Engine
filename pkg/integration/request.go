package integration

import (
	"time"

	"github.com/exposureguard/exposureguard/pkg/model"
)

// Request defines the input specification passed to an adapter during plan construction.
type Request struct {
	Target        model.Target      `json:"target"`
	Mode          model.ScanMode    `json:"mode"`
	Profile       string            `json:"profile"`
	WorkDir       string            `json:"work_dir"`
	InputHosts    []string          `json:"input_hosts,omitempty"`
	InputURLs     []string          `json:"input_urls,omitempty"`
	Limits        model.Limits      `json:"limits"`
	Timeout       time.Duration     `json:"timeout"`
	TemplatesPath string            `json:"templates_path,omitempty"`
	CustomEnv     map[string]string `json:"custom_env,omitempty"`
	Options       map[string]any    `json:"options,omitempty"`
}
