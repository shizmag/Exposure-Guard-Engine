//go:build windows

package integration

import (
	"os/exec"
	"time"
)

func prepareCommand(cmd *exec.Cmd) {
	// Process groups on Windows require Windows job objects; fallback to standard.
}

func terminateProcess(cmd *exec.Cmd, gracePeriod time.Duration) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
}
