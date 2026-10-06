//go:build !windows

package integration

import (
	"os/exec"
	"syscall"
	"time"
)

func prepareCommand(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
}

func terminateProcess(cmd *exec.Cmd, gracePeriod time.Duration) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	pid := cmd.Process.Pid
	if pid <= 0 {
		return
	}

	// Signal the entire process group with negative PID
	_ = syscall.Kill(-pid, syscall.SIGTERM)

	// Wait up to grace period before SIGKILL
	deadline := time.Now().Add(gracePeriod)
	for time.Now().Before(deadline) {
		// Check if process is still alive using signal 0
		if err := syscall.Kill(-pid, syscall.Signal(0)); err != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Force kill entire group
	_ = syscall.Kill(-pid, syscall.SIGKILL)
}
