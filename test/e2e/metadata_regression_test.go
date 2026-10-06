package e2e_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMetadataEndpointRejectionRegression(t *testing.T) {
	binPath := filepath.Clean(filepath.Join("..", "..", "bin", "exposureguard"))
	if fi, err := os.Stat(binPath); err != nil || fi.IsDir() {
		t.Skip("bin/exposureguard not found, run make build first")
	}

	dangerousTargets := []string{
		"http://169.254.169.254/",
		"http://169.254.169.254:80/latest/meta-data/",
		"http://metadata.google.internal/",
		"http://instance-data/",
		"http://127.0.0.1:8080/",
		"http://localhost:8080/",
	}

	for _, target := range dangerousTargets {
		// 1. In standard default mode, must exit with error (code 3 or 2, blocked hostname)
		cmd := exec.Command(binPath, "scan", target)
		out, err := cmd.CombinedOutput()
		assert.Error(t, err, "default scan against %s must fail", target)
		assert.Contains(t, string(out), "blocked", "output should state target is blocked: %s", string(out))

		// 2. Even with --allow-private, cloud metadata endpoints MUST REMAIN BLOCKED!
		if target == "http://169.254.169.254/" ||
			target == "http://169.254.169.254:80/latest/meta-data/" ||
			target == "http://metadata.google.internal/" ||
			target == "http://instance-data/" {
			cmdPrivate := exec.Command(binPath, "scan", target, "--allow-private")
			outPrivate, errPrivate := cmdPrivate.CombinedOutput()
			require.Error(t, errPrivate, "scan with --allow-private against metadata %s must STILL fail", target)
			assert.Contains(t, string(outPrivate), "blocked", "metadata must be blocked even with --allow-private: %s", string(outPrivate))
		}
	}
}
