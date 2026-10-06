package integration

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Runner manages process invocation, cancellation, output bounds, and path resolution.
type Runner interface {
	// LookPath searches for the executable binary using configured priority.
	LookPath(binary string) (string, error)

	// DetectVersion runs the binary with discovery arguments and extracts its semantic version string.
	DetectVersion(ctx context.Context, binary string, args []string) (string, error)

	// Run executes an ExecutionPlan safely under bounds and context cancellation.
	Run(ctx context.Context, plan ExecutionPlan) (*RunResult, error)
}

// DefaultExposureGuardHome returns the root directory for exposureguard managed tools and assets.
func DefaultExposureGuardHome() string {
	if h := os.Getenv("EXPOSUREGUARD_HOME"); h != "" {
		return h
	}
	userHome, err := os.UserHomeDir()
	if err != nil || userHome == "" {
		return "/tmp/exposureguard"
	}
	return filepath.Join(userHome, ".local", "share", "exposureguard")
}

// ResolveBinaryPath locates the binary following the discovery order:
// 1. Explicit environment variable: EXPOSUREGUARD_<BINARY>_PATH
// 2. $EXPOSUREGUARD_HOME/bin/<binary>
// 3. System PATH lookup
func ResolveBinaryPath(binary string) (string, error) {
	// 1. Check explicit environment override (e.g. EXPOSUREGUARD_SUBFINDER_PATH)
	envKey := "EXPOSUREGUARD_" + strings.ToUpper(strings.ReplaceAll(binary, "-", "_")) + "_PATH"
	if p := os.Getenv(envKey); p != "" {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p, nil
		}
	}

	// 2. Check $EXPOSUREGUARD_HOME/bin/<binary>
	home := DefaultExposureGuardHome()
	homeBin := filepath.Join(home, "bin", binary)
	if fi, err := os.Stat(homeBin); err == nil && !fi.IsDir() {
		return homeBin, nil
	}

	// 3. Fallback to system PATH
	return exec.LookPath(binary)
}

var (
	prefixedVersionRegex = regexp.MustCompile(`(?i)(?:version:?\s*v?|engine version:?\s*v?|current version:?\s*v?|v)([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
	bareVersionRegex     = regexp.MustCompile(`\b([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b`)
)

// ExtractVersion parses a semver-like version string from arbitrary CLI output.
func ExtractVersion(output string) string {
	if matches := prefixedVersionRegex.FindStringSubmatch(output); len(matches) > 1 {
		return matches[1]
	}
	if matches := bareVersionRegex.FindStringSubmatch(output); len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// CompareVersions compares two semver strings (e.g. "2.16.0" vs "2.6.0").
// Returns -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2.
func CompareVersions(v1, v2 string) int {
	clean1 := strings.TrimPrefix(strings.TrimSpace(v1), "v")
	clean2 := strings.TrimPrefix(strings.TrimSpace(v2), "v")

	parts1 := strings.Split(clean1, ".")
	parts2 := strings.Split(clean2, ".")

	maxLen := max(len(parts1), len(parts2))

	for i := range maxLen {
		var n1, n2 int
		if i < len(parts1) {
			n1, _ = strconv.Atoi(parts1[i])
		}
		if i < len(parts2) {
			n2, _ = strconv.Atoi(parts2[i])
		}
		if n1 < n2 {
			return -1
		}
		if n1 > n2 {
			return 1
		}
	}
	return 0
}
