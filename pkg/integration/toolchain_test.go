package integration_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/exposureguard/exposureguard/pkg/integration"
)

func TestToolsLockManifestDrift(t *testing.T) {
	rootManifestPath := filepath.Join("..", "..", "tools.lock.json")
	data, err := os.ReadFile(rootManifestPath)
	if err != nil {
		t.Fatalf("failed to read canonical /tools.lock.json: %v", err)
	}

	manifest := integration.GetToolsLock()
	if manifest == nil || len(manifest.Tools) == 0 {
		t.Fatalf("GetToolsLock() returned empty manifest")
	}

	// Verify that embedded manifest matches the canonical root tools.lock.json
	// by extracting versions and verifying JSON equivalence
	expectedTools := []string{"subfinder", "httpx", "katana", "nuclei", "nuclei-templates"}
	for _, tool := range expectedTools {
		v := integration.PinnedToolVersion(tool)
		if v == "" {
			t.Errorf("PinnedToolVersion(%q) is empty", tool)
		}
	}

	// Direct exact byte comparison against canonical /tools.lock.json
	if !bytes.Equal(data, integration.EmbeddedToolsLockBytes()) {
		t.Fatalf("drift detected: pkg/integration/tools_lock_gen.go does not match canonical /tools.lock.json. Run 'go generate ./pkg/integration/...' to resync.")
	}
}

func TestToolsLockManifestIntegrity(t *testing.T) {
	manifest := integration.GetToolsLock()
	if manifest.Version != "1.0" {
		t.Errorf("manifest.Version = %q; want %q", manifest.Version, "1.0")
	}

	requiredTools := []struct {
		id      string
		version string
	}{
		{"subfinder", "2.16.0"},
		{"httpx", "1.12.0"},
		{"katana", "1.8.0"},
		{"nuclei", "3.11.1"},
		{"nuclei-templates", "10.5.0"},
	}

	for _, req := range requiredTools {
		entry, ok := manifest.Tools[req.id]
		if !ok {
			t.Errorf("missing tool %q in tools.lock manifest", req.id)
			continue
		}
		if entry.Version != req.version {
			t.Errorf("tool %q version = %q; want %q", req.id, entry.Version, req.version)
		}
		if req.id == "nuclei-templates" {
			if entry.Archive == "" || len(entry.SHA256) != 64 {
				t.Errorf("nuclei-templates archive or sha256 invalid: %v", entry)
			}
			continue
		}

		platforms := []string{"darwin_amd64", "darwin_arm64", "linux_amd64", "linux_arm64"}
		for _, p := range platforms {
			chk, ok := entry.Checksums[p]
			if !ok {
				t.Errorf("tool %q missing platform checksum for %q", req.id, p)
				continue
			}
			if chk.Archive == "" || len(chk.SHA256) != 64 {
				t.Errorf("tool %q platform %q invalid archive/sha256: %v", req.id, p, chk)
			}
		}
	}
}
