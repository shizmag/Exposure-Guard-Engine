package cli

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/exposureguard/exposureguard/internal/distribution"
)

func TestDoctorEngineOnlyPassesWithoutExternalTools(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"bin", "profiles/nuclei/v1", "schemas"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	copy := func(source, destination string) {
		data, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(destination, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	copy("../../tools.lock.json", filepath.Join(root, "tools.lock.json"))
	copy("../../schemas/distribution-manifest.schema.json", filepath.Join(root, "schemas/distribution-manifest.schema.json"))
	copy("../../profiles/nuclei/v1/manifest.json", filepath.Join(root, "profiles/nuclei/v1/manifest.json"))
	copy("../../profiles/nuclei/v1/templates.txt", filepath.Join(root, "profiles/nuclei/v1/templates.txt"))
	binary := filepath.Join(root, "bin", "exposureguard")
	build := exec.Command("go", "build", "-ldflags", "-X github.com/exposureguard/exposureguard/internal/buildinfo.Version=0.1.0-dev", "-o", binary, "../../cmd/exposureguard")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build doctor test binary: %v\n%s", err, output)
	}
	if _, err := distribution.Write(root, "0.1.0-dev", "unknown", filepath.Join(root, "schemas/distribution-manifest.schema.json")); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "doctor", "--format", "json")
	cmd.Env = append(os.Environ(), "EXPOSUREGUARD_HOME="+root)
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("doctor: %v", err)
	}
	var report struct {
		Status           string `json:"status"`
		AllReady         bool   `json:"all_ready"`
		DistributionType string `json:"distribution_type"`
	}
	if err := json.Unmarshal(output, &report); err != nil {
		t.Fatal(err)
	}
	if report.Status == "FAIL" || !report.AllReady || report.DistributionType != "engine-only" {
		t.Fatalf("engine-only doctor failed: %s", output)
	}
	if err := os.WriteFile(binary, []byte("tampered"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := distribution.Check(root, filepath.Join(root, "schemas/distribution-manifest.schema.json")); err == nil {
		t.Fatal("binary tampering did not fail distribution verification")
	}
}
