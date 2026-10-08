package distribution

import (
	"os"
	"path/filepath"
	"testing"
)

func testDistributionRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"bin", "profiles/nuclei/v1", "schemas"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	copyFile := func(src, dst string) {
		t.Helper()
		data, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	copyFile("../../tools.lock.json", filepath.Join(root, "tools.lock.json"))
	copyFile("../../schemas/distribution-manifest.schema.json", filepath.Join(root, "schemas/distribution-manifest.schema.json"))
	copyFile("../../profiles/nuclei/v1/manifest.json", filepath.Join(root, "profiles/nuclei/v1/manifest.json"))
	copyFile("../../profiles/nuclei/v1/templates.txt", filepath.Join(root, "profiles/nuclei/v1/templates.txt"))
	if err := os.WriteFile(filepath.Join(root, "bin/exposureguard"), []byte("engine"), 0o755); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestBuildAndCheckEngineOnlyManifest(t *testing.T) {
	root := testDistributionRoot(t)
	schema := filepath.Join(root, "schemas/distribution-manifest.schema.json")
	manifest, err := Write(root, "0.1.0-rc1", "abc123", schema)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.DistributionType != "engine-only" || len(manifest.Tools) != 0 || manifest.IdentityAlgorithmVersion != "1" {
		t.Fatalf("unexpected engine-only manifest: %+v", manifest)
	}
	if err := Check(root, schema); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bin/exposureguard"), []byte("modified"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Check(root, schema); err == nil {
		t.Fatal("binary tampering passed distribution check")
	}
}

func TestBuildAndCheckFullManifestVerifiesRuntimeTreesAndTools(t *testing.T) {
	root := testDistributionRoot(t)
	for _, name := range toolNames {
		script := "#!/bin/sh\necho '" + name + " version 1.0.0'\n"
		if err := os.WriteFile(filepath.Join(root, "bin", name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	templates := filepath.Join(root, "share/nuclei-templates/http")
	if err := os.MkdirAll(templates, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(templates, "test.yaml"), []byte("id: test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	schema := filepath.Join(root, "schemas/distribution-manifest.schema.json")
	manifest, err := Write(root, "0.1.0-rc1", "abc123", schema)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.DistributionType != "full" || len(manifest.Tools) != len(toolNames) {
		t.Fatalf("unexpected full manifest: %+v", manifest)
	}
	if err := Check(root, schema); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bin/nuclei"), []byte("tampered"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Check(root, schema); err == nil {
		t.Fatal("tool tampering passed distribution check")
	}
	if _, err := Write(root, "0.1.0-rc1", "abc123", schema); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(templates, "test.yaml"), []byte("id: changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Check(root, schema); err == nil {
		t.Fatal("template tampering passed distribution check")
	}
}
