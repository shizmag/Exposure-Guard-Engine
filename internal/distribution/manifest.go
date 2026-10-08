package distribution

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/exposureguard/exposureguard/internal/buildinfo"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

var toolNames = []string{"subfinder", "httpx", "katana", "nuclei"}

type Tool struct {
	Version      string `json:"version"`
	BinarySHA256 string `json:"binary_sha256"`
}

type Manifest struct {
	DistributionSchemaVersion string          `json:"distribution_schema_version"`
	DistributionType          string          `json:"distribution_type"`
	DistributionCapabilities  []string        `json:"distribution_capabilities"`
	Engine                    string          `json:"engine"`
	EngineVersion             string          `json:"engine_version"`
	EngineCommit              string          `json:"engine_commit"`
	EngineBinarySHA256        string          `json:"engine_binary_sha256"`
	ProtocolVersion           string          `json:"protocol_version"`
	BatchProtocolVersion      string          `json:"batch_protocol_version"`
	SnapshotSchemaVersion     string          `json:"snapshot_schema_version"`
	IdentityAlgorithmVersion  string          `json:"identity_algorithm_version"`
	ToolchainManifestSHA256   string          `json:"toolchain_manifest_sha256"`
	Tools                     map[string]Tool `json:"tools"`
	NucleiTemplatesVersion    string          `json:"nuclei_templates_version"`
	NucleiTemplatesSHA256     string          `json:"nuclei_templates_sha256"`
	NucleiRulesetVersion      string          `json:"nuclei_ruleset_version"`
	NucleiRulesetSHA256       string          `json:"nuclei_ruleset_sha256"`
}

func shaFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// TreeSHA256 fingerprints sorted relative paths and each regular file's SHA-256.
func TreeSHA256(root string) (string, error) {
	var entries []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("tree entry is not a regular file: %s", path)
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		hash, err := shaFile(path)
		if err != nil {
			return err
		}
		entries = append(entries, filepath.ToSlash(rel)+"\x00"+hash)
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(entries)
	h := sha256.New()
	for _, entry := range entries {
		_, _ = h.Write([]byte(entry))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func Build(root string, engineVersion, commit string) (Manifest, error) {
	readJSON := func(path string, target any) error {
		data, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			return err
		}
		return json.Unmarshal(data, target)
	}
	lock := struct {
		Tools map[string]struct {
			Version string `json:"version"`
			SHA256  string `json:"sha256"`
			Archive string `json:"archive"`
		} `json:"tools"`
	}{}
	if err := readJSON("tools.lock.json", &lock); err != nil {
		return Manifest{}, fmt.Errorf("read tools.lock.json: %w", err)
	}
	manifest := Manifest{
		DistributionSchemaVersion: "1", DistributionType: "engine-only", DistributionCapabilities: []string{"native"},
		Engine: "exposureguard", EngineVersion: engineVersion, EngineCommit: commit,
		ProtocolVersion: buildinfo.ProtocolVersion, BatchProtocolVersion: buildinfo.BatchProtocolVersion,
		SnapshotSchemaVersion: buildinfo.SnapshotSchemaVersion, IdentityAlgorithmVersion: buildinfo.IdentityAlgorithmVersion,
		ToolchainManifestSHA256: "", Tools: map[string]Tool{},
		NucleiRulesetVersion: "v1.0-defensive",
	}
	var err error
	manifest.EngineBinarySHA256, err = shaFile(engineBinaryPath(root))
	if err != nil {
		return Manifest{}, err
	}
	manifest.ToolchainManifestSHA256, err = shaFile(filepath.Join(root, "tools.lock.json"))
	if err != nil {
		return Manifest{}, err
	}
	for _, name := range toolNames {
		path := filepath.Join(root, "bin", name)
		if runtime.GOOS == "windows" {
			path += ".exe"
		}
		if runtime.GOOS != "windows" {
			if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
				path += ".exe"
			}
		}
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return Manifest{}, err
		}
		if _, err := os.Stat(engineBinaryPath(root)); err != nil {
			return Manifest{}, errors.New("Engine binary is required before external tools")
		}
		hash, err := shaFile(path)
		if err != nil {
			return Manifest{}, err
		}
		manifest.Tools[name] = Tool{Version: lock.Tools[name].Version, BinarySHA256: hash}
	}
	if len(manifest.Tools) != 0 && len(manifest.Tools) != len(toolNames) {
		return Manifest{}, errors.New("external tools must be installed as complete pinned set")
	}
	if len(manifest.Tools) == len(toolNames) {
		manifest.DistributionType = "full"
		manifest.DistributionCapabilities = []string{"native", "subfinder", "httpx", "katana", "nuclei"}
		manifest.NucleiTemplatesVersion = lock.Tools["nuclei-templates"].Version
		manifest.NucleiTemplatesSHA256 = lock.Tools["nuclei-templates"].SHA256
	}
	if len(manifest.Tools) > 0 {
		templates := filepath.Join(root, "share", "nuclei-templates")
		if !dirExists(templates) {
			templates = filepath.Join(root, "templates")
		}
		if !dirExists(templates) {
			return Manifest{}, errors.New("full distribution requires installed Nuclei templates")
		}
		manifest.NucleiTemplatesSHA256, err = TreeSHA256(templates)
		if err != nil {
			return Manifest{}, err
		}
	} else {
		manifest.NucleiTemplatesVersion = ""
		manifest.NucleiTemplatesSHA256 = ""
	}
	manifest.NucleiRulesetSHA256, err = TreeSHA256(filepath.Join(root, "profiles", "nuclei", "v1"))
	if err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func engineBinaryPath(root string) string {
	path := filepath.Join(root, "bin", "exposureguard")
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return path + ".exe"
	}
	return path
}

func dirExists(path string) bool { info, err := os.Stat(path); return err == nil && info.IsDir() }

func Write(root, engineVersion, commit, schemaPath string) (Manifest, error) {
	manifest, err := Build(root, engineVersion, commit)
	if err != nil {
		return Manifest{}, err
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return Manifest{}, err
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(filepath.Join(root, "distribution-manifest.json"), encoded, 0o644); err != nil {
		return Manifest{}, err
	}
	return manifest, Check(root, schemaPath)
}

func Validate(manifestPath, schemaPath string) error {
	schemaData, err := os.ReadFile(schemaPath)
	if err != nil {
		return err
	}
	var schemaDoc any
	if err := json.Unmarshal(schemaData, &schemaDoc); err != nil {
		return err
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	if err := compiler.AddResource("https://exposureguard.dev/schemas/distribution-manifest.schema.json", schemaDoc); err != nil {
		return err
	}
	schema, err := compiler.Compile("https://exposureguard.dev/schemas/distribution-manifest.schema.json")
	if err != nil {
		return err
	}
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	var document any
	if err := json.Unmarshal(data, &document); err != nil {
		return err
	}
	if err := schema.Validate(document); err != nil {
		return fmt.Errorf("distribution manifest schema validation: %w", err)
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return err
	}
	if strings.TrimSpace(manifest.IdentityAlgorithmVersion) != buildinfo.IdentityAlgorithmVersion {
		return errors.New("identity algorithm version must be 1")
	}
	return nil
}

func Check(root, schemaPath string) error {
	if !filepath.IsAbs(schemaPath) {
		schemaPath = filepath.Join(root, schemaPath)
	}
	manifestPath := filepath.Join(root, "distribution-manifest.json")
	if err := Validate(manifestPath, schemaPath); err != nil {
		return err
	}
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return err
	}
	check := func(path, expected string) error {
		actual, err := shaFile(path)
		if err != nil {
			return err
		}
		if actual != expected {
			return fmt.Errorf("SHA-256 mismatch: %s", path)
		}
		return nil
	}
	if err := check(engineBinaryPath(root), manifest.EngineBinarySHA256); err != nil {
		return err
	}
	if err := check(filepath.Join(root, "tools.lock.json"), manifest.ToolchainManifestSHA256); err != nil {
		return err
	}
	for name, tool := range manifest.Tools {
		path := filepath.Join(root, "bin", name)
		if runtime.GOOS == "windows" {
			path += ".exe"
		}
		if runtime.GOOS != "windows" {
			if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
				path += ".exe"
			}
		}
		if err := check(path, tool.BinarySHA256); err != nil {
			return err
		}
	}
	if manifest.DistributionType == "full" {
		lock := struct {
			Tools map[string]struct {
				Version string `json:"version"`
			} `json:"tools"`
		}{}
		lockData, err := os.ReadFile(filepath.Join(root, "tools.lock.json"))
		if err != nil {
			return err
		}
		if err := json.Unmarshal(lockData, &lock); err != nil {
			return err
		}
		for _, name := range toolNames {
			tool, exists := manifest.Tools[name]
			if !exists {
				return fmt.Errorf("full distribution missing %s", name)
			}
			if tool.Version != lock.Tools[name].Version {
				return fmt.Errorf("%s version differs from tools.lock.json", name)
			}
			if _, err := os.Stat(filepath.Join(root, "bin", name)); err != nil && runtime.GOOS == "windows" {
				if _, err := os.Stat(filepath.Join(root, "bin", name+".exe")); err != nil {
					return fmt.Errorf("full distribution missing %s binary", name)
				}
			} else if err != nil {
				return fmt.Errorf("full distribution missing %s binary", name)
			}
		}
	}
	rules, err := TreeSHA256(filepath.Join(root, "profiles", "nuclei", "v1"))
	if err != nil {
		return err
	}
	if rules != manifest.NucleiRulesetSHA256 {
		return errors.New("curated ruleset fingerprint mismatch")
	}
	if manifest.DistributionType == "engine-only" && len(manifest.Tools) != 0 {
		return errors.New("engine-only distribution must not declare external tools")
	}
	if manifest.DistributionType == "full" {
		templates := filepath.Join(root, "share", "nuclei-templates")
		if !dirExists(templates) {
			templates = filepath.Join(root, "templates")
		}
		actual, err := TreeSHA256(templates)
		if err != nil {
			return err
		}
		if actual != manifest.NucleiTemplatesSHA256 {
			return errors.New("Nuclei runtime templates fingerprint mismatch")
		}
		if len(manifest.Tools) != len(toolNames) {
			return errors.New("full distribution requires all pinned tools")
		}
	}
	return nil
}
