package cli

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/exposureguard/exposureguard/integrations/nuclei"
	"github.com/exposureguard/exposureguard/internal/buildinfo"
	"github.com/exposureguard/exposureguard/pkg/integration"
	"github.com/spf13/cobra"
)

func distributionManifestPath() string {
	path := filepath.Join(integration.DefaultExposureGuardHome(), "distribution-manifest.json")
	if _, err := os.Stat(path); err == nil {
		return path
	}
	if executable, err := os.Executable(); err == nil {
		for _, candidate := range []string{filepath.Join(filepath.Dir(executable), "..", "distribution-manifest.json"), filepath.Join("/opt/exposureguard", "distribution-manifest.json")} {
			if _, err := os.Stat(candidate); err == nil {
				return candidate
			}
		}
	}
	return path
}

func fileSHA256(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

func verifiedDistributionManifest(binaryPath, fallback string) (map[string]any, error) {
	manifestPath := distributionManifestPath()
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return map[string]any{"engine_version": fallback, "engine_binary_sha256": fileSHA256(binaryPath)}, nil
	}
	var manifest map[string]any
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("invalid distribution manifest: %w", err)
	}
	if manifest["engine_version"] != buildinfo.Version {
		return nil, fmt.Errorf("distribution manifest engine version mismatch")
	}
	if manifest["engine_binary_sha256"] != fileSHA256(binaryPath) {
		return nil, fmt.Errorf("distribution manifest binary SHA-256 mismatch")
	}
	if manifest["toolchain_manifest_sha256"] != fmt.Sprintf("%x", sha256.Sum256(integration.EmbeddedToolsLockBytes())) {
		return nil, fmt.Errorf("distribution manifest toolchain fingerprint mismatch")
	}
	return manifest, nil
}

func newVersionCmd() *cobra.Command {
	var (
		jsonOutput bool
		format     string
	)

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print version and build metadata",
		RunE: func(cmd *cobra.Command, args []string) error {
			info := buildinfo.Get()
			if jsonOutput || format == "json" {
				binaryPath, _ := os.Executable()
				binaryHash := fileSHA256(binaryPath)
				manifest, err := verifiedDistributionManifest(binaryPath, info.Version)
				if err != nil {
					return err
				}
				output := struct {
					buildinfo.Info
					ToolchainManifestSHA256 string         `json:"toolchain_manifest_sha256"`
					NucleiRulesetVersion    string         `json:"nuclei_ruleset_version"`
					NucleiRulesetSHA256     string         `json:"nuclei_ruleset_sha256"`
					DistributionManifest    map[string]any `json:"distribution_manifest,omitempty"`
					EngineBinarySHA256      string         `json:"engine_binary_sha256"`
				}{
					Info:                    info,
					ToolchainManifestSHA256: fmt.Sprintf("%x", sha256.Sum256(integration.EmbeddedToolsLockBytes())),
					NucleiRulesetVersion:    nuclei.CuratedProfileVersion,
					NucleiRulesetSHA256:     nuclei.CuratedRulesetSHA256,
					DistributionManifest:    manifest,
					EngineBinarySHA256:      binaryHash,
				}
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(output)
			}

			fmt.Fprintf(os.Stdout, "%s %s (commit: %s, built: %s, %s)\n",
				info.Engine, info.Version, info.GitCommit, info.BuildDate, info.GoVersion)
			fmt.Fprintf(os.Stdout, "protocol version: %s, snapshot schema: %s\n",
				info.ProtocolVersion, info.SnapshotSchemaVersion)
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output version metadata as JSON")
	cmd.Flags().StringVar(&format, "format", "human", "output format: human, json")
	return cmd
}
