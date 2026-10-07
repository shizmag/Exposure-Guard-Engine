package cli

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/exposureguard/exposureguard/integrations/nuclei"
	"github.com/exposureguard/exposureguard/internal/buildinfo"
	"github.com/exposureguard/exposureguard/pkg/integration"
	"github.com/spf13/cobra"
)

type doctorOptions struct {
	format string
}

func newDoctorCmd() *cobra.Command {
	opts := &doctorOptions{}

	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Verify system health, runtime prerequisites, and external integration readiness",
		Long: `The doctor command checks the health of the ExposureGuard runtime environment,
verifies protocol and schema compatibility, tests external integrations (Subfinder, httpx,
Katana, Nuclei), validates template presence, and checks network deployment safety.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDoctor(cmd.Context(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.format, "format", "human", "output format: human, json")

	return cmd
}

// DoctorStatus represents a standard health check tier.
type DoctorStatus string

const (
	StatusPass DoctorStatus = "PASS"
	StatusWarn DoctorStatus = "WARN"
	StatusFail DoctorStatus = "FAIL"
)

type doctorEngineView struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	GitCommit string `json:"git_commit,omitempty"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

type doctorTempView struct {
	Path     string `json:"path"`
	Writable bool   `json:"writable"`
	Error    string `json:"error,omitempty"`
}

type doctorIntegrationItem struct {
	ID         string       `json:"id"`
	Binary     string       `json:"binary"`
	Path       string       `json:"path,omitempty"`
	Version    string       `json:"version,omitempty"`
	Installed  bool         `json:"installed"`
	Compatible bool         `json:"compatible"`
	Status     DoctorStatus `json:"status"`
	Warning    string       `json:"warning,omitempty"`
}

type doctorTemplatesView struct {
	Path       string       `json:"path,omitempty"`
	Present    bool         `json:"present"`
	Version    string       `json:"version,omitempty"`
	Compatible bool         `json:"compatible"`
	Status     DoctorStatus `json:"status"`
	Error      string       `json:"error,omitempty"`
}

type doctorNetworkSafetyView struct {
	Status  DoctorStatus `json:"status"`
	Message string       `json:"message"`
}

type doctorCheckItem struct {
	Name    string       `json:"name"`
	Status  DoctorStatus `json:"status"`
	Message string       `json:"message"`
}

type doctorReport struct {
	Status                     DoctorStatus            `json:"status"`
	Engine                     doctorEngineView        `json:"engine"`
	ProtocolVersion            string                  `json:"protocol_version"`
	SnapshotSchemaVersion      string                  `json:"snapshot_schema_version"`
	BatchProtocolVersion       string                  `json:"batch_protocol_version"`
	IdentityAlgorithmVersion   string                  `json:"identity_algorithm_version"`
	ToolchainManifestSHA256    string                  `json:"toolchain_manifest_sha256"`
	DistributionManifestSHA256 string                  `json:"distribution_manifest_sha256"`
	NucleiRulesetVersion       string                  `json:"nuclei_ruleset_version"`
	NucleiRulesetSHA256        string                  `json:"nuclei_ruleset_sha256"`
	MaxParallelScans           int                     `json:"max_parallel_scans"`
	TempDir                    doctorTempView          `json:"temp_dir"`
	Integrations               []doctorIntegrationItem `json:"integrations"`
	NucleiTemplates            doctorTemplatesView     `json:"nuclei_templates"`
	NetworkSafety              doctorNetworkSafetyView `json:"network_safety"`
	Checks                     []doctorCheckItem       `json:"checks"`
	AllReady                   bool                    `json:"all_ready"`
}

func runDoctor(ctx context.Context, opts *doctorOptions) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	overallStatus := StatusPass
	parallelScans, parallelErr := maxParallelScans()
	manifestHash, manifestErr := distributionManifestStatus()

	report := doctorReport{
		Engine: doctorEngineView{
			Name:      buildinfo.EngineName,
			Version:   buildinfo.Version,
			GitCommit: buildinfo.GitCommit,
			OS:        runtime.GOOS,
			Arch:      runtime.GOARCH,
		},
		ProtocolVersion:            buildinfo.ProtocolVersion,
		SnapshotSchemaVersion:      buildinfo.SnapshotSchemaVersion,
		BatchProtocolVersion:       buildinfo.BatchProtocolVersion,
		IdentityAlgorithmVersion:   buildinfo.IdentityAlgorithmVersion,
		ToolchainManifestSHA256:    fmt.Sprintf("%x", sha256.Sum256(integration.EmbeddedToolsLockBytes())),
		DistributionManifestSHA256: manifestHash,
		NucleiRulesetVersion:       nuclei.CuratedProfileVersion,
		NucleiRulesetSHA256:        nuclei.CuratedRulesetSHA256,
		MaxParallelScans:           parallelScans,
		NetworkSafety: doctorNetworkSafetyView{
			Status:  StatusWarn,
			Message: "Host cannot verify platform egress firewall; ensure scanner egress rules isolate RFC1918 and metadata in production.",
		},
		AllReady: true,
	}
	if manifestErr != nil {
		report.AllReady = false
		overallStatus = StatusFail
		report.Checks = append(report.Checks, doctorCheckItem{Name: "distribution_manifest", Status: StatusFail, Message: manifestErr.Error()})
	} else {
		report.Checks = append(report.Checks, doctorCheckItem{Name: "distribution_manifest", Status: StatusPass, Message: "Distribution fingerprint verified"})
	}
	if parallelErr != nil {
		report.AllReady = false
		overallStatus = StatusFail
		report.Checks = append(report.Checks, doctorCheckItem{Name: "batch_parallelism", Status: StatusFail, Message: parallelErr.Error()})
	} else {
		report.Checks = append(report.Checks, doctorCheckItem{Name: "batch_parallelism", Status: StatusPass, Message: fmt.Sprintf("Maximum parallel scans: %d", parallelScans)})
	}

	report.Checks = append(report.Checks, doctorCheckItem{
		Name:    "engine",
		Status:  StatusPass,
		Message: fmt.Sprintf("%s %s (%s/%s)", buildinfo.EngineName, buildinfo.Version, runtime.GOOS, runtime.GOARCH),
	})
	report.Checks = append(report.Checks, doctorCheckItem{
		Name:    "protocol",
		Status:  StatusPass,
		Message: fmt.Sprintf("Protocol v%s", buildinfo.ProtocolVersion),
	})
	report.Checks = append(report.Checks, doctorCheckItem{
		Name:    "snapshot_schema",
		Status:  StatusPass,
		Message: fmt.Sprintf("Snapshot Schema v%s", buildinfo.SnapshotSchemaVersion),
	})

	// 1. Check temporary execution directory
	testDir := filepath.Join(os.TempDir(), fmt.Sprintf("eg-doctor-%d", time.Now().UnixNano()))
	if err := os.MkdirAll(testDir, 0o700); err != nil {
		report.TempDir = doctorTempView{
			Path:     os.TempDir(),
			Writable: false,
			Error:    err.Error(),
		}
		report.AllReady = false
		overallStatus = StatusFail
		report.Checks = append(report.Checks, doctorCheckItem{
			Name:    "temp_dir",
			Status:  StatusFail,
			Message: fmt.Sprintf("Temp dir not writable (%s): %v", os.TempDir(), err),
		})
	} else {
		testFile := filepath.Join(testDir, "test.tmp")
		if err := os.WriteFile(testFile, []byte("ok"), 0o600); err != nil {
			report.TempDir = doctorTempView{
				Path:     os.TempDir(),
				Writable: false,
				Error:    err.Error(),
			}
			report.AllReady = false
			overallStatus = StatusFail
			report.Checks = append(report.Checks, doctorCheckItem{
				Name:    "temp_dir",
				Status:  StatusFail,
				Message: fmt.Sprintf("Temp dir write test failed: %v", err),
			})
		} else {
			report.TempDir = doctorTempView{
				Path:     os.TempDir(),
				Writable: true,
			}
			report.Checks = append(report.Checks, doctorCheckItem{
				Name:    "temp_dir",
				Status:  StatusPass,
				Message: fmt.Sprintf("Temp directory writable (%s)", os.TempDir()),
			})
		}
		_ = os.RemoveAll(testDir)
	}

	// 2. Probe registered integrations
	runner := integration.NewOSRunner("")
	reg := integration.DefaultRegistry()
	adapters := reg.List()

	for _, a := range adapters {
		meta := a.Metadata()
		inst, err := a.Detect(ctx, runner)

		itemStatus := StatusFail
		if inst.Installed && inst.Compatible {
			itemStatus = StatusPass
		} else if inst.Installed && !inst.Compatible {
			itemStatus = StatusWarn
			if overallStatus != StatusFail {
				overallStatus = StatusWarn
			}
		} else {
			itemStatus = StatusFail
			if overallStatus != StatusFail {
				overallStatus = StatusWarn
			}
		}

		item := doctorIntegrationItem{
			ID:         a.ID(),
			Binary:     meta.Binary,
			Path:       inst.Path,
			Version:    inst.Version,
			Installed:  inst.Installed,
			Compatible: inst.Compatible,
			Status:     itemStatus,
			Warning:    inst.Warning,
		}
		if err != nil && item.Warning == "" {
			item.Warning = err.Error()
		}

		if !inst.Installed || !inst.Compatible {
			report.AllReady = false
		}

		report.Integrations = append(report.Integrations, item)
		report.Checks = append(report.Checks, doctorCheckItem{
			Name:    "integration." + a.ID(),
			Status:  itemStatus,
			Message: fmt.Sprintf("%s (%s)", meta.Binary, inst.Version),
		})
	}

	// 3. Check Nuclei templates
	templatesPath, templatesVer, err := discoverNucleiTemplates()
	if err != nil {
		report.NucleiTemplates = doctorTemplatesView{
			Present:    false,
			Compatible: false,
			Status:     StatusWarn,
			Error:      err.Error(),
		}
		report.AllReady = false
		report.Checks = append(report.Checks, doctorCheckItem{
			Name:    "nuclei_templates",
			Status:  StatusWarn,
			Message: err.Error(),
		})
	} else {
		report.NucleiTemplates = doctorTemplatesView{
			Path:       templatesPath,
			Present:    true,
			Version:    templatesVer,
			Compatible: true,
			Status:     StatusPass,
		}
		report.Checks = append(report.Checks, doctorCheckItem{
			Name:    "nuclei_templates",
			Status:  StatusPass,
			Message: fmt.Sprintf("Templates compatible (%s)", templatesPath),
		})
	}

	report.Checks = append(report.Checks, doctorCheckItem{
		Name:    "network_safety",
		Status:  StatusWarn,
		Message: report.NetworkSafety.Message,
	})

	report.Status = overallStatus

	if opts.format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}

	// Human formatting
	fmt.Printf("%-4s  engine: %s %s (%s/%s)\n", StatusPass, buildinfo.EngineName, buildinfo.Version, runtime.GOOS, runtime.GOARCH)
	fmt.Printf("%-4s  protocol: v%s\n", StatusPass, buildinfo.ProtocolVersion)
	fmt.Printf("%-4s  snapshot_schema: v%s\n", StatusPass, buildinfo.SnapshotSchemaVersion)

	if report.TempDir.Writable {
		fmt.Printf("%-4s  temp_dir: writable (%s)\n", StatusPass, report.TempDir.Path)
	} else {
		fmt.Printf("%-4s  temp_dir: write failed (%s)\n", StatusFail, report.TempDir.Error)
	}

	for _, item := range report.Integrations {
		if item.Status == StatusPass {
			fmt.Printf("%-4s  %s: %s (%s)\n", StatusPass, item.ID, item.Version, item.Path)
		} else if item.Status == StatusWarn {
			fmt.Printf("%-4s  %s: version incompatible (%s: %s)\n", StatusWarn, item.ID, item.Version, item.Warning)
		} else {
			fmt.Printf("%-4s  %s: binary missing (%s not found in PATH or %s/bin)\n", StatusFail, item.ID, item.Binary, integration.DefaultExposureGuardHome())
		}
	}

	if report.NucleiTemplates.Present {
		fmt.Printf("%-4s  nuclei_templates: present (%s)\n", StatusPass, report.NucleiTemplates.Path)
	} else {
		fmt.Printf("%-4s  nuclei_templates: not found (%s)\n", StatusWarn, report.NucleiTemplates.Error)
	}

	fmt.Printf("%-4s  network_safety: %s\n\n", report.NetworkSafety.Status, report.NetworkSafety.Message)

	if report.AllReady {
		fmt.Println("All core components ready.")
	} else {
		fmt.Println("Notice: Run './install.sh' to fetch pinned external binaries and templates.")
	}

	return nil
}

func distributionManifestStatus() (string, error) {
	path := filepath.Join(integration.DefaultExposureGuardHome(), "distribution-manifest.json")
	data, err := os.ReadFile(path)
	if err != nil {
		executable, exeErr := os.Executable()
		if exeErr != nil {
			return "", fmt.Errorf("distribution manifest missing: %w", err)
		}
		candidates := []string{filepath.Join(filepath.Dir(executable), "..", "distribution-manifest.json"), filepath.Join("/opt/exposureguard", "distribution-manifest.json")}
		for _, candidate := range candidates {
			data, err = os.ReadFile(candidate)
			if err == nil {
				break
			}
		}
		if err != nil {
			return "", fmt.Errorf("distribution manifest missing: %w", err)
		}
	}
	var manifest struct {
		EngineVersion string `json:"engine_version"`
		EngineBinary  string `json:"engine_binary_sha256"`
		Toolchain     string `json:"toolchain_manifest_sha256"`
		Ruleset       string `json:"nuclei_ruleset_sha256"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return "", fmt.Errorf("distribution manifest invalid: %w", err)
	}
	if manifest.EngineVersion != buildinfo.Version {
		return "", errors.New("distribution engine version mismatch")
	}
	if executable, err := os.Executable(); err != nil || manifest.EngineBinary != fileSHA256(executable) {
		return "", errors.New("distribution engine binary fingerprint mismatch")
	}
	if manifest.Toolchain != fmt.Sprintf("%x", sha256.Sum256(integration.EmbeddedToolsLockBytes())) {
		return "", errors.New("distribution toolchain fingerprint mismatch")
	}
	if manifest.Ruleset != nuclei.CuratedRulesetSHA256 {
		return "", errors.New("distribution ruleset fingerprint mismatch")
	}
	return fmt.Sprintf("%x", sha256.Sum256(data)), nil
}

func discoverNucleiTemplates() (string, string, error) {
	// 1. Explicit environment override
	if envPath := os.Getenv("EXPOSUREGUARD_NUCLEI_TEMPLATES"); envPath != "" {
		if _, err := os.Stat(filepath.Join(envPath, ".nuclei-templates-version")); err == nil {
			return envPath, readVersionFile(filepath.Join(envPath, ".nuclei-templates-version")), nil
		}
		if _, err := os.Stat(envPath); err == nil {
			return envPath, "custom", nil
		}
	}

	// 2. Default location in EXPOSUREGUARD_HOME
	home := integration.DefaultExposureGuardHome()
	homeTemplates := filepath.Join(home, "share", "nuclei-templates")
	if _, err := os.Stat(homeTemplates); err == nil {
		ver := readVersionFile(filepath.Join(homeTemplates, ".nuclei-templates-version"))
		return homeTemplates, ver, nil
	}

	// 3. Fallback to current repository / workspace if running from source
	cwd, err := os.Getwd()
	if err == nil {
		repoTemplates := filepath.Join(cwd, "profiles", "nuclei", "v1")
		if _, err := os.Stat(filepath.Join(repoTemplates, "manifest.json")); err == nil {
			return repoTemplates, "curated-v1", nil
		}
	}

	return "", "", fmt.Errorf("templates not found at %s/nuclei-templates", home)
}

func readVersionFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(b))
}
