package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

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
verifies that third-party integrations (Subfinder, httpx, Katana, Nuclei) are installed,
validates versions and compatibility contracts, and ensures templates are available.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDoctor(cmd.Context(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.format, "format", "human", "output format: human, json")

	return cmd
}

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
	ID         string `json:"id"`
	Binary     string `json:"binary"`
	Path       string `json:"path,omitempty"`
	Version    string `json:"version,omitempty"`
	Installed  bool   `json:"installed"`
	Compatible bool   `json:"compatible"`
	Warning    string `json:"warning,omitempty"`
}

type doctorTemplatesView struct {
	Path       string `json:"path,omitempty"`
	Present    bool   `json:"present"`
	Version    string `json:"version,omitempty"`
	Compatible bool   `json:"compatible"`
	Error      string `json:"error,omitempty"`
}

type doctorReport struct {
	Engine          doctorEngineView        `json:"engine"`
	TempDir         doctorTempView          `json:"temp_dir"`
	Integrations    []doctorIntegrationItem `json:"integrations"`
	NucleiTemplates doctorTemplatesView     `json:"nuclei_templates"`
	AllReady        bool                    `json:"all_ready"`
}

func runDoctor(ctx context.Context, opts *doctorOptions) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	report := doctorReport{
		Engine: doctorEngineView{
			Name:      buildinfo.EngineName,
			Version:   buildinfo.Version,
			GitCommit: buildinfo.GitCommit,
			OS:        runtime.GOOS,
			Arch:      runtime.GOARCH,
		},
		AllReady: true,
	}

	// 1. Check temporary execution directory
	testDir := filepath.Join(os.TempDir(), fmt.Sprintf("eg-doctor-%d", time.Now().UnixNano()))
	if err := os.MkdirAll(testDir, 0o700); err != nil {
		report.TempDir = doctorTempView{
			Path:     os.TempDir(),
			Writable: false,
			Error:    err.Error(),
		}
		report.AllReady = false
	} else {
		testFile := filepath.Join(testDir, "test.tmp")
		if err := os.WriteFile(testFile, []byte("ok"), 0o600); err != nil {
			report.TempDir = doctorTempView{
				Path:     os.TempDir(),
				Writable: false,
				Error:    err.Error(),
			}
			report.AllReady = false
		} else {
			report.TempDir = doctorTempView{
				Path:     os.TempDir(),
				Writable: true,
			}
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

		item := doctorIntegrationItem{
			ID:         a.ID(),
			Binary:     meta.Binary,
			Path:       inst.Path,
			Version:    inst.Version,
			Installed:  inst.Installed,
			Compatible: inst.Compatible,
			Warning:    inst.Warning,
		}
		if err != nil && item.Warning == "" {
			item.Warning = err.Error()
		}

		if !inst.Installed || !inst.Compatible {
			report.AllReady = false
		}

		report.Integrations = append(report.Integrations, item)
	}

	// 3. Check Nuclei templates
	templatesPath, templatesVer, err := discoverNucleiTemplates()
	if err != nil {
		report.NucleiTemplates = doctorTemplatesView{
			Present:    false,
			Compatible: false,
			Error:      err.Error(),
		}
		report.AllReady = false
	} else {
		report.NucleiTemplates = doctorTemplatesView{
			Path:       templatesPath,
			Present:    true,
			Version:    templatesVer,
			Compatible: true,
		}
	}

	if opts.format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}

	// Human formatting
	fmt.Printf("✓ %s %s (%s/%s)\n", buildinfo.EngineName, buildinfo.Version, runtime.GOOS, runtime.GOARCH)

	if report.TempDir.Writable {
		fmt.Printf("✓ Temp directory writable (%s)\n", report.TempDir.Path)
	} else {
		fmt.Printf("✗ Temp directory error: %s\n", report.TempDir.Error)
	}

	for _, item := range report.Integrations {
		if item.Installed && item.Compatible {
			fmt.Printf("✓ %s %s (%s)\n", item.ID, item.Version, item.Path)
		} else if item.Installed && !item.Compatible {
			fmt.Printf("! %s %s (%s) — warning: %s\n", item.ID, item.Version, item.Path, item.Warning)
		} else {
			fmt.Printf("✗ %s unavailable (%s not found in PATH or %s/bin)\n", item.ID, item.Binary, integration.DefaultExposureGuardHome())
		}
	}

	if report.NucleiTemplates.Present {
		verStr := ""
		if report.NucleiTemplates.Version != "" {
			verStr = " " + report.NucleiTemplates.Version
		}
		fmt.Printf("✓ nuclei templates compatible%s (%s)\n", verStr, report.NucleiTemplates.Path)
	} else {
		fmt.Printf("! nuclei templates not found (%s)\n", report.NucleiTemplates.Error)
	}

	fmt.Println()
	if report.AllReady {
		fmt.Println("All integrations ready.")
	} else {
		fmt.Println("Some integrations or templates are not ready. Use './install.sh' to install pinned dependencies.")
	}

	return nil
}

// discoverNucleiTemplates searches standard locations for Nuclei templates.
func discoverNucleiTemplates() (string, string, error) {
	candidates := []string{
		os.Getenv("EXPOSUREGUARD_NUCLEI_TEMPLATES"),
		os.Getenv("NUCLEI_TEMPLATES_PATH"),
		filepath.Join(integration.DefaultExposureGuardHome(), "tools", "nuclei", "templates"),
		"/opt/exposureguard/nuclei-templates",
	}

	if userHome, err := os.UserHomeDir(); err == nil && userHome != "" {
		candidates = append(candidates,
			filepath.Join(userHome, "nuclei-templates"),
			filepath.Join(userHome, ".local", "nuclei-templates"),
			filepath.Join(userHome, "Library", "Application Support", "nuclei"),
		)
	}

	for _, path := range candidates {
		if path == "" {
			continue
		}
		fi, err := os.Stat(path)
		if err == nil && fi.IsDir() {
			// Try reading version from .templates-config.json if available
			var ver string
			cfgPath := filepath.Join(path, ".templates-config.json")
			if fi, err := os.Stat(cfgPath); err == nil && !fi.IsDir() {
				if data, err := os.ReadFile(cfgPath); err == nil {
					var cfg struct {
						Version string `json:"nuclei-templates-version"`
					}
					if json.Unmarshal(data, &cfg) == nil && cfg.Version != "" {
						ver = cfg.Version
					}
				}
			}
			return path, ver, nil
		}
	}

	return "", "", fmt.Errorf("no nuclei templates directory located")
}
