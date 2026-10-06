package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/exposureguard/exposureguard/internal/config"
	"github.com/exposureguard/exposureguard/pkg/integration"
	"github.com/spf13/cobra"
)

type configOptions struct {
	format string
}

func newConfigCmd() *cobra.Command {
	opts := &configOptions{}

	cmd := &cobra.Command{
		Use:   "config",
		Short: "Inspect effective ExposureGuard engine configuration",
		Long: `The config namespace allows inspecting the effective configuration parameters,
defaults, resource limits, and tool directories resolved from flags, files, and environment.`,
	}

	cmd.PersistentFlags().StringVar(&opts.format, "format", "human", "output format: human, json")

	cmd.AddCommand(newConfigShowCmd(opts))

	return cmd
}

func newConfigShowCmd(opts *configOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Show effective runtime configuration with secrets redacted",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgFile)
			if err != nil {
				return &ExitCodeError{Code: 2, Err: fmt.Errorf("loading configuration failed: %w", err)}
			}

			type effectiveConfigView struct {
				ConfigFile    string   `json:"config_file,omitempty"`
				Format        string   `json:"format"`
				LogLevel      string   `json:"log_level"`
				Profile       string   `json:"profile"`
				Mode          string   `json:"mode"`
				UserAgent     string   `json:"user_agent"`
				NativeModules []string `json:"native_modules"`
				Limits        any      `json:"limits"`
				ToolsHome     string   `json:"tools_home"`
			}

			view := effectiveConfigView{
				ConfigFile:    cfgFile,
				Format:        cfg.Format,
				LogLevel:      cfg.LogLevel,
				Profile:       cfg.Profile,
				Mode:          cfg.Mode,
				UserAgent:     cfg.UserAgent,
				NativeModules: cfg.Modules,
				Limits:        cfg.Limits,
				ToolsHome:     integration.DefaultExposureGuardHome(),
			}

			if strings.EqualFold(opts.format, "json") {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(view)
			}

			fmt.Println("ExposureGuard Effective Configuration")
			if view.ConfigFile != "" {
				fmt.Printf("  Config File:     %s\n", view.ConfigFile)
			} else {
				fmt.Printf("  Config File:     (none, using defaults + env)\n")
			}
			fmt.Printf("  Default Profile: %s\n", view.Profile)
			fmt.Printf("  Default Mode:    %s\n", view.Mode)
			fmt.Printf("  Output Format:   %s\n", view.Format)
			fmt.Printf("  Log Level:       %s\n", view.LogLevel)
			fmt.Printf("  Tools Home:      %s\n", view.ToolsHome)
			fmt.Printf("  User-Agent:      %s\n\n", view.UserAgent)

			fmt.Println("Native Modules:")
			for _, m := range view.NativeModules {
				fmt.Printf("  • %s\n", m)
			}

			fmt.Println("\nResource Limits:")
			fmt.Printf("  • Total Timeout:          %ds\n", cfg.Limits.TotalTimeoutSeconds)
			fmt.Printf("  • Request Timeout:        %ds\n", cfg.Limits.RequestTimeoutSeconds)
			fmt.Printf("  • Max Concurrency:        %d\n", cfg.Limits.MaxConcurrency)
			fmt.Printf("  • Max Pages:              %d\n", cfg.Limits.MaxPages)
			fmt.Printf("  • Max Depth:              %d\n", cfg.Limits.MaxDepth)
			fmt.Printf("  • Max Assets:             %d\n", cfg.Limits.MaxAssets)
			fmt.Printf("  • Max Response Size:      %d bytes\n", cfg.Limits.MaxResponseBytes)
			fmt.Printf("  • Max Total Download:     %d bytes\n", cfg.Limits.MaxTotalDownloadBytes)

			return nil
		},
	}
}
