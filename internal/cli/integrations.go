package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/exposureguard/exposureguard/pkg/integration"
	"github.com/spf13/cobra"
)

type integrationsOptions struct {
	format string
}

func newIntegrationsCmd() *cobra.Command {
	opts := &integrationsOptions{}

	cmd := &cobra.Command{
		Use:   "integrations",
		Short: "Manage and inspect external security discovery integrations",
		Long: `The integrations namespace allows inspecting external discovery and security tools
(Subfinder, httpx, Katana, Nuclei) integrated into ExposureGuard.`,
	}

	cmd.PersistentFlags().StringVar(&opts.format, "format", "human", "output format: human, json")

	cmd.AddCommand(newIntegrationsListCmd(opts))
	cmd.AddCommand(newIntegrationsInfoCmd(opts))

	return cmd
}

type integrationStatusView struct {
	ID           string   `json:"id"`
	DisplayName  string   `json:"display_name"`
	Status       string   `json:"status"`
	Version      string   `json:"version,omitempty"`
	Binary       string   `json:"binary"`
	Path         string   `json:"path,omitempty"`
	Capabilities []string `json:"capabilities"`
	RiskClass    string   `json:"risk_class"`
	UpstreamURL  string   `json:"upstream_url,omitempty"`
	Warning      string   `json:"warning,omitempty"`
}

func newIntegrationsListCmd(opts *integrationsOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all registered integrations and their host installation status",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
			defer cancel()

			runner := integration.NewOSRunner("")
			reg := integration.DefaultRegistry()
			adapters := reg.List()

			var views []integrationStatusView
			for _, a := range adapters {
				meta := a.Metadata()
				inst, _ := a.Detect(ctx, runner)

				status := "missing"
				if inst.Installed {
					if inst.Compatible {
						status = "ready"
					} else {
						status = "incompatible"
					}
				}

				caps := make([]string, len(meta.Capabilities))
				for i, c := range meta.Capabilities {
					caps[i] = string(c)
				}

				views = append(views, integrationStatusView{
					ID:           a.ID(),
					DisplayName:  meta.DisplayName,
					Status:       status,
					Version:      inst.Version,
					Binary:       meta.Binary,
					Path:         inst.Path,
					Capabilities: caps,
					RiskClass:    string(meta.RiskClass),
					UpstreamURL:  meta.UpstreamURL,
					Warning:      inst.Warning,
				})
			}

			if opts.format == "json" {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(views)
			}

			if len(views) == 0 {
				fmt.Println("No external integrations registered.")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			fmt.Fprintln(w, "Integration\tStatus\tVersion\tCapability")
			for _, v := range views {
				ver := v.Version
				if ver == "" {
					ver = "-"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", v.ID, v.Status, ver, strings.Join(v.Capabilities, ", "))
			}
			return w.Flush()
		},
	}
}

func newIntegrationsInfoCmd(opts *integrationsOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "info <integration-id>",
		Short: "Display detailed configuration and metadata for a specific integration",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
			defer cancel()

			id := args[0]
			reg := integration.DefaultRegistry()
			a, ok := reg.Get(id)
			if !ok {
				return &ExitCodeError{Code: 1, Err: fmt.Errorf("integration %q is not registered", id)}
			}

			runner := integration.NewOSRunner("")
			meta := a.Metadata()
			inst, _ := a.Detect(ctx, runner)

			status := "missing"
			if inst.Installed {
				if inst.Compatible {
					status = "ready"
				} else {
					status = "incompatible"
				}
			}

			caps := make([]string, len(meta.Capabilities))
			for i, c := range meta.Capabilities {
				caps[i] = string(c)
			}

			view := integrationStatusView{
				ID:           a.ID(),
				DisplayName:  meta.DisplayName,
				Status:       status,
				Version:      inst.Version,
				Binary:       meta.Binary,
				Path:         inst.Path,
				Capabilities: caps,
				RiskClass:    string(meta.RiskClass),
				UpstreamURL:  meta.UpstreamURL,
				Warning:      inst.Warning,
			}

			if opts.format == "json" {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(view)
			}

			fmt.Printf("Integration:     %s (%s)\n", meta.DisplayName, meta.ID)
			fmt.Printf("Description:     %s\n", meta.Description)
			fmt.Printf("Status:          %s\n", status)
			fmt.Printf("Binary:          %s\n", meta.Binary)
			if inst.Path != "" {
				fmt.Printf("Binary Path:     %s\n", inst.Path)
			}
			if inst.Version != "" {
				fmt.Printf("Detected Version: %s\n", inst.Version)
			}
			if meta.TestedVersion != "" {
				fmt.Printf("Tested Version:  %s\n", meta.TestedVersion)
			}
			if meta.MinimumSupportedVersion != "" {
				fmt.Printf("Min Supported:   %s\n", meta.MinimumSupportedVersion)
			}
			fmt.Printf("Risk Class:      %s\n", meta.RiskClass)
			fmt.Printf("Capabilities:    %s\n", strings.Join(caps, ", "))
			if meta.UpstreamURL != "" {
				fmt.Printf("Upstream URL:    %s\n", meta.UpstreamURL)
			}
			if inst.Warning != "" {
				fmt.Printf("Warning:         %s\n", inst.Warning)
			}
			return nil
		},
	}
}
