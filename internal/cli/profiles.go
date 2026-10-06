package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/exposureguard/exposureguard/pkg/profile"
	"github.com/spf13/cobra"
)

type profilesOptions struct {
	format string
}

func newProfilesCmd() *cobra.Command {
	opts := &profilesOptions{}

	cmd := &cobra.Command{
		Use:   "profiles",
		Short: "Inspect predefined scan execution profiles",
		Long: `The profiles command lists and displays details for predefined scanning profiles
(quick, standard, deep). Each profile defines which native check modules, external
integrations, and default limits are applied during a scan.`,
	}

	cmd.PersistentFlags().StringVar(&opts.format, "format", "human", "output format: human, json")

	cmd.AddCommand(newProfilesListCmd(opts))
	cmd.AddCommand(newProfilesShowCmd(opts))

	return cmd
}

func newProfilesListCmd(opts *profilesOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all available scan profiles",
		RunE: func(cmd *cobra.Command, args []string) error {
			defs := profile.List()

			if strings.EqualFold(opts.format, "json") {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(defs)
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			fmt.Fprintln(w, "ID\tNAME\tREQUIRED MODE\tNATIVE CHECKS\tINTEGRATIONS\tDESCRIPTION")
			for _, p := range defs {
				mode := string(p.RequiredMode)
				if mode == "" {
					mode = "any"
				}
				integrations := strings.Join(p.Integrations, ", ")
				if integrations == "" {
					integrations = "none"
				}
				checks := strings.Join(p.NativeChecks, ", ")
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
					p.ID, p.Name, mode, checks, integrations, p.Description)
			}
			return w.Flush()
		},
	}
}

func newProfilesShowCmd(opts *profilesOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "show <profile>",
		Short: "Show detailed execution plan and limits for a specific profile",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			def, err := profile.Resolve(args[0])
			if err != nil {
				return &ExitCodeError{Code: 2, Err: err}
			}

			if strings.EqualFold(opts.format, "json") {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(def)
			}

			fmt.Printf("Profile: %s (%s)\n", def.ID, def.Name)
			fmt.Printf("Description: %s\n", def.Description)
			mode := string(def.RequiredMode)
			if mode == "" {
				mode = "any (public or owned)"
			}
			fmt.Printf("Required Mode: %s\n\n", mode)

			fmt.Println("Native Check Modules:")
			for _, c := range def.NativeChecks {
				fmt.Printf("  • %s\n", c)
			}

			fmt.Println("\nExternal Integrations:")
			if len(def.Integrations) == 0 {
				fmt.Println("  • none (pure native execution)")
			} else {
				for _, i := range def.Integrations {
					fmt.Printf("  • %s\n", i)
				}
			}

			fmt.Println("\nDefault Execution Limits:")
			fmt.Printf("  • Total Timeout:          %ds\n", def.Limits.TotalTimeoutSeconds)
			fmt.Printf("  • Request Timeout:        %ds\n", def.Limits.RequestTimeoutSeconds)
			fmt.Printf("  • Max Concurrency:        %d\n", def.Limits.MaxConcurrency)
			fmt.Printf("  • Max Pages:              %d\n", def.Limits.MaxPages)
			fmt.Printf("  • Max Depth:              %d\n", def.Limits.MaxDepth)
			fmt.Printf("  • Max Assets:             %d\n", def.Limits.MaxAssets)
			fmt.Printf("  • Max Response Size:      %d bytes\n", def.Limits.MaxResponseBytes)
			fmt.Printf("  • Max Total Download:     %d bytes\n", def.Limits.MaxTotalDownloadBytes)

			return nil
		},
	}
}
