package cli

import (
	"fmt"
	"os"

	"github.com/exposureguard/exposureguard/internal/buildinfo"
	"github.com/spf13/cobra"
)

var (
	cfgFile string
	noColor bool
)

// NewRootCmd constructs the base cobra command.
func NewRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   buildinfo.EngineName,
		Short: "ExposureGuard — defensive outside-in exposure scanner",
		Long: `ExposureGuard is a defensive, outside-in inspection and state inventory
engine for web applications and internet-facing assets.

It safely discovers assets, collects normalized observations, identifies actionable
findings, and computes state changes across time without intrusive exploits.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.PersistentFlags().StringVar(&cfgFile, "config", "", "path to configuration file")
	cmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "disable ANSI color output")

	cmd.AddCommand(newVersionCmd())
	cmd.AddCommand(newScanCmd())
	cmd.AddCommand(newDiffCmd())

	return cmd
}

// Execute runs the root CLI command and exits with non-zero on failure.
func Execute() {
	cmd := NewRootCmd()
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
