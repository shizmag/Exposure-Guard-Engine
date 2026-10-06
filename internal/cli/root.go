package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/exposureguard/exposureguard/integrations"
	"github.com/exposureguard/exposureguard/internal/buildinfo"
	"github.com/spf13/cobra"
)

var (
	cfgFile string
	noColor bool
)

// ExitCodeError wraps an error with an explicit process exit code.
type ExitCodeError struct {
	Code int
	Err  error
}

func (e *ExitCodeError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return fmt.Sprintf("exit code %d", e.Code)
}

func (e *ExitCodeError) Unwrap() error {
	return e.Err
}

// NewRootCmd constructs the base cobra command.
func NewRootCmd() *cobra.Command {
	integrations.InitDefaultRegistry()

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
	cmd.AddCommand(newDoctorCmd())
	cmd.AddCommand(newIntegrationsCmd())

	return cmd
}

// Execute runs the root CLI command and exits with non-zero on failure.
func Execute() {
	cmd := NewRootCmd()
	if err := cmd.Execute(); err != nil {
		var exitErr *ExitCodeError
		if errors.As(err, &exitErr) {
			if exitErr.Err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", exitErr.Err)
			}
			os.Exit(exitErr.Code)
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
