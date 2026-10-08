package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/exposureguard/exposureguard/pkg/capabilities"
	"github.com/spf13/cobra"
)

func newCapabilitiesCmd() *cobra.Command {
	format := "json"
	cmd := &cobra.Command{
		Use:   "capabilities",
		Short: "Print the versioned Engine capability contract",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !strings.EqualFold(format, "json") {
				return &ExitCodeError{Code: 2, Err: fmt.Errorf("unsupported capabilities format %q (supported: json)", format)}
			}
			data, err := capabilities.JSON()
			if err != nil {
				return err
			}
			_, err = os.Stdout.Write(append(data, '\n'))
			return err
		},
	}
	cmd.Flags().StringVar(&format, "format", "json", "output format: json")
	return cmd
}
