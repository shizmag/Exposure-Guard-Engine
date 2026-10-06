package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/exposureguard/exposureguard/internal/buildinfo"
	"github.com/spf13/cobra"
)

func newVersionCmd() *cobra.Command {
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print version and build metadata",
		RunE: func(cmd *cobra.Command, args []string) error {
			info := buildinfo.Get()
			if jsonOutput {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(info)
			}

			fmt.Fprintf(os.Stdout, "%s %s (commit: %s, built: %s, %s)\n",
				info.Engine, info.Version, info.GitCommit, info.BuildDate, info.GoVersion)
			fmt.Fprintf(os.Stdout, "protocol version: %s, snapshot schema: %s\n",
				info.ProtocolVersion, info.SnapshotSchemaVersion)
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output version metadata as JSON")
	return cmd
}
