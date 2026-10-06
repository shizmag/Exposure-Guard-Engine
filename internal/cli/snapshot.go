package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/exposureguard/exposureguard/pkg/model"
	"github.com/exposureguard/exposureguard/pkg/snapshot"
	"github.com/spf13/cobra"
)

func newSnapshotCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "snapshot",
		Short: "Inspect and calculate canonical fingerprints for snapshot files",
	}

	cmd.AddCommand(newSnapshotHashCmd())
	return cmd
}

func newSnapshotHashCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "hash <snapshot.json>",
		Short: "Compute the canonical SHA-256 fingerprint for a snapshot file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := os.ReadFile(args[0])
			if err != nil {
				return &ExitCodeError{Code: 2, Err: fmt.Errorf("reading snapshot file failed: %w", err)}
			}

			var snap model.Snapshot
			if err := json.Unmarshal(data, &snap); err != nil {
				return &ExitCodeError{Code: 2, Err: fmt.Errorf("parsing snapshot JSON failed: %w", err)}
			}

			hash := snapshot.ComputeCanonicalHash(&snap)
			fmt.Fprintf(os.Stdout, "%s\n", hash)
			return nil
		},
	}
}
