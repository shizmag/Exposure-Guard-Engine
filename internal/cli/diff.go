package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
)

func newDiffCmd() *cobra.Command {
	var (
		format string
		output string
	)

	cmd := &cobra.Command{
		Use:   "diff <old.json> <new.json>",
		Short: "Compute changes between two ExposureGuard snapshots",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDiff(cmd.Context(), args[0], args[1], format, output)
		},
	}

	cmd.Flags().StringVar(&format, "format", "human", "output format: human, json, jsonl")
	cmd.Flags().StringVarP(&output, "output", "o", "", "file path to write diff results")

	return cmd
}

func runDiff(_ context.Context, oldPath, newPath, _format, _output string) error {
	// Stub until pkg/diff is wired in Stage 7
	fmt.Printf("Comparing %s with %s\n", oldPath, newPath)
	return nil
}
