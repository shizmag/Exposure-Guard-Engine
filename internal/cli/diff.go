package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/exposureguard/exposureguard/pkg/diff"
	"github.com/exposureguard/exposureguard/pkg/model"
	"github.com/exposureguard/exposureguard/pkg/render/human"
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

func runDiff(_ context.Context, oldPath, newPath, format, output string) error {
	oldBytes, err := os.ReadFile(oldPath)
	if err != nil {
		return fmt.Errorf("reading old snapshot failed: %w", err)
	}

	newBytes, err := os.ReadFile(newPath)
	if err != nil {
		return fmt.Errorf("reading new snapshot failed: %w", err)
	}

	var oldSnap, newSnap model.Snapshot
	if err := json.Unmarshal(oldBytes, &oldSnap); err != nil {
		return fmt.Errorf("parsing old snapshot JSON failed: %w", err)
	}
	if err := json.Unmarshal(newBytes, &newSnap); err != nil {
		return fmt.Errorf("parsing new snapshot JSON failed: %w", err)
	}

	changes := diff.Compare(&oldSnap, &newSnap)

	outWriter := os.Stdout
	if output != "" {
		f, err := os.Create(output)
		if err != nil {
			return fmt.Errorf("creating output file failed: %w", err)
		}
		defer f.Close()
		outWriter = f
	}

	switch format {
	case "json":
		enc := json.NewEncoder(outWriter)
		enc.SetIndent("", "  ")
		return enc.Encode(changes)
	default: // human
		return human.RenderDiff(outWriter, changes, human.Options{NoColor: noColor})
	}
}
