package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/exposureguard/exposureguard/pkg/checks"
	"github.com/spf13/cobra"
)

type checksOptions struct {
	format string
}

func newChecksCmd() *cobra.Command {
	opts := &checksOptions{}

	cmd := &cobra.Command{
		Use:   "checks",
		Short: "Inspect registered native security check rules and finding definitions",
		Long: `The checks namespace provides inspection of all built-in security finding rules,
their severity classifications, confidence rationale, and recommended remediations.`,
	}

	cmd.PersistentFlags().StringVar(&opts.format, "format", "human", "output format: human, json")

	cmd.AddCommand(newChecksListCmd(opts))

	return cmd
}

func newChecksListCmd(opts *checksOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all native security finding rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			rules := checks.AllRules()

			if strings.EqualFold(opts.format, "json") {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(rules)
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			fmt.Fprintln(w, "RULE ID\tMODULE\tSEVERITY\tCONFIDENCE\tTITLE")
			for _, r := range rules {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
					r.ID, r.Module, r.Severity, r.Confidence, r.Title)
			}
			return w.Flush()
		},
	}
}
