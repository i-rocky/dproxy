package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

func Execute(ctx context.Context, argv0 string, args []string, stdout, stderr io.Writer) int {
	root := newRootCommand(argv0, stdout, stderr)
	root.SetArgs(args)
	if err := root.ExecuteContext(ctx); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	return 0
}

func newRootCommand(argv0 string, stdout, stderr io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use:           argv0,
		Short:         "Run development tools in isolated containers",
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the dproxy version",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintln(cmd.OutOrStdout(), "dproxy dev")
		},
	})
	return root
}
