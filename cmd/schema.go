package cmd

import (
	"fmt"

	"github.com/moolen/patchpilot/internal/policy"
	"github.com/spf13/cobra"
)

func newSchemaCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "schema",
		Short: "Print JSON schema for .patchpilot.yaml",
		RunE: func(command *cobra.Command, args []string) error {
			_, _ = fmt.Fprintln(command.OutOrStdout(), string(policy.SchemaJSON()))
			return nil
		},
	}
}
