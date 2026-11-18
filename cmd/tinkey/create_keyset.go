package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

func newCreateKeysetCommand() *cobra.Command {
	var (
		keyTemplateName string
		masterKey       masterKeyOptions
		out             outOptions
	)
	cmd := &cobra.Command{
		Use:   "create-keyset",
		Short: "Creates a new keyset",
		Long: "Creates a keyset that contains a single key of the given template. " +
			"The keyset is encrypted if --master-key-uri is specified.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			keyTemplate, err := lookupKeyTemplate(keyTemplateName)
			if err != nil {
				return err
			}
			masterKeyAEAD, err := masterKey.aead(cmd.Context())
			if err != nil {
				return err
			}

			handle, err := keyset.NewHandle(keyTemplate)
			if err != nil {
				return fmt.Errorf("generate %s key: %w", keyTemplateName, err)
			}
			return writeKeyset(cmd.OutOrStdout(), out, handle, masterKeyAEAD)
		},
	}
	addKeyTemplateFlag(cmd, &keyTemplateName)
	masterKey.addFlags(cmd.Flags(), "", "the keyset")
	out.addFlags(cmd.Flags())
	return cmd
}
