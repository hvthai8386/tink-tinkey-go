package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

func newAddKeyCommand() *cobra.Command {
	return newGenerateKeyCommand(
		"add-key",
		"Generates and adds a new key to a keyset",
		"Generates a key of the given template and adds it to the keyset. "+
			"The primary key does not change; use promote-key to make the new key primary.",
		false,
	)
}

func newRotateKeysetCommand() *cobra.Command {
	return newGenerateKeyCommand(
		"rotate-keyset",
		"Generates a new key, adds it to a keyset and sets it as the primary key",
		"Generates a key of the given template, adds it to the keyset and makes it primary. "+
			"Older keys stay in the keyset, so existing ciphertexts and MACs remain valid.\n\n"+
			"When several services read the keyset, rotate in two steps instead: "+
			"add-key, distribute the keyset to every reader, then promote-key. "+
			"Otherwise a reader that still has the old keyset cannot use data produced with the new key.",
		true,
	)
}

// newGenerateKeyCommand builds add-key and rotate-keyset, which differ only in
// whether the generated key becomes primary.
func newGenerateKeyCommand(use, short, long string, makePrimary bool) *cobra.Command {
	var (
		keyTemplateName string
		in              inOptions
		masterKey       masterKeyOptions
		out             outOptions
	)
	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Long:  long,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			keyTemplate, err := lookupKeyTemplate(keyTemplateName)
			if err != nil {
				return err
			}
			masterKeyAEAD, err := masterKey.aead(cmd.Context())
			if err != nil {
				return err
			}
			handle, err := readKeyset(cmd.InOrStdin(), in, masterKeyAEAD)
			if err != nil {
				return err
			}

			manager := keyset.NewManagerFromHandle(handle)
			newKeyID, err := manager.Add(keyTemplate)
			if err != nil {
				return fmt.Errorf("generate %s key: %w", keyTemplateName, err)
			}
			if makePrimary {
				if err := manager.SetPrimary(newKeyID); err != nil {
					return fmt.Errorf("promote new key %d to primary: %w", newKeyID, err)
				}
			}
			updated, err := manager.Handle()
			if err != nil {
				return err
			}
			return writeKeyset(cmd.OutOrStdout(), out, updated, masterKeyAEAD)
		},
	}
	addKeyTemplateFlag(cmd, &keyTemplateName)
	in.addFlags(cmd.Flags())
	masterKey.addFlags(cmd.Flags(), "", "the keyset")
	out.addFlags(cmd.Flags())
	return cmd
}
