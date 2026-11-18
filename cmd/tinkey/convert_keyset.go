package main

import (
	"github.com/spf13/cobra"
)

func newConvertKeysetCommand() *cobra.Command {
	var (
		in           inOptions
		masterKey    masterKeyOptions
		out          outOptions
		newMasterKey masterKeyOptions
	)
	cmd := &cobra.Command{
		Use:   "convert-keyset",
		Short: "Changes format, encrypts, decrypts a keyset",
		Long: "Reads a keyset and writes it back unchanged in --out-format. " +
			"The input is decrypted with --master-key-uri if specified, and the output is " +
			"encrypted with --new-master-key-uri if specified, so the command also encrypts " +
			"a cleartext keyset, decrypts an encrypted one, or moves it to another master key.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			masterKeyAEAD, err := masterKey.aead(cmd.Context())
			if err != nil {
				return err
			}
			newMasterKeyAEAD, err := newMasterKey.aead(cmd.Context())
			if err != nil {
				return err
			}

			handle, err := readKeyset(cmd.InOrStdin(), in, masterKeyAEAD)
			if err != nil {
				return err
			}
			return writeKeyset(cmd.OutOrStdout(), out, handle, newMasterKeyAEAD)
		},
	}
	in.addFlags(cmd.Flags())
	masterKey.addFlags(cmd.Flags(), "", "the input keyset")
	out.addFlags(cmd.Flags())
	newMasterKey.addFlags(cmd.Flags(), "new-", "the output keyset")
	return cmd
}
