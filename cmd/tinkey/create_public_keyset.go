package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newCreatePublicKeysetCommand() *cobra.Command {
	var (
		in        inOptions
		masterKey masterKeyOptions
		out       outOptions
	)
	cmd := &cobra.Command{
		Use:   "create-public-keyset",
		Short: "Creates a public keyset from a private keyset",
		Long: "Extracts the public keys of a keyset of private keys. " +
			"The private keyset is decrypted with --master-key-uri if specified; " +
			"the public keyset holds no secret and is always written in cleartext.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			masterKeyAEAD, err := masterKey.aead(cmd.Context())
			if err != nil {
				return err
			}
			handle, err := readKeyset(cmd.InOrStdin(), in, masterKeyAEAD)
			if err != nil {
				return err
			}

			publicHandle, err := handle.Public()
			if err != nil {
				return fmt.Errorf("extract public keys: %w", err)
			}
			return writeKeyset(cmd.OutOrStdout(), out, publicHandle, nil)
		},
	}
	in.addFlags(cmd.Flags())
	masterKey.addFlags(cmd.Flags(), "", "the private keyset")
	out.addFlags(cmd.Flags())
	return cmd
}
