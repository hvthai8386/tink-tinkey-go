package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
)

func newListKeysetCommand() *cobra.Command {
	var (
		in        inOptions
		masterKey masterKeyOptions
	)
	cmd := &cobra.Command{
		Use:   "list-keyset",
		Short: "Lists keys in a keyset",
		Long:  "Lists the id, type and status of every key in a keyset. It does not output key material.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			masterKeyAEAD, err := masterKey.aead(cmd.Context())
			if err != nil {
				return err
			}
			handle, err := readKeyset(cmd.InOrStdin(), in, masterKeyAEAD, []byte(masterKey.associatedData))
			if err != nil {
				return err
			}

			// Written field by field to match the protobuf text format Java
			// Tinkey prints; Go's prototext output is deliberately unstable.
			var listing strings.Builder
			keysetInfo := handle.KeysetInfo()
			fmt.Fprintf(&listing, "primary_key_id: %d\n", keysetInfo.GetPrimaryKeyId())
			for _, keyInfo := range keysetInfo.GetKeyInfo() {
				fmt.Fprintln(&listing, "key_info {")
				// The text format leaves out empty fields; a destroyed key has no type.
				if keyInfo.GetTypeUrl() != "" {
					fmt.Fprintf(&listing, "  type_url: %q\n", keyInfo.GetTypeUrl())
				}
				fmt.Fprintf(&listing, "  status: %s\n", keyInfo.GetStatus())
				fmt.Fprintf(&listing, "  key_id: %d\n", keyInfo.GetKeyId())
				fmt.Fprintf(&listing, "  output_prefix_type: %s\n", keyInfo.GetOutputPrefixType())
				fmt.Fprintln(&listing, "}")
			}
			// Java Tinkey ends its output with an empty line.
			listing.WriteString("\n")
			_, err = io.WriteString(cmd.OutOrStdout(), listing.String())
			return err
		},
	}
	in.addFlags(cmd.Flags())
	masterKey.addFlags(cmd.Flags(), "", "the keyset")
	return cmd
}
