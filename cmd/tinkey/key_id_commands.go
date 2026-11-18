package main

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"google.golang.org/protobuf/proto"
)

// keyIDValue is the value of --key-id: a decimal unsigned 32-bit number, as in
// Java Tinkey. pflag's own uint32 flag would read a leading 0 as octal, so that
// --key-id 02222 would change key 1170 instead of key 2222.
type keyIDValue uint32

// Set implements pflag.Value.
func (v *keyIDValue) Set(value string) error {
	keyID, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return fmt.Errorf("invalid key id %q: must be a decimal number from 0 to 4294967295", value)
	}
	*v = keyIDValue(keyID)
	return nil
}

func (v *keyIDValue) String() string { return strconv.FormatUint(uint64(*v), 10) }

func (v *keyIDValue) Type() string { return "number" }

// newKeyIDCommand builds the commands that change one existing key of a keyset
// (promote-key, enable-key, disable-key, delete-key, destroy-key). changeKey
// applies the change to the key with --key-id and returns the changed keyset.
func newKeyIDCommand(use, short string, changeKey func(handle *keyset.Handle, keyID uint32) (*keyset.Handle, error)) *cobra.Command {
	var (
		keyID     keyIDValue
		in        inOptions
		masterKey masterKeyOptions
		out       outOptions
	)
	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			masterKeyAEAD, err := masterKey.aead(cmd.Context())
			if err != nil {
				return err
			}
			handle, err := readKeyset(cmd.InOrStdin(), in, masterKeyAEAD)
			if err != nil {
				return err
			}

			updated, err := changeKey(handle, uint32(keyID))
			if err != nil {
				return fmt.Errorf("%s %d: %w", use, keyID, err)
			}
			return writeKeyset(cmd.OutOrStdout(), out, updated, masterKeyAEAD)
		},
	}
	cmd.Flags().Var(&keyID, "key-id", "The target key id")
	requireFlag(cmd, "key-id")
	in.addFlags(cmd.Flags())
	masterKey.addFlags(cmd.Flags(), "", "the keyset")
	out.addFlags(cmd.Flags())
	return cmd
}

// withManager adapts a keyset.Manager method to the changeKey of newKeyIDCommand.
func withManager(changeKey func(manager *keyset.Manager, keyID uint32) error) func(*keyset.Handle, uint32) (*keyset.Handle, error) {
	return func(handle *keyset.Handle, keyID uint32) (*keyset.Handle, error) {
		manager := keyset.NewManagerFromHandle(handle)
		if err := changeKey(manager, keyID); err != nil {
			return nil, err
		}
		return manager.Handle()
	}
}

// destroyKey erases the key material of a key and keeps its entry, with status
// DESTROYED, so that the key id is never reused. It follows the rules of
// KeysetManager.destroy in Tink Java; tink-go's keyset.Manager has no such
// operation, hence the edit of the keyset proto.
func destroyKey(handle *keyset.Handle, keyID uint32) (*keyset.Handle, error) {
	keysetProto := insecurecleartextkeyset.KeysetMaterial(handle)
	if keyID == keysetProto.GetPrimaryKeyId() {
		return nil, errors.New("cannot destroy the primary key")
	}
	for _, key := range keysetProto.GetKey() {
		if key.GetKeyId() != keyID {
			continue
		}
		// An empty KeyData rather than none: tink-go refuses to load a keyset
		// with a key that has no KeyData at all.
		key.KeyData = &tinkpb.KeyData{}
		key.Status = tinkpb.KeyStatusType_DESTROYED
		serialized, err := proto.Marshal(keysetProto)
		if err != nil {
			return nil, fmt.Errorf("serialize keyset: %w", err)
		}
		return insecurecleartextkeyset.Read(keyset.NewBinaryReader(bytes.NewReader(serialized)))
	}
	return nil, errors.New("key not found")
}
