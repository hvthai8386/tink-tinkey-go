// Package tinkey implements the tinkey command line: it manages Tink keysets
// with the commands and flags of Java Tinkey and reads and writes the same
// keyset files, so the two tools can be used on the same keysets.
//
// The command itself is cmd/tinkey. A program that wants the same commands
// with some flags fixed, such as its own master key, runs NewRootCommand with
// the arguments it builds.
package tinkey

import (
	"github.com/spf13/cobra"
	"github.com/tink-crypto/tink-go/v2/keyset"

	// Imported for their side effect: each registers the key types that the
	// key templates of its primitive need to generate keys.
	_ "github.com/tink-crypto/tink-go/v2/aead"
	_ "github.com/tink-crypto/tink-go/v2/daead"
	_ "github.com/tink-crypto/tink-go/v2/hybrid"
	_ "github.com/tink-crypto/tink-go/v2/jwt"
	_ "github.com/tink-crypto/tink-go/v2/keyderivation"
	_ "github.com/tink-crypto/tink-go/v2/mac"
	_ "github.com/tink-crypto/tink-go/v2/prf"
	_ "github.com/tink-crypto/tink-go/v2/signature"
	_ "github.com/tink-crypto/tink-go/v2/streamingaead"
)

// NewRootCommand returns the tinkey command with all its subcommands.
//
// The caller sets the arguments, standard input and standard output on the
// returned command (SetArgs, SetIn, SetOut) and runs it with ExecuteContext.
// The command prints neither the error it returns nor the usage text.
func NewRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "tinkey",
		Short: "Manage Tink keysets",
		// The caller prints the error once; cobra would also print the usage
		// text for failures that have nothing to do with the arguments.
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	root.AddCommand(
		newCreateKeysetCommand(),
		newAddKeyCommand(),
		newRotateKeysetCommand(),
		newKeyIDCommand("promote-key", "Promotes a specified key to primary", withManager((*keyset.Manager).SetPrimary)),
		newKeyIDCommand("enable-key", "Enables a specified key in a keyset", withManager((*keyset.Manager).Enable)),
		newKeyIDCommand("disable-key", "Disables a specified key in a keyset", withManager((*keyset.Manager).Disable)),
		newKeyIDCommand("delete-key", "Deletes a specified key in a keyset", withManager((*keyset.Manager).Delete)),
		newKeyIDCommand("destroy-key", "Destroys the key material of a specified key in a keyset", destroyKey),
		newListKeysetCommand(),
		newConvertKeysetCommand(),
		newCreatePublicKeysetCommand(),
		newListKeyTemplatesCommand(),
	)
	return root
}
