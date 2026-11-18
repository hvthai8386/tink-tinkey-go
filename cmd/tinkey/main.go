// Tinkey manages Tink keysets from the command line. It accepts the commands
// and flags of the Java Tinkey and reads and writes the same keyset files, so
// the two tools can be used on the same keysets.
package main

import (
	"context"
	"fmt"
	"os"

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

func main() {
	if err := newRootCommand().ExecuteContext(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "tinkey:", err)
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "tinkey",
		Short: "Manage Tink keysets",
		// main prints the error once; cobra would also print the usage text
		// for failures that have nothing to do with the arguments.
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
