// Tinkey manages Tink keysets from the command line. See package tinkey.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/hvthai8386/tink-tinkey-go/tinkey"
)

func main() {
	if err := tinkey.NewRootCommand().ExecuteContext(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "tinkey:", err)
		os.Exit(1)
	}
}
