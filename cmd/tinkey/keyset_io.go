package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/pflag"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"
)

// keysetFormat is the value of --in-format and --out-format.
type keysetFormat string

const (
	formatJSON   keysetFormat = "json"
	formatBinary keysetFormat = "binary"
)

// Set implements pflag.Value. Like Java Tinkey it ignores case.
func (f *keysetFormat) Set(value string) error {
	switch strings.ToLower(value) {
	case "json":
		*f = formatJSON
	case "binary":
		*f = formatBinary
	default:
		return fmt.Errorf("invalid format %q: must be json or binary", value)
	}
	return nil
}

func (f *keysetFormat) String() string { return string(*f) }

func (f *keysetFormat) Type() string { return "format" }

// inOptions say where to read a keyset from.
type inOptions struct {
	path   string
	format keysetFormat
}

func (o *inOptions) addFlags(flags *pflag.FlagSet) {
	flags.StringVar(&o.path, "in", "",
		"The input filename to read the keyset from; standard input if not specified")
	o.format = formatJSON
	flags.Var(&o.format, "in-format", "The input format: json or binary (case-insensitive)")
}

// outOptions say where to write a keyset to.
type outOptions struct {
	path   string
	format keysetFormat
}

func (o *outOptions) addFlags(flags *pflag.FlagSet) {
	flags.StringVar(&o.path, "out", "",
		"The output filename, must not exist, to write the keyset to; standard output if not specified")
	o.format = formatJSON
	flags.Var(&o.format, "out-format", "The output format: json or binary (case-insensitive)")
}

// readKeyset reads a keyset from the --in file, or from stdin without --in.
// A nil masterKey reads a cleartext keyset; otherwise the keyset must be
// encrypted with masterKey and empty associated data, as Java Tinkey writes it.
func readKeyset(stdin io.Reader, in inOptions, masterKey tink.AEAD) (*keyset.Handle, error) {
	source := stdin
	sourceName := "standard input"
	if in.path != "" {
		serialized, err := os.ReadFile(in.path)
		if err != nil {
			return nil, err
		}
		source = bytes.NewReader(serialized)
		sourceName = in.path
	}

	var reader keyset.Reader = keyset.NewJSONReader(source)
	if in.format == formatBinary {
		reader = keyset.NewBinaryReader(source)
	}

	if masterKey == nil {
		handle, err := insecurecleartextkeyset.Read(reader)
		if err != nil {
			return nil, fmt.Errorf("read cleartext %s keyset from %s: %w", in.format, sourceName, err)
		}
		return handle, nil
	}
	handle, err := keyset.Read(reader, masterKey)
	if err != nil {
		return nil, fmt.Errorf("read encrypted %s keyset from %s: %w", in.format, sourceName, err)
	}
	return handle, nil
}

// writeKeyset writes a keyset to the --out file, or to stdout without --out.
// A nil masterKey writes the keyset in cleartext; otherwise it is encrypted
// with masterKey and empty associated data, as Java Tinkey reads it.
func writeKeyset(stdout io.Writer, out outOptions, handle *keyset.Handle, masterKey tink.AEAD) error {
	// Serialized in memory first, so that a failed KMS call leaves no empty
	// or partial output file behind.
	var serialized bytes.Buffer
	var writer keyset.Writer = keyset.NewJSONWriter(&serialized)
	if out.format == formatBinary {
		writer = keyset.NewBinaryWriter(&serialized)
	}

	if masterKey == nil {
		if err := insecurecleartextkeyset.Write(handle, writer); err != nil {
			return fmt.Errorf("serialize cleartext keyset: %w", err)
		}
	} else {
		if err := handle.Write(writer, masterKey); err != nil {
			return fmt.Errorf("encrypt keyset with master key: %w", err)
		}
	}

	if out.path == "" {
		_, err := stdout.Write(serialized.Bytes())
		return err
	}

	// O_EXCL keeps an existing keyset from being overwritten, as in Java
	// Tinkey. 0600 because a cleartext keyset holds secret key material.
	file, err := os.OpenFile(out.path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(serialized.Bytes())
	// Close can report a write the kernel deferred, so its error matters too.
	return errors.Join(writeErr, file.Close())
}
