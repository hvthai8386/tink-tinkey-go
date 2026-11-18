# Decision journal

Append-only. Newest entry at the bottom.

## 2026-11-18 — Keysets and command line stay interchangeable with Java Tinkey
**Context:** This CLI is a Go port of Google's Java Tinkey (release 1.14.0). Teams run both tools against the same keyset files, so a keyset written by one must be readable by the other, and a script written for one must keep working with the other.
**Decision:** Three things are fixed by Java Tinkey and must not drift. (1) Encrypted keysets are encrypted with the master key and **empty associated data**: `readKeyset` and `writeKeyset` in `cmd/tinkey/keyset_io.go` call `keyset.Read` and `Handle.Write`, never the `WithAssociatedData` variants; adding associated data makes every existing encrypted keyset undecryptable and breaks Java Tinkey. (2) Command names, flag names (`--in`, `--in-format`, `--out`, `--out-format`, `--master-key-uri`, `--credential`, `--new-master-key-uri`, `--new-credential`, `--key-id`, `--key-template`) and the names in `keyTemplates` (`cmd/tinkey/key_templates.go`) are the ones Java Tinkey uses; a new template is added under its Java name. (3) Anything Java Tinkey does not have is additive only: `--token` and `--new-token` are new flags, and no existing flag changes meaning. Where this CLI is stricter than Java (it rejects `--credential` or `--token` without a master key URI, which Java ignores), it fails instead of silently writing a different keyset.
**Source:** Thai Huynh, request of 2026-11-18 ("Tinkey-compatible CLI")
**Supersedes:** None

## 2026-11-18 — Key templates are Java Tinkey's own, embedded as generated data
**Context:** The CLI first offered three templates built with tink-go's template functions. Covering all 147 names of Java Tinkey 1.14.0 by hand would mean mapping each name to a tink-go function, or building the proto where tink-go has none, with nothing to prove that a name means the same parameters in both tools.
**Decision:** `cmd/tinkey/java_key_templates.txt` holds every template of a Java Tinkey release as a serialized `KeyTemplate` proto. It is written by `make java-key-templates` (`tools/java-key-templates/.../DumpKeyTemplates.java`, which registers key types exactly as `Tinkey.main` does) and is never edited by hand; `keyTemplates` in `cmd/tinkey/key_templates.go` is built from it at start-up. A template is added by regenerating the file from a newer Java Tinkey, not by writing Go code. Templates whose key type tink-go cannot generate are dropped by type URL (`aesEAXTypeURL`, the only one today); `TestEveryListedKeyTemplateCreatesAKeyset` fails when a regenerated file brings another such type. The blank imports in `cmd/tinkey/main.go` register the key types; a new primitive package of tink-go must be added there.
**Source:** None
**Supersedes:** None. It changes how `keyTemplates` is filled; "Keysets and command line stay interchangeable with Java Tinkey" (2026-11-18) stands.

## 2026-11-18 — destroy-key writes an empty KeyData, never none
**Context:** tink-go has no destroy operation and refuses to load a keyset with a key that has no `KeyData`. Java Tinkey's `destroy-key` leaves an empty `KeyData` in the binary keyset it writes.
**Decision:** `destroyKey` in `cmd/tinkey/key_id_commands.go` edits the keyset proto: status `DESTROYED` and `KeyData` set to an empty message, which serializes to the same bytes as Java Tinkey's output and which tink-go loads. Setting `KeyData` to nil would produce a keyset this CLI can no longer read. `list-keyset` omits the empty `type_url` of such a key, as Java does.
**Source:** None
**Supersedes:** None

## 2026-11-18 — Associated data of an encrypted keyset is empty by default and set only by --associated-data
**Context:** An application that uses these keysets wraps them with `keyset.WriteWithAssociatedData` and a fixed label per keyset, so the KMS refuses to unwrap one keyset as another. Tinkey always uses empty associated data, so it could neither create nor read those keysets.
**Decision:** `masterKeyOptions.associatedData` (`--associated-data`, `--new-associated-data` in `cmd/tinkey/master_key.go`) is passed to `readKeyset` and `writeKeyset`, which call `keyset.ReadWithAssociatedData` and `Handle.WriteWithAssociatedData`. The default stays empty, which is what Java Tinkey reads and writes: no command may set associated data on its own, and the flag never gets a non-empty default. The value is used as given, byte for byte; trimming or normalizing it would make existing keysets undecryptable.
**Source:** Thai Huynh, 2026-11-18
**Supersedes:** Point (1) of "Keysets and command line stay interchangeable with Java Tinkey" (2026-11-18), which forbade the `WithAssociatedData` variants. Its requirement stands for the default: without the flag, keysets are encrypted with empty associated data.

## 2026-11-18 — Package tinkey is importable; its only API is NewRootCommand
**Context:** A service wanted its own small tool to run the tinkey commands with its master key and associated data fixed, without installing a second binary in its image. The commands lived in `package main` under `cmd/tinkey`, which cannot be imported.
**Decision:** The implementation moved to package `tinkey` (directory `tinkey/`); `cmd/tinkey/main.go` only runs it. Earlier entries name files under `cmd/tinkey/`: the same files are now under `tinkey/`. The one exported identifier is `NewRootCommand`; importers drive it through arguments, so command names, flag names and the bytes written to standard output are the API, and nothing else is exported to keep it that small. Because the module is now a dependency of other modules, `go.mod` keeps the lowest `go` version the code needs (`go 1.26.3`) and names the patched release in the `toolchain` line (`toolchain go1.26.11`): a higher `go` line would force every importer onto that release, while the `toolchain` line only selects what this repository and its CI build with. Raise the `toolchain` line, not the `go` line, to pick up standard library fixes.
**Source:** Thai Huynh, 2026-11-18
**Supersedes:** None

