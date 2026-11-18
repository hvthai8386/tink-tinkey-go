# tink-tinkey-go

A Go port of [Tinkey](https://github.com/tink-crypto/tink-tinkey), the command line tool that manages
[Tink](https://developers.google.com/tink) keysets. It reads and writes the same keyset files as Java Tinkey and
uses the same command and flag names.

It has the commands and key templates of Java Tinkey 1.14.0 and encrypts keysets at rest with a Google Cloud KMS or
AWS KMS key. On top of Java Tinkey, it can authenticate to Google Cloud KMS with an access token (`--token`).

This is an independent port. It is not affiliated with, endorsed by, or supported by Google or the Tink project.

## Install

```sh
go install github.com/hvthai8386/tink-tinkey-go/cmd/tinkey@latest
```

or, from a checkout, `make build` writes `bin/tinkey`.

## Commands

| Command              | What it does                                                        |
|----------------------|---------------------------------------------------------------------|
| `create-keyset`      | Creates a keyset with one new key                                   |
| `add-key`            | Adds a new key; the primary key does not change                     |
| `promote-key`        | Makes the key with `--key-id` the primary key                       |
| `rotate-keyset`      | Adds a new key and makes it primary in one step                     |
| `enable-key`         | Enables the key with `--key-id`                                     |
| `disable-key`        | Disables the key with `--key-id`                                    |
| `delete-key`         | Deletes the key with `--key-id`                                     |
| `destroy-key`        | Erases the key material of the key with `--key-id`, keeps its entry |
| `list-keyset`        | Lists id, type and status of every key, without key material        |
| `convert-keyset`     | Changes the format, encrypts, decrypts, or moves to a new master key |
| `create-public-keyset` | Extracts the public keys of a keyset of private keys              |
| `list-key-templates` | Lists the supported key templates                                   |

`list-key-templates` prints the 143 key templates, for example `AES256_GCM`, `HMAC_SHA256_256BITTAG`, `ECDSA_P256`.
They are the templates of Java Tinkey 1.14.0, taken from it byte for byte, so a key made here has the same parameters
as the key Java Tinkey makes for the same name.

Keysets are read from `--in` (standard input if absent) and written to `--out` (standard output if absent).
`--out` must not exist: a keyset is never overwritten. `--in-format` and `--out-format` are `json` (default) or `binary`.

```sh
tinkey create-keyset --key-template AES256_GCM --out keyset.json
tinkey list-keyset --in keyset.json
```

## Key rotation

When every reader gets the new keyset at the same time, one step is enough:

```sh
tinkey rotate-keyset --key-template AES256_GCM --in keyset.json --out rotated.json
```

When readers are updated one by one, a reader that still has the old keyset cannot decrypt data written with the new
primary key. Rotate in two steps instead:

```sh
tinkey add-key --key-template AES256_GCM --in keyset.json --out with-new-key.json
# distribute with-new-key.json to every reader, then:
tinkey promote-key --key-id 1234567890 --in with-new-key.json --out rotated.json
```

Once nothing is encrypted with the old key any more, retire it with `disable-key`, then `delete-key`.

## Encrypting keysets with Google Cloud KMS

Without `--master-key-uri` a keyset is in cleartext. With it, the keyset is encrypted with that KMS key, and the
same flag is needed to read it back:

```sh
KEY=gcp-kms://projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key

tinkey create-keyset --key-template AES256_GCM --master-key-uri "$KEY" --out keyset.json
tinkey rotate-keyset --key-template AES256_GCM --master-key-uri "$KEY" --in keyset.json --out rotated.json
```

The caller needs `roles/cloudkms.cryptoKeyEncrypterDecrypter` on the key. There are three ways to authenticate:

| Flags                     | Credentials used                                                                  |
|---------------------------|-----------------------------------------------------------------------------------|
| none                      | Application Default Credentials: GKE Workload Identity, a VM's service account, `GOOGLE_APPLICATION_CREDENTIALS`, or `gcloud auth application-default login` |
| `--token <access token>`  | The given OAuth 2.0 access token of a service account                             |
| `--credential <file>`     | The given service account JSON key file                                           |

`--token` and `--credential` are mutually exclusive.

On GKE with Workload Identity, pass no credential flag: the pod's Kubernetes service account is mapped to a Google
service account, and the metadata server issues its tokens.

With `--token`, the token is used as is and is not refreshed. It is visible in the process list to other users of
the machine, so prefer Workload Identity where it is available.

```sh
tinkey list-keyset --in keyset.json --master-key-uri "$KEY" \
  --token "$(gcloud auth print-access-token --impersonate-service-account=tinkey@my-project.iam.gserviceaccount.com)"
```

`convert-keyset` reads with `--master-key-uri`, `--credential`, `--token` and writes with `--new-master-key-uri`,
`--new-credential`, `--new-token`:

```sh
# encrypt a cleartext keyset
tinkey convert-keyset --in cleartext.json --new-master-key-uri "$KEY" --out encrypted.json
# move a keyset to another master key
tinkey convert-keyset --in encrypted.json --master-key-uri "$KEY" --new-master-key-uri "$NEW_KEY" --out moved.json
```

## Binding a keyset to its use with associated data

`--associated-data` binds a label to the encrypted keyset: the KMS decrypts the keyset only when given the same
label. An application that stores several keysets under one KMS key can then never load one in place of another.

```sh
tinkey create-keyset --key-template AES256_GCM --master-key-uri "$KEY" --associated-data "orders data keyset" --out keyset.json
tinkey list-keyset --in keyset.json --master-key-uri "$KEY" --associated-data "orders data keyset"
```

Every later command on that keyset needs the same `--associated-data`; without it, or with another value, the KMS
refuses to decrypt. `convert-keyset` reads with `--associated-data` and writes with `--new-associated-data`, so it can
add, change or remove the label.

The application must read the keyset the same way, for example with `keyset.ReadWithAssociatedData` in tink-go. Java
Tinkey has no such option: it reads and writes only keysets without associated data.

## Encrypting keysets with AWS KMS

```sh
KEY=aws-kms://arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555
tinkey create-keyset --key-template AES256_GCM --master-key-uri "$KEY" --out keyset.json
```

Without `--credential`, the default credentials chain of the AWS SDK is used (environment variables, shared config,
the role of the instance or pod). `--credential` takes a credentials file in the CSV format of the IAM console or in
the INI format of `~/.aws/credentials` (profile `default`). `--token` does not apply to AWS KMS.

## Differences from Java Tinkey

- `--token` and `--new-token` exist only here.
- `--associated-data` and `--new-associated-data` exist only here. A keyset encrypted with associated data cannot be
  read by Java Tinkey.
- `--credential` or `--token` without the matching master key URI is an error; Java Tinkey ignores the credential and
  writes a cleartext keyset.
- The four AES-EAX key templates (`AES128_EAX`, `AES128_EAX_RAW`, `AES256_EAX`, `AES256_EAX_RAW`) are missing:
  tink-go has no AES-EAX key type.
- An AWS `--credential` file must be in one of the two formats above; other formats Java Tinkey may read are rejected.
- After `destroy-key`, the binary keyset is the same, byte for byte, as the one Java Tinkey writes, and both tools
  read it. Java Tinkey 1.14.0 cannot parse the JSON keyset after `destroy-key`, whichever tool wrote it; this tool can.
- A keyset whose `primaryKeyId` matches none of its keys is rejected (`keyset does not contain a valid primary key`).
  No Tinkey command writes such a keyset, but Java Tinkey reads one made by other means.
- Output files are created with mode `0600`.

## How it was verified

| What | Checked against |
|------|-----------------|
| All 143 key templates, JSON and binary keysets, public keysets, `destroy-key` | Java Tinkey 1.14.0, in both directions, on cleartext keysets |
| Keysets encrypted with Google Cloud KMS | A real Cloud KMS key and Java Tinkey 1.14.0, in both directions (two templates) |
| `--token` and GKE Workload Identity | A real Cloud KMS key |
| `--associated-data` | A real Cloud KMS key and an application reading with `keyset.ReadWithAssociatedData`, in both directions |
| `--credential` for Google Cloud KMS | A fake token endpoint and KMS only |
| `aws-kms://` master keys | A fake AWS KMS only; never run against AWS or compared with Java Tinkey |

## Development

```sh
make build   # bin/tinkey
make test    # go test -race ./...
make lint    # golangci-lint run ./...
```

CI also runs `go run golang.org/x/vuln/cmd/govulncheck@latest ./...` and fails on a known vulnerability the code can
reach.

`cmd/tinkey/java_key_templates.txt` is generated from a Java Tinkey release and must not be edited by hand. To move
to another release (needs a JDK):

```sh
make java-key-templates TINKEY_JAR=/path/to/tinkey_deploy.jar
```

The tests run every command in process against a fake Cloud KMS, token endpoint, metadata server and AWS KMS; they
need no cloud account. Decisions that constrain future changes are in [DECISIONS.md](DECISIONS.md).

## License

Apache License 2.0, see [LICENSE](LICENSE). Parts are derived from Tinkey, see [NOTICE](NOTICE).
