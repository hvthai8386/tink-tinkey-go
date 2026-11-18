package main

import (
	"bytes"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/aead/aesgcm"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/mac"
	"github.com/tink-crypto/tink-go/v2/mac/hmac"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"github.com/tink-crypto/tink-go/v2/signature"
)

// runTinkey runs the CLI in-process with the given stdin and arguments and
// returns what it wrote to stdout.
func runTinkey(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	var stdout bytes.Buffer
	root := newRootCommand()
	root.SetArgs(args)
	root.SetIn(strings.NewReader(stdin))
	root.SetOut(&stdout)
	root.SetErr(io.Discard)
	err := root.Execute()
	return stdout.String(), err
}

func mustRunTinkey(t *testing.T, stdin string, args ...string) string {
	t.Helper()
	stdout, err := runTinkey(t, stdin, args...)
	if err != nil {
		t.Fatalf("tinkey %s: %v", strings.Join(args, " "), err)
	}
	return stdout
}

func parseCleartextKeyset(t *testing.T, keysetJSON string) *keyset.Handle {
	t.Helper()
	handle, err := insecurecleartextkeyset.Read(keyset.NewJSONReader(strings.NewReader(keysetJSON)))
	if err != nil {
		t.Fatalf("parse cleartext JSON keyset %q: %v", keysetJSON, err)
	}
	return handle
}

func primaryKeyID(t *testing.T, handle *keyset.Handle) uint32 {
	t.Helper()
	primary, err := handle.Primary()
	if err != nil {
		t.Fatalf("keyset has no primary key: %v", err)
	}
	return primary.KeyID()
}

// keyStatuses returns the status of every key in the keyset by key id.
func keyStatuses(t *testing.T, handle *keyset.Handle) map[uint32]keyset.KeyStatus {
	t.Helper()
	statuses := make(map[uint32]keyset.KeyStatus)
	for i := range handle.Len() {
		entry, err := handle.Entry(i)
		if err != nil {
			t.Fatalf("keyset entry %d: %v", i, err)
		}
		statuses[entry.KeyID()] = entry.KeyStatus()
	}
	return statuses
}

// otherKeyID returns the id of the one key in a two-key keyset that is not excludedKeyID.
func otherKeyID(t *testing.T, handle *keyset.Handle, excludedKeyID uint32) uint32 {
	t.Helper()
	statuses := keyStatuses(t, handle)
	if len(statuses) != 2 {
		t.Fatalf("keyset has %d keys, want 2", len(statuses))
	}
	for keyID := range statuses {
		if keyID != excludedKeyID {
			return keyID
		}
	}
	t.Fatalf("keyset has no key other than %d", excludedKeyID)
	return 0
}

func keyIDFlag(keyID uint32) string {
	return "--key-id=" + strconv.FormatUint(uint64(keyID), 10)
}

func TestCreateKeysetAES256GCM(t *testing.T) {
	handle := parseCleartextKeyset(t, mustRunTinkey(t, "", "create-keyset", "--key-template", "AES256_GCM"))

	if handle.Len() != 1 {
		t.Fatalf("keyset has %d keys, want 1", handle.Len())
	}
	primary, err := handle.Primary()
	if err != nil {
		t.Fatalf("keyset has no primary key: %v", err)
	}
	parameters, isAESGCM := primary.Key().Parameters().(*aesgcm.Parameters)
	if !isAESGCM {
		t.Fatalf("key parameters are %T, want *aesgcm.Parameters", primary.Key().Parameters())
	}
	if parameters.KeySizeInBytes() != 32 {
		t.Errorf("key size = %d bytes, want 32", parameters.KeySizeInBytes())
	}
	if parameters.Variant() != aesgcm.VariantTink {
		t.Errorf("variant = %v, want TINK", parameters.Variant())
	}

	primitive, err := aead.New(handle)
	if err != nil {
		t.Fatalf("aead.New: %v", err)
	}
	ciphertext, err := primitive.Encrypt([]byte("plaintext"), []byte("associated data"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	plaintext, err := primitive.Decrypt(ciphertext, []byte("associated data"))
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(plaintext) != "plaintext" {
		t.Errorf("decrypted %q, want %q", plaintext, "plaintext")
	}
}

func TestCreateKeysetHMACSHA256(t *testing.T) {
	tests := []struct {
		keyTemplate    string
		tagSizeInBytes int
	}{
		{"HMAC_SHA256_128BITTAG", 16},
		{"HMAC_SHA256_256BITTAG", 32},
	}
	for _, test := range tests {
		t.Run(test.keyTemplate, func(t *testing.T) {
			handle := parseCleartextKeyset(t, mustRunTinkey(t, "", "create-keyset", "--key-template", test.keyTemplate))

			primary, err := handle.Primary()
			if err != nil {
				t.Fatalf("keyset has no primary key: %v", err)
			}
			parameters, isHMAC := primary.Key().Parameters().(*hmac.Parameters)
			if !isHMAC {
				t.Fatalf("key parameters are %T, want *hmac.Parameters", primary.Key().Parameters())
			}
			if parameters.HashType() != hmac.SHA256 {
				t.Errorf("hash type = %v, want SHA256", parameters.HashType())
			}
			if parameters.CryptographicTagSizeInBytes() != test.tagSizeInBytes {
				t.Errorf("tag size = %d bytes, want %d", parameters.CryptographicTagSizeInBytes(), test.tagSizeInBytes)
			}

			primitive, err := mac.New(handle)
			if err != nil {
				t.Fatalf("mac.New: %v", err)
			}
			tag, err := primitive.ComputeMAC([]byte("message"))
			if err != nil {
				t.Fatalf("ComputeMAC: %v", err)
			}
			if err := primitive.VerifyMAC(tag, []byte("message")); err != nil {
				t.Errorf("VerifyMAC: %v", err)
			}
		})
	}
}

func TestCreateKeysetRejectsInvalidArguments(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantError string
	}{
		{"unknown key template", []string{"create-keyset", "--key-template", "AES512_GCM"}, `unknown key template "AES512_GCM"`},
		// A Java Tinkey template of the one key type tink-go does not have.
		{"AES-EAX key template", []string{"create-keyset", "--key-template", "AES128_EAX"}, `unknown key template "AES128_EAX"`},
		{"missing key template", []string{"create-keyset"}, `required flag(s) "key-template" not set`},
		{"invalid output format", []string{"create-keyset", "--key-template", "AES256_GCM", "--out-format", "xml"}, `invalid format "xml"`},
		{"token without master key", []string{"create-keyset", "--key-template", "AES256_GCM", "--token", "t"}, "--credential and --token require --master-key-uri"},
		{"credential without master key", []string{"create-keyset", "--key-template", "AES256_GCM", "--credential", "c.json"}, "--credential and --token require --master-key-uri"},
		{
			"token and credential together",
			[]string{"create-keyset", "--key-template", "AES256_GCM", "--master-key-uri", "gcp-kms://projects/p/locations/global/keyRings/r/cryptoKeys/k", "--token", "t", "--credential", "c.json"},
			"--credential and --token are mutually exclusive",
		},
		{
			"master key of an unsupported KMS",
			[]string{"create-keyset", "--key-template", "AES256_GCM", "--master-key-uri", "azure-kms://vault/keys/k"},
			"it must start with gcp-kms:// or aws-kms://",
		},
		{
			"token with an AWS KMS master key",
			[]string{"create-keyset", "--key-template", "AES256_GCM", "--master-key-uri", "aws-kms://arn:aws:kms:us-east-1:1:key/k", "--token", "t"},
			"--token is supported only with gcp-kms:// keys",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stdout, err := runTinkey(t, "", test.args...)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Errorf("error = %v, want it to contain %q", err, test.wantError)
			}
			if stdout != "" {
				t.Errorf("wrote %q to stdout, want nothing", stdout)
			}
		})
	}
}

func TestOutputFileIsNeverOverwritten(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "keyset.json")
	mustRunTinkey(t, "", "create-keyset", "--key-template", "AES256_GCM", "--out", outPath)
	firstKeyset, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	parseCleartextKeyset(t, string(firstKeyset))

	if _, err := runTinkey(t, "", "create-keyset", "--key-template", "AES256_GCM", "--out", outPath); err == nil {
		t.Error("create-keyset onto an existing --out file succeeded, want an error")
	}
	keysetAfterSecondRun, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keysetAfterSecondRun, firstKeyset) {
		t.Error("existing --out file was modified")
	}
}

func TestRotateKeysetMakesNewKeyPrimaryAndKeepsOldKey(t *testing.T) {
	originalJSON := mustRunTinkey(t, "", "create-keyset", "--key-template", "AES256_GCM")
	original := parseCleartextKeyset(t, originalJSON)
	originalKeyID := primaryKeyID(t, original)
	originalAEAD, err := aead.New(original)
	if err != nil {
		t.Fatalf("aead.New: %v", err)
	}
	oldCiphertext, err := originalAEAD.Encrypt([]byte("written before rotation"), nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	rotated := parseCleartextKeyset(t, mustRunTinkey(t, originalJSON, "rotate-keyset", "--key-template", "AES256_GCM"))

	newKeyID := otherKeyID(t, rotated, originalKeyID)
	if got := primaryKeyID(t, rotated); got != newKeyID {
		t.Errorf("primary key id = %d, want the new key %d", got, newKeyID)
	}
	if got := keyStatuses(t, rotated)[originalKeyID]; got != keyset.Enabled {
		t.Errorf("original key status = %v, want ENABLED", got)
	}
	rotatedAEAD, err := aead.New(rotated)
	if err != nil {
		t.Fatalf("aead.New: %v", err)
	}
	plaintext, err := rotatedAEAD.Decrypt(oldCiphertext, nil)
	if err != nil || string(plaintext) != "written before rotation" {
		t.Errorf("decrypting a pre-rotation ciphertext with the rotated keyset = %q, %v", plaintext, err)
	}
	newCiphertext, err := rotatedAEAD.Encrypt([]byte("written after rotation"), nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := originalAEAD.Decrypt(newCiphertext, nil); err == nil {
		t.Error("the pre-rotation keyset decrypted a post-rotation ciphertext, so the new key is not in use")
	}
}

func TestRotationInTwoStepsThenRetiringOldKey(t *testing.T) {
	originalJSON := mustRunTinkey(t, "", "create-keyset", "--key-template", "HMAC_SHA256_256BITTAG")
	original := parseCleartextKeyset(t, originalJSON)
	originalKeyID := primaryKeyID(t, original)
	originalMAC, err := mac.New(original)
	if err != nil {
		t.Fatalf("mac.New: %v", err)
	}
	oldTag, err := originalMAC.ComputeMAC([]byte("message"))
	if err != nil {
		t.Fatalf("ComputeMAC: %v", err)
	}
	verifiesOldTag := func(keysetJSON string) bool {
		primitive, err := mac.New(parseCleartextKeyset(t, keysetJSON))
		if err != nil {
			t.Fatalf("mac.New: %v", err)
		}
		return primitive.VerifyMAC(oldTag, []byte("message")) == nil
	}

	withNewKeyJSON := mustRunTinkey(t, originalJSON, "add-key", "--key-template", "HMAC_SHA256_256BITTAG")
	withNewKey := parseCleartextKeyset(t, withNewKeyJSON)
	if got := primaryKeyID(t, withNewKey); got != originalKeyID {
		t.Fatalf("after add-key the primary key id = %d, want it unchanged at %d", got, originalKeyID)
	}
	newKeyID := otherKeyID(t, withNewKey, originalKeyID)

	promotedJSON := mustRunTinkey(t, withNewKeyJSON, "promote-key", keyIDFlag(newKeyID))
	if got := primaryKeyID(t, parseCleartextKeyset(t, promotedJSON)); got != newKeyID {
		t.Fatalf("after promote-key the primary key id = %d, want %d", got, newKeyID)
	}
	if !verifiesOldTag(promotedJSON) {
		t.Error("after promote-key a tag of the old key no longer verifies")
	}

	disabledJSON := mustRunTinkey(t, promotedJSON, "disable-key", keyIDFlag(originalKeyID))
	if got := keyStatuses(t, parseCleartextKeyset(t, disabledJSON))[originalKeyID]; got != keyset.Disabled {
		t.Errorf("after disable-key the old key status = %v, want DISABLED", got)
	}
	if verifiesOldTag(disabledJSON) {
		t.Error("after disable-key a tag of the old key still verifies")
	}

	enabledJSON := mustRunTinkey(t, disabledJSON, "enable-key", keyIDFlag(originalKeyID))
	if !verifiesOldTag(enabledJSON) {
		t.Error("after enable-key a tag of the old key does not verify")
	}

	deletedJSON := mustRunTinkey(t, enabledJSON, "delete-key", keyIDFlag(originalKeyID))
	remaining := keyStatuses(t, parseCleartextKeyset(t, deletedJSON))
	if _, hasOldKey := remaining[originalKeyID]; hasOldKey || len(remaining) != 1 {
		t.Errorf("after delete-key the keyset has keys %v, want only %d", remaining, newKeyID)
	}
}

func TestKeyIDCommandsRejectUnsafeChanges(t *testing.T) {
	keysetJSON := mustRunTinkey(t, "", "create-keyset", "--key-template", "AES256_GCM")
	primary := primaryKeyID(t, parseCleartextKeyset(t, keysetJSON))
	// Any id other than the primary's is absent from a one-key keyset.
	absentKeyID := primary + 1

	tests := []struct {
		name string
		args []string
	}{
		{"disable the primary key", []string{"disable-key", keyIDFlag(primary)}},
		{"delete the primary key", []string{"delete-key", keyIDFlag(primary)}},
		{"promote an absent key", []string{"promote-key", keyIDFlag(absentKeyID)}},
		{"enable an absent key", []string{"enable-key", keyIDFlag(absentKeyID)}},
		{"missing key id", []string{"promote-key"}},
		{"key id out of range", []string{"promote-key", "--key-id=4294967296"}},
		{"hexadecimal key id", []string{"promote-key", "--key-id=0x" + strconv.FormatUint(uint64(primary), 16)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stdout, err := runTinkey(t, keysetJSON, test.args...)
			if err == nil {
				t.Error("command succeeded, want an error")
			}
			if stdout != "" {
				t.Errorf("wrote %q to stdout, want nothing", stdout)
			}
		})
	}
}

func TestKeyIDWithLeadingZeroIsDecimal(t *testing.T) {
	// 02222 read as octal is 1170, the id of the other key.
	const keysetJSON = `{
		"primaryKeyId": 1170,
		"key": [
			{
				"keyData": {
					"typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey",
					"value": "GiCXlcAQx22K2CHz5QxtRGoQnT72rWskeP4VLTXQyY658Q==",
					"keyMaterialType": "SYMMETRIC"
				},
				"status": "ENABLED",
				"keyId": 1170,
				"outputPrefixType": "TINK"
			},
			{
				"keyData": {
					"typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey",
					"value": "GiDKN7vJ2YgH3pfW0QbM0VQx0cXc1m3T8cJ2b1x4Vn0pLw==",
					"keyMaterialType": "SYMMETRIC"
				},
				"status": "ENABLED",
				"keyId": 2222,
				"outputPrefixType": "TINK"
			}
		]
	}`

	promotedJSON := mustRunTinkey(t, keysetJSON, "promote-key", "--key-id=02222")

	if got := primaryKeyID(t, parseCleartextKeyset(t, promotedJSON)); got != 2222 {
		t.Errorf("primary key id = %d, want 2222", got)
	}
}

// Java Tinkey's destroy-key keeps the entry of the key but empties its key
// data. The entry must survive every command until delete-key removes it.
func TestKeyDestroyedByJavaTinkeyIsKeptUntilDeleted(t *testing.T) {
	// The first key is what Java Tinkey 1.14.0 writes after destroy-key.
	const keysetJSON = `{
		"primaryKeyId": 2222,
		"key": [
			{
				"keyData": {
					"typeUrl": "",
					"value": "",
					"keyMaterialType": "UNKNOWN_KEYMATERIAL"
				},
				"status": "DESTROYED",
				"keyId": 1111,
				"outputPrefixType": "TINK"
			},
			{
				"keyData": {
					"typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey",
					"value": "GiDKN7vJ2YgH3pfW0QbM0VQx0cXc1m3T8cJ2b1x4Vn0pLw==",
					"keyMaterialType": "SYMMETRIC"
				},
				"status": "ENABLED",
				"keyId": 2222,
				"outputPrefixType": "TINK"
			}
		]
	}`
	const destroyedKeyInfo = "  status: DESTROYED\n  key_id: 1111\n"

	rotatedJSON := mustRunTinkey(t, keysetJSON, "rotate-keyset", "--key-template", "AES256_GCM")
	if listing := mustRunTinkey(t, rotatedJSON, "list-keyset"); !strings.Contains(listing, destroyedKeyInfo) {
		t.Errorf("list-keyset after rotate-keyset printed:\n%s\nwant it to contain:\n%s", listing, destroyedKeyInfo)
	}

	if _, err := runTinkey(t, keysetJSON, "enable-key", "--key-id=1111"); err == nil {
		t.Error("enable-key enabled a destroyed key, want an error")
	}

	deletedJSON := mustRunTinkey(t, keysetJSON, "delete-key", "--key-id=1111")
	if listing := mustRunTinkey(t, deletedJSON, "list-keyset"); strings.Contains(listing, "key_id: 1111") {
		t.Errorf("list-keyset after delete-key printed:\n%s\nwant no key 1111", listing)
	}
}

func TestListKeysetPrintsKeyInfoWithoutKeyMaterial(t *testing.T) {
	const keysetJSON = `{
		"primaryKeyId": 2222,
		"key": [
			{
				"keyData": {
					"typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey",
					"value": "GiCXlcAQx22K2CHz5QxtRGoQnT72rWskeP4VLTXQyY658Q==",
					"keyMaterialType": "SYMMETRIC"
				},
				"status": "DISABLED",
				"keyId": 1111,
				"outputPrefixType": "TINK"
			},
			{
				"keyData": {
					"typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey",
					"value": "GiDKN7vJ2YgH3pfW0QbM0VQx0cXc1m3T8cJ2b1x4Vn0pLw==",
					"keyMaterialType": "SYMMETRIC"
				},
				"status": "ENABLED",
				"keyId": 2222,
				"outputPrefixType": "TINK"
			}
		]
	}`
	const want = `primary_key_id: 2222
key_info {
  type_url: "type.googleapis.com/google.crypto.tink.AesGcmKey"
  status: DISABLED
  key_id: 1111
  output_prefix_type: TINK
}
key_info {
  type_url: "type.googleapis.com/google.crypto.tink.AesGcmKey"
  status: ENABLED
  key_id: 2222
  output_prefix_type: TINK
}

`
	if got := mustRunTinkey(t, keysetJSON, "list-keyset"); got != want {
		t.Errorf("list-keyset printed:\n%s\nwant:\n%s", got, want)
	}
}

func TestListKeyTemplatesListsJavaTinkeyTemplates(t *testing.T) {
	listing := mustRunTinkey(t, "", "list-key-templates")

	lines := strings.Split(strings.TrimSuffix(listing, "\n"), "\n")
	if lines[0] != "The following key templates are supported:" {
		t.Errorf("first line = %q, want the Java Tinkey heading", lines[0])
	}
	names := lines[1:]
	// Java Tinkey 1.14.0 has 147 templates; the 4 AES-EAX ones are left out.
	if len(names) != 143 {
		t.Errorf("listed %d key templates, want 143", len(names))
	}
	if !slices.IsSorted(names) {
		t.Errorf("key templates are not sorted: %v", names)
	}
	for _, name := range []string{"AES256_GCM", "HMAC_SHA256_256BITTAG", "ECDSA_P256", "HKDF_SHA256_DERIVES_AES256_GCM"} {
		if !slices.Contains(names, name) {
			t.Errorf("key template %s is not listed", name)
		}
	}
	if slices.Contains(names, "AES128_EAX") {
		t.Error("AES128_EAX is listed, but tink-go cannot generate AES-EAX keys")
	}
}

// A listed template that tink-go cannot generate a key for would only fail when
// a user asks for it.
func TestEveryListedKeyTemplateCreatesAKeyset(t *testing.T) {
	for name := range keyTemplates {
		keysetJSON, err := runTinkey(t, "", "create-keyset", "--key-template", name)
		if err != nil {
			t.Errorf("create-keyset --key-template %s: %v", name, err)
			continue
		}
		if _, err := runTinkey(t, keysetJSON, "list-keyset"); err != nil {
			t.Errorf("list-keyset of a new %s keyset: %v", name, err)
		}
	}
}

func TestCreatePublicKeysetVerifiesSignaturesOfPrivateKeyset(t *testing.T) {
	privateJSON := mustRunTinkey(t, "", "create-keyset", "--key-template", "ECDSA_P256")

	publicJSON := mustRunTinkey(t, privateJSON, "create-public-keyset")

	// ReadWithNoSecrets fails if the keyset still holds a private key.
	publicHandle, err := keyset.ReadWithNoSecrets(keyset.NewJSONReader(strings.NewReader(publicJSON)))
	if err != nil {
		t.Fatalf("read the public keyset: %v", err)
	}
	signer, err := signature.NewSigner(parseCleartextKeyset(t, privateJSON))
	if err != nil {
		t.Fatalf("signature.NewSigner: %v", err)
	}
	verifier, err := signature.NewVerifier(publicHandle)
	if err != nil {
		t.Fatalf("signature.NewVerifier: %v", err)
	}
	signed, err := signer.Sign([]byte("message"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := verifier.Verify(signed, []byte("message")); err != nil {
		t.Errorf("the public keyset does not verify a signature of the private keyset: %v", err)
	}
}

func TestCreatePublicKeysetRejectsSymmetricKeyset(t *testing.T) {
	symmetricJSON := mustRunTinkey(t, "", "create-keyset", "--key-template", "AES256_GCM")

	stdout, err := runTinkey(t, symmetricJSON, "create-public-keyset")

	if err == nil {
		t.Error("create-public-keyset succeeded on a symmetric keyset, want an error")
	}
	if stdout != "" {
		t.Errorf("wrote %q to stdout, want nothing", stdout)
	}
}

func TestDestroyKeyErasesKeyMaterialAndKeepsEntry(t *testing.T) {
	keysetJSON := mustRunTinkey(t, "", "create-keyset", "--key-template", "AES256_GCM")
	original := parseCleartextKeyset(t, keysetJSON)
	oldKeyID := primaryKeyID(t, original)
	oldKeyMaterial := insecurecleartextkeyset.KeysetMaterial(original).GetKey()[0].GetKeyData().GetValue()
	rotatedJSON := mustRunTinkey(t, keysetJSON, "rotate-keyset", "--key-template", "AES256_GCM")

	destroyedJSON := mustRunTinkey(t, rotatedJSON, "destroy-key", keyIDFlag(oldKeyID))

	destroyedKeyset, err := keyset.NewJSONReader(strings.NewReader(destroyedJSON)).Read()
	if err != nil {
		t.Fatalf("parse the keyset written by destroy-key: %v", err)
	}
	if len(destroyedKeyset.GetKey()) != 2 {
		t.Fatalf("keyset has %d keys, want 2", len(destroyedKeyset.GetKey()))
	}
	for _, key := range destroyedKeyset.GetKey() {
		if key.GetKeyId() != oldKeyID {
			continue
		}
		if key.GetStatus() != tinkpb.KeyStatusType_DESTROYED {
			t.Errorf("status of key %d = %s, want DESTROYED", oldKeyID, key.GetStatus())
		}
		if len(key.GetKeyData().GetValue()) != 0 {
			t.Errorf("key %d still has key material", oldKeyID)
		}
	}
	if strings.Contains(destroyedJSON, base64.StdEncoding.EncodeToString(oldKeyMaterial)) {
		t.Error("the keyset written by destroy-key still contains the destroyed key material")
	}
	// As Java Tinkey prints a destroyed key: without a type_url line.
	wantKeyInfo := "key_info {\n  status: DESTROYED\n  key_id: " + strconv.FormatUint(uint64(oldKeyID), 10) + "\n"
	if listing := mustRunTinkey(t, destroyedJSON, "list-keyset"); !strings.Contains(listing, wantKeyInfo) {
		t.Errorf("list-keyset after destroy-key printed:\n%s\nwant it to contain:\n%s", listing, wantKeyInfo)
	}
}

func TestDestroyKeyRejectsPrimaryAndAbsentKeys(t *testing.T) {
	keysetJSON := mustRunTinkey(t, "", "create-keyset", "--key-template", "AES256_GCM")
	primary := primaryKeyID(t, parseCleartextKeyset(t, keysetJSON))

	tests := []struct {
		name      string
		keyID     uint32
		wantError string
	}{
		{"primary key", primary, "cannot destroy the primary key"},
		{"absent key", primary + 1, "key not found"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stdout, err := runTinkey(t, keysetJSON, "destroy-key", keyIDFlag(test.keyID))
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Errorf("error = %v, want it to contain %q", err, test.wantError)
			}
			if stdout != "" {
				t.Errorf("wrote %q to stdout, want nothing", stdout)
			}
		})
	}
}

func TestConvertKeysetBetweenJSONAndBinaryFiles(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "keyset.json")
	binaryPath := filepath.Join(dir, "keyset.bin")
	mustRunTinkey(t, "", "create-keyset", "--key-template", "AES256_GCM", "--out", jsonPath)

	// Upper case: the format flags ignore case, as in Java Tinkey.
	mustRunTinkey(t, "", "convert-keyset", "--in", jsonPath, "--out", binaryPath, "--out-format", "BINARY")

	binaryKeyset, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	fromBinary, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(bytes.NewReader(binaryKeyset)))
	if err != nil {
		t.Fatalf("read the binary keyset written by convert-keyset: %v", err)
	}
	jsonKeyset, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	wantKeyID := primaryKeyID(t, parseCleartextKeyset(t, string(jsonKeyset)))
	if got := primaryKeyID(t, fromBinary); got != wantKeyID {
		t.Errorf("binary keyset primary key id = %d, want %d", got, wantKeyID)
	}

	backToJSON := mustRunTinkey(t, "", "convert-keyset", "--in", binaryPath, "--in-format", "binary")
	if got := primaryKeyID(t, parseCleartextKeyset(t, backToJSON)); got != wantKeyID {
		t.Errorf("keyset converted back to JSON has primary key id %d, want %d", got, wantKeyID)
	}
}

func TestOutputFileIsPrivate(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "keyset.json")
	mustRunTinkey(t, "", "create-keyset", "--key-template", "AES256_GCM", "--out", outPath)

	info, err := os.Stat(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("keyset file mode = %o, want 600", got)
	}
}
