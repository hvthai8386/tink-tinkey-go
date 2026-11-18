package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"hash/crc32"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"google.golang.org/api/cloudkms/v1"
)

const (
	masterKeyURI      = "gcp-kms://projects/p/locations/global/keyRings/r/cryptoKeys/master"
	masterKeyName     = "projects/p/locations/global/keyRings/r/cryptoKeys/master"
	newMasterKeyURI   = "gcp-kms://projects/p/locations/global/keyRings/r/cryptoKeys/new-master"
	newMasterKeyName  = "projects/p/locations/global/keyRings/r/cryptoKeys/new-master"
	metadataToken     = "token-from-metadata-server"
	tokenEndpointPath = "/token"
	// tokenEndpointToken is what the fake OAuth token endpoint issues to a
	// service account key file.
	tokenEndpointToken = "token-from-token-endpoint"
)

// kmsCall is one request the fake Cloud KMS accepted.
type kmsCall struct {
	operation   string // "encrypt" or "decrypt"
	keyName     string
	bearerToken string
}

// fakeGoogleCloud serves, from one local HTTP server, the Google endpoints the
// CLI reaches when a keyset is encrypted with a master key: Cloud KMS, the
// OAuth token endpoint a service account key file points to, and the metadata
// server that issues Workload Identity tokens.
type fakeGoogleCloud struct {
	url string
	// gcm encrypts for every fake KMS key; the key name is bound into each
	// ciphertext, so decrypting with another key fails as in Cloud KMS.
	gcm cipher.AEAD

	mu       sync.Mutex
	kmsCalls []kmsCall
}

// startFakeGoogleCloud starts the fake and points the CLI at it: the Cloud KMS
// endpoint through gcpKMSEndpoint, the metadata server through
// GCE_METADATA_HOST. It also hides the developer's own Google credentials, so
// Application Default Credentials can only come from the fake metadata server.
func startFakeGoogleCloud(t *testing.T) *fakeGoogleCloud {
	t.Helper()
	cloud := &fakeGoogleCloud{gcm: newFakeKMSCipher(t)}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/", cloud.serveKMS)
	mux.HandleFunc("POST "+tokenEndpointPath, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"access_token": tokenEndpointToken, "token_type": "Bearer", "expires_in": 3600})
	})
	mux.HandleFunc("GET /computeMetadata/v1/instance/service-accounts/default/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata-Flavor") != "Google" {
			http.Error(w, "missing Metadata-Flavor header", http.StatusForbidden)
			return
		}
		writeJSON(w, map[string]any{"access_token": metadataToken, "token_type": "Bearer", "expires_in": 3600})
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	cloud.url = server.URL

	gcpKMSEndpoint = server.URL
	t.Cleanup(func() { gcpKMSEndpoint = "" })
	t.Setenv("GCE_METADATA_HOST", strings.TrimPrefix(server.URL, "http://"))
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	t.Setenv("HOME", t.TempDir())
	return cloud
}

// newFakeKMSCipher returns the cipher a fake KMS encrypts with, under a random key.
func newFakeKMSCipher(t *testing.T) cipher.AEAD {
	t.Helper()
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return gcm
}

func (c *fakeGoogleCloud) serveKMS(w http.ResponseWriter, r *http.Request) {
	bearerToken, hasBearerToken := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !hasBearerToken {
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return
	}
	keyName, operation, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/v1/"), ":")

	switch operation {
	case "encrypt":
		var request cloudkms.EncryptRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		plaintext, err := base64.URLEncoding.DecodeString(request.Plaintext)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		nonce := make([]byte, c.gcm.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		ciphertext := c.gcm.Seal(nonce, nonce, plaintext, []byte(keyName))
		writeJSON(w, &cloudkms.EncryptResponse{
			Ciphertext:              base64.StdEncoding.EncodeToString(ciphertext),
			CiphertextCrc32c:        crc32c(ciphertext),
			VerifiedPlaintextCrc32c: true,
			VerifiedAdditionalAuthenticatedDataCrc32c: true,
		})
	case "decrypt":
		var request cloudkms.DecryptRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		ciphertext, err := base64.URLEncoding.DecodeString(request.Ciphertext)
		if err != nil || len(ciphertext) < c.gcm.NonceSize() {
			http.Error(w, "malformed ciphertext", http.StatusBadRequest)
			return
		}
		nonce, sealed := ciphertext[:c.gcm.NonceSize()], ciphertext[c.gcm.NonceSize():]
		plaintext, err := c.gcm.Open(nil, nonce, sealed, []byte(keyName))
		if err != nil {
			http.Error(w, "ciphertext was not encrypted with "+keyName, http.StatusBadRequest)
			return
		}
		writeJSON(w, &cloudkms.DecryptResponse{
			Plaintext:       base64.StdEncoding.EncodeToString(plaintext),
			PlaintextCrc32c: crc32c(plaintext),
		})
	default:
		http.NotFound(w, r)
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.kmsCalls = append(c.kmsCalls, kmsCall{operation: operation, keyName: keyName, bearerToken: bearerToken})
}

// takeKMSCalls returns the KMS calls accepted since the previous call to it.
func (c *fakeGoogleCloud) takeKMSCalls() []kmsCall {
	c.mu.Lock()
	defer c.mu.Unlock()
	calls := c.kmsCalls
	c.kmsCalls = nil
	return calls
}

func writeJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	// The Metadata-Flavor response header is what the metadata client checks.
	w.Header().Set("Metadata-Flavor", "Google")
	if err := json.NewEncoder(w).Encode(body); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func crc32c(data []byte) int64 {
	return int64(crc32.Checksum(data, crc32.MakeTable(crc32.Castagnoli)))
}

// assertEncryptedKeyset fails the test unless keysetJSON is an encrypted keyset
// that exposes no cleartext key.
func assertEncryptedKeyset(t *testing.T, keysetJSON string) {
	t.Helper()
	encrypted, err := keyset.NewJSONReader(strings.NewReader(keysetJSON)).ReadEncrypted()
	if err != nil || len(encrypted.GetEncryptedKeyset()) == 0 {
		t.Fatalf("output %q is not an encrypted keyset: %v", keysetJSON, err)
	}
	if _, err := insecurecleartextkeyset.Read(keyset.NewJSONReader(strings.NewReader(keysetJSON))); err == nil {
		t.Fatalf("output %q parses as a cleartext keyset", keysetJSON)
	}
}

func TestCreateKeysetEncryptsWithMasterKeyUsingAccessToken(t *testing.T) {
	cloud := startFakeGoogleCloud(t)

	encryptedJSON := mustRunTinkey(t, "", "create-keyset", "--key-template", "AES256_GCM",
		"--master-key-uri", masterKeyURI, "--token", "access-token")

	assertEncryptedKeyset(t, encryptedJSON)
	wantCalls := []kmsCall{{"encrypt", masterKeyName, "access-token"}}
	if got := cloud.takeKMSCalls(); !slices.Equal(got, wantCalls) {
		t.Errorf("KMS calls = %v, want %v", got, wantCalls)
	}

	listing := mustRunTinkey(t, encryptedJSON, "list-keyset", "--master-key-uri", masterKeyURI, "--token", "access-token")
	if !strings.Contains(listing, "google.crypto.tink.AesGcmKey") {
		t.Errorf("list-keyset of the encrypted keyset printed %q, want an AesGcmKey", listing)
	}
	if _, err := runTinkey(t, encryptedJSON, "list-keyset"); err == nil {
		t.Error("list-keyset read an encrypted keyset without --master-key-uri, want an error")
	}
}

func TestRotateKeysetKeepsKeysetEncrypted(t *testing.T) {
	startFakeGoogleCloud(t)
	masterKeyFlags := []string{"--master-key-uri", masterKeyURI, "--token", "access-token"}
	decrypt := func(encryptedJSON string) *keyset.Handle {
		return parseCleartextKeyset(t, mustRunTinkey(t, encryptedJSON, append([]string{"convert-keyset"}, masterKeyFlags...)...))
	}
	encryptedJSON := mustRunTinkey(t, "", append([]string{"create-keyset", "--key-template", "AES256_GCM"}, masterKeyFlags...)...)
	originalKeyID := primaryKeyID(t, decrypt(encryptedJSON))

	rotatedJSON := mustRunTinkey(t, encryptedJSON, append([]string{"rotate-keyset", "--key-template", "AES256_GCM"}, masterKeyFlags...)...)

	assertEncryptedKeyset(t, rotatedJSON)
	rotated := decrypt(rotatedJSON)
	newKeyID := otherKeyID(t, rotated, originalKeyID)
	if got := primaryKeyID(t, rotated); got != newKeyID {
		t.Errorf("primary key id = %d, want the new key %d", got, newKeyID)
	}
}

func TestConvertKeysetMovesKeysetToNewMasterKey(t *testing.T) {
	cloud := startFakeGoogleCloud(t)
	cleartextJSON := mustRunTinkey(t, "", "create-keyset", "--key-template", "HMAC_SHA256_128BITTAG")
	wantKeyID := primaryKeyID(t, parseCleartextKeyset(t, cleartextJSON))
	underMasterKeyJSON := mustRunTinkey(t, cleartextJSON, "convert-keyset",
		"--new-master-key-uri", masterKeyURI, "--new-token", "access-token")
	assertEncryptedKeyset(t, underMasterKeyJSON)
	cloud.takeKMSCalls()

	underNewMasterKeyJSON := mustRunTinkey(t, underMasterKeyJSON, "convert-keyset",
		"--master-key-uri", masterKeyURI, "--token", "access-token",
		"--new-master-key-uri", newMasterKeyURI, "--new-token", "new-access-token")

	assertEncryptedKeyset(t, underNewMasterKeyJSON)
	wantCalls := []kmsCall{
		{"decrypt", masterKeyName, "access-token"},
		{"encrypt", newMasterKeyName, "new-access-token"},
	}
	if got := cloud.takeKMSCalls(); !slices.Equal(got, wantCalls) {
		t.Errorf("KMS calls = %v, want %v", got, wantCalls)
	}
	if _, err := runTinkey(t, underNewMasterKeyJSON, "list-keyset", "--master-key-uri", masterKeyURI, "--token", "access-token"); err == nil {
		t.Error("the old master key still decrypts the converted keyset")
	}
	decryptedJSON := mustRunTinkey(t, underNewMasterKeyJSON, "convert-keyset",
		"--master-key-uri", newMasterKeyURI, "--token", "new-access-token")
	if got := primaryKeyID(t, parseCleartextKeyset(t, decryptedJSON)); got != wantKeyID {
		t.Errorf("primary key id after moving master keys = %d, want %d", got, wantKeyID)
	}
}

func TestConvertKeysetRejectsNewTokenWithoutNewMasterKey(t *testing.T) {
	cleartextJSON := mustRunTinkey(t, "", "create-keyset", "--key-template", "AES256_GCM")

	stdout, err := runTinkey(t, cleartextJSON, "convert-keyset", "--new-token", "access-token")

	const wantError = "--new-credential and --new-token require --new-master-key-uri"
	if err == nil || !strings.Contains(err.Error(), wantError) {
		t.Errorf("error = %v, want it to contain %q", err, wantError)
	}
	if stdout != "" {
		t.Errorf("wrote %q to stdout, want nothing", stdout)
	}
}

func TestMasterKeyAuthenticatesWithWorkloadIdentityByDefault(t *testing.T) {
	cloud := startFakeGoogleCloud(t)

	encryptedJSON := mustRunTinkey(t, "", "create-keyset", "--key-template", "AES256_GCM",
		"--master-key-uri", masterKeyURI)

	assertEncryptedKeyset(t, encryptedJSON)
	wantCalls := []kmsCall{{"encrypt", masterKeyName, metadataToken}}
	if got := cloud.takeKMSCalls(); !slices.Equal(got, wantCalls) {
		t.Errorf("KMS calls = %v, want %v", got, wantCalls)
	}
}

func TestMasterKeyAuthenticatesWithServiceAccountFile(t *testing.T) {
	cloud := startFakeGoogleCloud(t)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	serviceAccountKey, err := json.Marshal(map[string]string{
		"type":           "service_account",
		"project_id":     "p",
		"private_key_id": "key-id",
		"private_key":    string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER})),
		"client_email":   "tinkey@p.iam.gserviceaccount.com",
		"token_uri":      cloud.url + tokenEndpointPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	credentialPath := filepath.Join(t.TempDir(), "credential.json")
	if err := os.WriteFile(credentialPath, serviceAccountKey, 0o600); err != nil {
		t.Fatal(err)
	}

	encryptedJSON := mustRunTinkey(t, "", "create-keyset", "--key-template", "AES256_GCM",
		"--master-key-uri", masterKeyURI, "--credential", credentialPath)

	assertEncryptedKeyset(t, encryptedJSON)
	wantCalls := []kmsCall{{"encrypt", masterKeyName, tokenEndpointToken}}
	if got := cloud.takeKMSCalls(); !slices.Equal(got, wantCalls) {
		t.Errorf("KMS calls = %v, want %v", got, wantCalls)
	}
}

// fakeAWSKMS stands in for AWS KMS. As in fakeGoogleCloud, the key id is bound
// into each ciphertext, so decrypting with another key fails.
type fakeAWSKMS struct {
	gcm cipher.AEAD
	// encryptedWithKeyIDs lists the key id of every Encrypt call.
	encryptedWithKeyIDs []string
}

func (f *fakeAWSKMS) Encrypt(_ context.Context, input *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	nonce := make([]byte, f.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	f.encryptedWithKeyIDs = append(f.encryptedWithKeyIDs, *input.KeyId)
	return &kms.EncryptOutput{
		KeyId:          input.KeyId,
		CiphertextBlob: f.gcm.Seal(nonce, nonce, input.Plaintext, []byte(*input.KeyId)),
	}, nil
}

func (f *fakeAWSKMS) Decrypt(_ context.Context, input *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	if len(input.CiphertextBlob) < f.gcm.NonceSize() {
		return nil, errors.New("malformed ciphertext")
	}
	nonce, sealed := input.CiphertextBlob[:f.gcm.NonceSize()], input.CiphertextBlob[f.gcm.NonceSize():]
	plaintext, err := f.gcm.Open(nil, nonce, sealed, []byte(*input.KeyId))
	if err != nil {
		return nil, errors.New("ciphertext was not encrypted with " + *input.KeyId)
	}
	return &kms.DecryptOutput{KeyId: input.KeyId, Plaintext: plaintext}, nil
}

func TestKeysetEncryptedWithAWSKMSMasterKey(t *testing.T) {
	const (
		awsKeyARN      = "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555"
		otherAWSKeyARN = "arn:aws:kms:us-east-1:123456789012:key/99999999-2222-3333-4444-555555555555"
	)
	fakeKMS := &fakeAWSKMS{gcm: newFakeKMSCipher(t)}
	awsKMSClient = fakeKMS
	t.Cleanup(func() { awsKMSClient = nil })

	encryptedJSON := mustRunTinkey(t, "", "create-keyset", "--key-template", "AES256_GCM",
		"--master-key-uri", "aws-kms://"+awsKeyARN)

	assertEncryptedKeyset(t, encryptedJSON)
	if want := []string{awsKeyARN}; !slices.Equal(fakeKMS.encryptedWithKeyIDs, want) {
		t.Errorf("AWS KMS encrypted with keys %v, want %v", fakeKMS.encryptedWithKeyIDs, want)
	}
	rotatedJSON := mustRunTinkey(t, encryptedJSON, "rotate-keyset", "--key-template", "AES256_GCM",
		"--master-key-uri", "aws-kms://"+awsKeyARN)
	listing := mustRunTinkey(t, rotatedJSON, "list-keyset", "--master-key-uri", "aws-kms://"+awsKeyARN)
	if got := strings.Count(listing, "key_info {"); got != 2 {
		t.Errorf("list-keyset after rotate-keyset printed %d keys, want 2:\n%s", got, listing)
	}
	if _, err := runTinkey(t, rotatedJSON, "list-keyset", "--master-key-uri", "aws-kms://"+otherAWSKeyARN); err == nil {
		t.Error("another AWS KMS key decrypted the keyset, want an error")
	}
}
