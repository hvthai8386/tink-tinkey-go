package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/pflag"
	"github.com/tink-crypto/tink-go-awskms/v3/integration/awskms"
	"github.com/tink-crypto/tink-go-gcpkms/v2/integration/gcpkms"
	"github.com/tink-crypto/tink-go/v2/tink"
	"golang.org/x/oauth2"
	"google.golang.org/api/option"
)

const (
	gcpKMSURIPrefix = "gcp-kms://"
	awsKMSURIPrefix = "aws-kms://"
)

// gcpKMSEndpoint overrides the Cloud KMS API endpoint. It stays empty outside
// tests, which point it at a fake KMS server.
var gcpKMSEndpoint string

// awsKMSClient replaces the AWS KMS client. It stays nil outside tests, which
// set a fake KMS.
var awsKMSClient awskms.KMSAPI

// masterKeyOptions identify the KMS key that encrypts a keyset at rest and how
// to authenticate to the KMS.
type masterKeyOptions struct {
	// flagPrefix is "new-" for the output key of convert-keyset, else empty.
	flagPrefix     string
	uri            string
	credentialPath string
	accessToken    string
}

// addFlags defines --master-key-uri, --credential and --token, each with the
// given prefix. keysetName says in the help text which keyset the key protects.
func (o *masterKeyOptions) addFlags(flags *pflag.FlagSet, prefix, keysetName string) {
	o.flagPrefix = prefix
	flags.StringVar(&o.uri, prefix+"master-key-uri", "",
		"KMS key that encrypts "+keysetName+", as "+
			"gcp-kms://projects/*/locations/*/keyRings/*/cryptoKeys/* or "+
			"aws-kms://arn:aws:kms:<region>:<account-id>:key/<key-id>; "+
			keysetName+" is in cleartext if not specified")
	flags.StringVar(&o.credentialPath, prefix+"credential", "",
		"Credential file used to call the KMS: a service account JSON file for Google Cloud, "+
			"a CSV or INI credentials file for AWS; "+
			"the default credentials of the environment are used if neither this nor --"+prefix+"token is specified")
	flags.StringVar(&o.accessToken, prefix+"token", "",
		"OAuth 2.0 access token of a service account, used to call Google Cloud KMS; "+
			"it is visible to other users in the process list")
}

// aead returns the AEAD that encrypts and decrypts keysets with the KMS master
// key. It returns nil when no master key URI is given: the keyset is then read
// or written in cleartext.
func (o *masterKeyOptions) aead(ctx context.Context) (tink.AEAD, error) {
	uriFlag := "--" + o.flagPrefix + "master-key-uri"
	credentialFlag := "--" + o.flagPrefix + "credential"
	tokenFlag := "--" + o.flagPrefix + "token"

	if o.uri == "" {
		// A forgotten URI would otherwise produce a cleartext keyset while
		// the caller expects an encrypted one.
		if o.credentialPath != "" || o.accessToken != "" {
			return nil, fmt.Errorf("%s and %s require %s", credentialFlag, tokenFlag, uriFlag)
		}
		return nil, nil
	}
	if o.credentialPath != "" && o.accessToken != "" {
		return nil, fmt.Errorf("%s and %s are mutually exclusive", credentialFlag, tokenFlag)
	}

	switch {
	case strings.HasPrefix(o.uri, gcpKMSURIPrefix):
		masterKey, err := o.gcpKMSAEAD(ctx)
		if err != nil {
			return nil, fmt.Errorf("%s %s: %w", uriFlag, o.uri, err)
		}
		return masterKey, nil
	case strings.HasPrefix(o.uri, awsKMSURIPrefix):
		if o.accessToken != "" {
			return nil, fmt.Errorf("%s is supported only with %s keys, not with %s %s",
				tokenFlag, gcpKMSURIPrefix, uriFlag, o.uri)
		}
		masterKey, err := o.awsKMSAEAD(ctx)
		if err != nil {
			return nil, fmt.Errorf("%s %s: %w", uriFlag, o.uri, err)
		}
		return masterKey, nil
	default:
		return nil, fmt.Errorf("unsupported %s %q: it must start with %s or %s",
			uriFlag, o.uri, gcpKMSURIPrefix, awsKMSURIPrefix)
	}
}

// gcpKMSAEAD authenticates to Cloud KMS with --token if given, else with
// --credential, else with Application Default Credentials. The last case needs
// no flag on GKE Workload Identity, where the metadata server issues the token
// of the pod's service account.
func (o *masterKeyOptions) gcpKMSAEAD(ctx context.Context) (tink.AEAD, error) {
	var apiOptions []option.ClientOption
	if o.accessToken != "" {
		staticToken := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: o.accessToken})
		apiOptions = append(apiOptions, option.WithTokenSource(staticToken))
	}
	if o.credentialPath != "" {
		apiOptions = append(apiOptions, option.WithAuthCredentialsFile(option.ServiceAccount, o.credentialPath))
	}
	if gcpKMSEndpoint != "" {
		apiOptions = append(apiOptions, option.WithEndpoint(gcpKMSEndpoint))
	}

	// REST is the transport Java Tinkey uses, and the fake KMS of the tests
	// speaks it over plain HTTP.
	client, err := gcpkms.NewClient(ctx, gcpKMSURIPrefix,
		gcpkms.WithTransport(gcpkms.TransportREST),
		gcpkms.WithGoogleAPIClientOptions(apiOptions...))
	if err != nil {
		return nil, fmt.Errorf("create Cloud KMS client: %w", err)
	}
	return client.GetAEAD(o.uri)
}

// awsKMSAEAD authenticates to AWS KMS with --credential if given, else with the
// default credentials chain of the AWS SDK (environment, shared config, role of
// the instance or pod).
func (o *masterKeyOptions) awsKMSAEAD(ctx context.Context) (tink.AEAD, error) {
	var clientOptions []awskms.ClientOption
	if o.credentialPath != "" {
		clientOptions = append(clientOptions, awskms.WithCredentialPath(o.credentialPath))
	}
	if awsKMSClient != nil {
		clientOptions = append(clientOptions, awskms.WithKMS(awsKMSClient))
	}

	// The client must be made for this one key: it reads the AWS region from
	// the key ARN in its URI prefix.
	client, err := awskms.NewClientWithOptions(ctx, o.uri, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("create AWS KMS client: %w", err)
	}
	return client.GetAEAD(o.uri)
}
