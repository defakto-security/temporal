// Package visibility holds checks for the Temporal visibility datastore
// config that ships with the image (OpenSearch via SigV4).
package visibility

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
	"go.temporal.io/server/common/config"
	"go.temporal.io/server/common/persistence/visibility/store/elasticsearch/client"
	"go.yaml.in/yaml/v3"
)

// TestSigV4Config checks Temporal's own aws-request-signing support, as the
// Helm values for the visibility store would configure it. It signs for
// service "es" in the configured region. "aws-sdk-default" is the provider to
// use with IRSA (it reads the web-identity env vars); this test feeds it plain
// env credentials, because there is no STS here to test the IRSA exchange.
func TestSigV4Config(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(t.TempDir(), "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "credentials"))

	gotCh := make(chan http.Header, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCh <- r.Header.Clone()
	}))
	defer srv.Close()

	hc, err := client.NewAwsHttpClient(client.ESAWSRequestSigningConfig{
		Enabled:            true,
		Region:             "us-east-2",
		CredentialProvider: "aws-sdk-default",
	})
	require.NoError(t, err)
	require.NotNil(t, hc)

	resp, err := hc.Get(srv.URL + "/_cluster/health")
	require.NoError(t, err)
	_ = resp.Body.Close()

	got := <-gotCh
	auth := got.Get("Authorization")
	require.Regexp(t, regexp.MustCompile(`^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/\d{8}/us-east-2/es/aws4_request, SignedHeaders=[a-z0-9;-]+, Signature=[0-9a-f]{64}$`), auth)
	require.NotEmpty(t, got.Get("X-Amz-Date"))
}

// TestSigV4RequiresRegion guards against a silent unsigned fallback.
func TestSigV4RequiresRegion(t *testing.T) {
	t.Setenv("AWS_REGION", "")
	_, err := client.NewAwsHttpClient(client.ESAWSRequestSigningConfig{
		Enabled:            true,
		CredentialProvider: "environment",
	})
	require.Error(t, err)
}

// TestSigV4UnknownProvider rejects typos in credentialProvider.
func TestSigV4UnknownProvider(t *testing.T) {
	t.Parallel()
	_, err := client.NewAwsHttpClient(client.ESAWSRequestSigningConfig{
		Enabled:            true,
		Region:             "us-east-2",
		CredentialProvider: "irsa",
	})
	require.Error(t, err)
}

// TestReferenceConfig_Visibility loads the shipped reference config the way
// Temporal does and checks the visibility store is OpenSearch with IRSA
// signing, and that the whole persistence block passes Temporal's validation.
func TestReferenceConfig_Visibility(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("../reference/temporal-visibility.example.yaml")
	require.NoError(t, err)

	var cfg struct {
		Persistence config.Persistence `yaml:"persistence"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &cfg))
	require.NoError(t, cfg.Persistence.Validate())

	require.Equal(t, "es-visibility", cfg.Persistence.VisibilityStore)
	es := cfg.Persistence.DataStores["es-visibility"].Elasticsearch
	require.NotNil(t, es)
	require.Equal(t, "v7", es.Version)
	require.Equal(t, "https", es.URL.Scheme)
	require.False(t, es.EnableSniff)
	require.Empty(t, es.Username)
	require.Empty(t, es.Password)
	require.True(t, es.AWSRequestSigning.Enabled)
	require.Equal(t, "aws-sdk-default", es.AWSRequestSigning.CredentialProvider)
	require.NotEmpty(t, es.AWSRequestSigning.Region)
	require.NotEmpty(t, es.GetVisibilityIndex())
}
