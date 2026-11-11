package main

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRunTool_NotSelected(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{nil, {"server"}, {"server", "other"}} {
		ran, err := runTool(args)
		require.False(t, ran)
		require.NoError(t, err)
	}
}

// TestRunTool_PingIsSigned is a SigV4 wiring test, not an OpenSearch or IRSA
// integration test. It runs `ping` against a local stand-in and checks the
// request carries a signature for "es" in the region from AWS_REGION. It does
// not run setup-schema or create-index. If ping fails, the upstream tool exits
// the test binary with status 1, so a failure here shows as a package failure.
func TestRunTool_PingIsSigned(t *testing.T) {
	// The tool reads these as flag defaults; keep the host's out of the test.
	for _, k := range []string{"ES_SERVER", "ES_USER", "ES_PWD", "AWS_CREDENTIALS", "AWS_SESSION_TOKEN", "ES_VISIBILITY_INDEX"} {
		t.Setenv(k, "")
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	t.Setenv("AWS_REGION", "us-east-2")

	var mu sync.Mutex
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		auth = r.Header.Get("Authorization")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":{"number":"7.10.2"}}`))
	}))
	defer srv.Close()

	ran, err := runTool([]string{"server", CmdElasticsearchTool,
		"--ep", srv.URL, "--aws-credentials", "aws-sdk-default", "ping"})
	require.True(t, ran)
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.Regexp(t, regexp.MustCompile(`^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/\d{8}/us-east-2/es/aws4_request`), auth)
}
