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

// TestRunTool_SignsRequests runs the tool against a local stand-in for
// OpenSearch and checks the request carries a SigV4 signature for "es".
func TestRunTool_SignsRequests(t *testing.T) {
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
