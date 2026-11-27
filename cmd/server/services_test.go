package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Only the services that take client calls build the authorizer and claim
// mapper. History, matching and worker pods run as the stock image does.
func TestTakesClientCalls(t *testing.T) {
	t.Parallel()
	require.True(t, takesClientCalls([]string{"frontend"}))
	require.True(t, takesClientCalls([]string{"internal-frontend"}))
	require.True(t, takesClientCalls([]string{"history", "frontend"}))
	for _, s := range []string{"history", "matching", "worker"} {
		require.False(t, takesClientCalls([]string{s}), s)
	}
}

// The metric tag names the listener the process serves.
func TestClientServiceName(t *testing.T) {
	t.Parallel()
	require.Equal(t, "frontend", clientServiceName([]string{"frontend"}))
	require.Equal(t, "internal-frontend", clientServiceName([]string{"internal-frontend"}))
	require.Equal(t, "frontend,internal-frontend", clientServiceName([]string{"frontend", "history", "internal-frontend"}))
	require.Empty(t, clientServiceName([]string{"history"}))
}
