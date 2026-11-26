package main

import (
	"errors"
	"maps"
	"testing"

	"github.com/stretchr/testify/require"
)

func runBind(t *testing.T, in map[string]string, lookupErr error) (map[string]string, error) {
	t.Helper()
	m := map[string]string{}
	maps.Copy(m, in)
	err := setBindEnv(
		func(k string) string { return m[k] },
		func(k, v string) error { m[k] = v; return nil },
		func() (string, error) { return "pod-1", nil },
		func(string) ([]string, error) {
			if lookupErr != nil {
				return nil, lookupErr
			}
			return []string{"10.0.0.7", "10.0.0.8"}, nil
		},
	)
	return m, err
}

func TestSetBindEnv(t *testing.T) {
	t.Parallel()
	t.Run("unset resolves host", func(t *testing.T) {
		t.Parallel()
		m, err := runBind(t, nil, nil)
		require.NoError(t, err)
		require.Equal(t, "10.0.0.7", m["BIND_ON_IP"])
		require.Empty(t, m["TEMPORAL_BROADCAST_ADDRESS"])
	})
	t.Run("wildcard sets broadcast", func(t *testing.T) {
		t.Parallel()
		for _, w := range []string{"0.0.0.0", "::0"} {
			m, err := runBind(t, map[string]string{"BIND_ON_IP": w}, nil)
			require.NoError(t, err)
			require.Equal(t, w, m["BIND_ON_IP"])
			require.Equal(t, "10.0.0.7", m["TEMPORAL_BROADCAST_ADDRESS"])
		}
	})
	t.Run("operator values kept", func(t *testing.T) {
		t.Parallel()
		m, err := runBind(t, map[string]string{"BIND_ON_IP": "0.0.0.0", "TEMPORAL_BROADCAST_ADDRESS": "1.2.3.4"}, errors.New("unused"))
		require.NoError(t, err)
		require.Equal(t, "1.2.3.4", m["TEMPORAL_BROADCAST_ADDRESS"])
	})
	t.Run("specific ip needs no lookup", func(t *testing.T) {
		t.Parallel()
		m, err := runBind(t, map[string]string{"BIND_ON_IP": "10.9.9.9"}, errors.New("unused"))
		require.NoError(t, err)
		require.Equal(t, "10.9.9.9", m["BIND_ON_IP"])
	})
	t.Run("lookup failure is an error", func(t *testing.T) {
		t.Parallel()
		_, err := runBind(t, nil, errors.New("no such host"))
		require.ErrorContains(t, err, "BIND_ON_IP")
	})
}
