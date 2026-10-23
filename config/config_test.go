package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

func TestLoad_Valid(t *testing.T) {
	t.Parallel()
	path := writeConfig(t, `
version: 1
trustDomain: corp.defakto.security
policyPath: /etc/defakto-spiffe-temporal/policy.cedar
`)
	cfg, err := Load(path)
	require.NoError(t, err)
	require.Equal(t, "corp.defakto.security", cfg.TrustDomain)
	require.Equal(t, DefaultDevIDTemplate, cfg.DevIDTemplate, "default applied")
}

func TestLoad_Errors(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"wrong version":       "version: 99\ntrustDomain: x\npolicyPath: /p\n",
		"missing trustDomain": "version: 1\npolicyPath: /p\n",
		"missing policyPath":  "version: 1\ntrustDomain: x\n",
		"unknown key":         "version: 1\ntrustDomain: x\npolicyPath: /p\nbogus: true\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := Load(writeConfig(t, body))
			require.Error(t, err)
		})
	}
}

func TestLoad_EmptyPath(t *testing.T) {
	t.Parallel()
	_, err := Load("")
	require.Error(t, err)
}
