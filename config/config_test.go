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
		"bad attr name":       "version: 1\ntrustDomain: x\npolicyPath: /p\nattributes:\n  \"a-b\": \"(x)\"\n",
		"reserved attr name":  "version: 1\ntrustDomain: x\npolicyPath: /p\nattributes:\n  principal: \"(x)\"\n",
		"bad attr regex":      "version: 1\ntrustDomain: x\npolicyPath: /p\nattributes:\n  team: \"(\"\n",
		"attr no group":       "version: 1\ntrustDomain: x\npolicyPath: /p\nattributes:\n  team: \"abc\"\n",
		"attr two groups":     "version: 1\ntrustDomain: x\npolicyPath: /p\nattributes:\n  team: \"(a)(b)\"\n",
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

func TestLoad_Attributes(t *testing.T) {
	t.Parallel()
	cfg, err := Load(writeConfig(t, "version: 1\ntrustDomain: x\npolicyPath: /p\nattributes:\n  nameSpace: \".*/ns/([^/]+)/.*\"\n"))
	require.NoError(t, err)
	rules, err := cfg.AttributeRules()
	require.NoError(t, err)
	require.Contains(t, rules, "nameSpace")
	require.Contains(t, rules, "ns", "defaults kept")
}
