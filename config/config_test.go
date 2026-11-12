package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

// writeConfig is a test helper or test case in this package.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

// TestLoad_Valid is a test helper or test case in this package.
func TestLoad_Valid(t *testing.T) {
	t.Parallel()
	path := writeConfig(t, `
version: 1
workloadAPI:
  audience: temporal
policyPath: /etc/defakto-spiffe-temporal/policy.cedar
`)
	cfg, err := Load(path)
	require.NoError(t, err)
	require.Equal(t, "temporal", cfg.WorkloadAPI.Audience)
	m, err := cfg.HumanMatcher()
	require.NoError(t, err)
	require.False(t, m.Matches(spiffeid.RequireFromString("spiffe://td.example/users/a/b")), "no template: nobody is human")
}

// TestLoad_Errors is a test helper or test case in this package.
func TestLoad_Errors(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"wrong version":      "version: 99\nworkloadAPI: {audience: a}\npolicyPath: /p\n",
		"missing audience":   "version: 1\npolicyPath: /p\n",
		"missing policyPath": "version: 1\nworkloadAPI: {audience: a}\n",
		"unknown key":        "version: 1\nworkloadAPI: {audience: a}\npolicyPath: /p\nbogus: true\n",
		"bad attr name":      "version: 1\nworkloadAPI: {audience: a}\npolicyPath: /p\nattributes:\n  \"a-b\": \"(x)\"\n",
		"reserved attr name": "version: 1\nworkloadAPI: {audience: a}\npolicyPath: /p\nattributes:\n  principal: \"(x)\"\n",
		"bad attr regex":     "version: 1\nworkloadAPI: {audience: a}\npolicyPath: /p\nattributes:\n  team: \"(\"\n",
		"attr no group":      "version: 1\nworkloadAPI: {audience: a}\npolicyPath: /p\nattributes:\n  team: \"abc\"\n",
		"attr two groups":    "version: 1\nworkloadAPI: {audience: a}\npolicyPath: /p\nattributes:\n  team: \"(a)(b)\"\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := Load(writeConfig(t, body))
			require.Error(t, err)
		})
	}
}

// TestLoad_EmptyPath is a test helper or test case in this package.
func TestLoad_EmptyPath(t *testing.T) {
	t.Parallel()
	_, err := Load("")
	require.Error(t, err)
}

// TestLoad_Attributes is a test helper or test case in this package.
func TestLoad_Attributes(t *testing.T) {
	t.Parallel()
	cfg, err := Load(writeConfig(t, "version: 1\nworkloadAPI: {audience: a}\npolicyPath: /p\nattributes:\n  nameSpace: \".*/ns/([^/]+)/.*\"\n"))
	require.NoError(t, err)
	rules, err := cfg.AttributeRules()
	require.NoError(t, err)
	require.Contains(t, rules, "nameSpace")
	require.Contains(t, rules, "ns", "defaults kept")
}

// TestLoad_DatabaseIAM checks the databaseIAM defaults and bounds.
func TestLoad_DatabaseIAM(t *testing.T) {
	t.Parallel()
	base := "version: 1\nworkloadAPI: {audience: a}\npolicyPath: /p\n"

	cfg, err := Load(writeConfig(t, base+"databaseIAM:\n  enabled: true\n"))
	require.NoError(t, err)
	require.Equal(t, 10*time.Minute, cfg.DatabaseIAM.RefreshInterval, "default interval")

	cfg, err = Load(writeConfig(t, base))
	require.NoError(t, err)
	require.False(t, cfg.DatabaseIAM.Enabled, "off by default")

	_, err = Load(writeConfig(t, base+"databaseIAM:\n  enabled: true\n  refreshInterval: 15m\n"))
	require.ErrorContains(t, err, "refreshInterval")
}

// TestReferenceConfigMapLoads keeps the shipped example in step with the schema.
func TestReferenceConfigMapLoads(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("../reference/configmap.example.yaml")
	require.NoError(t, err)
	var cm struct {
		Data map[string]string `yaml:"data"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &cm))
	cfg, err := Load(writeConfig(t, cm.Data["config.yaml"]))
	require.NoError(t, err)
	require.Equal(t, "temporal/prod-example", cfg.WorkloadAPI.Audience)
	_, err = cfg.HumanMatcher()
	require.NoError(t, err)
}

func TestLoad_AttributePatternSchemeStripped(t *testing.T) {
	t.Parallel()
	cfg, err := Load(writeConfig(t, "version: 1\nworkloadAPI: {audience: a}\npolicyPath: /p\nattributes:\n  k: 'spiffe://[^/]+/k8s/([^/]+)/.*'\n"))
	require.NoError(t, err)
	rules, err := cfg.AttributeRules()
	require.NoError(t, err)
	require.Equal(t, "x", rules["k"].FindStringSubmatch("td/k8s/x/y")[1])
}

// A path-only devIDTemplate would let a federated domain mint humans, so it
// needs an explicit opt-in.
func TestLoad_PathOnlyDevIDNeedsOptIn(t *testing.T) {
	t.Parallel()
	base := "version: 1\nworkloadAPI: {audience: a}\npolicyPath: /p\ndevIDTemplate: /users/{d}/{u}\n"
	_, err := Load(writeConfig(t, base))
	require.ErrorContains(t, err, "humanFromAnyTrustDomain")
	_, err = Load(writeConfig(t, base+"humanFromAnyTrustDomain: true\n"))
	require.NoError(t, err)
}

// trust_domain is the ID's own domain; a pattern cannot replace it.
func TestLoad_TrustDomainAttributeReserved(t *testing.T) {
	t.Parallel()
	_, err := Load(writeConfig(t, "version: 1\nworkloadAPI: {audience: a}\npolicyPath: /p\nattributes:\n  trust_domain: '.*/td/([^/]+)/.*'\n"))
	require.ErrorContains(t, err, "cannot be overridden")
}

// A pattern that still carries spiffe:// anywhere but the front never matches.
func TestLoad_AttributePatternWithSchemeInside(t *testing.T) {
	t.Parallel()
	for _, p := range []string{`^spiffe://x/(.*)`, `(?:spiffe://)?x/(.*)`, `spiffe:\/\/x/(.*)`, `(spiffe://[^/]+)/.*`} {
		_, err := Load(writeConfig(t, "version: 1\nworkloadAPI: {audience: a}\npolicyPath: /p\nattributes:\n  k: '"+p+"'\n"))
		require.ErrorContains(t, err, "without spiffe://", p)
	}
}

func TestIDMatcher(t *testing.T) {
	t.Parallel()
	id := spiffeid.RequireFromString
	cfg := &Config{DevIDTemplate: "spiffe://admin.example.org/users/{domain}/{username}", ServiceIDTemplate: "/ns/{ns}/sa/{sa}"}
	human, err := cfg.HumanMatcher()
	require.NoError(t, err)
	svc, err := cfg.ServiceMatcher()
	require.NoError(t, err)

	require.True(t, human.Matches(id("spiffe://admin.example.org/users/example.org/alice")))
	require.False(t, human.Matches(id("spiffe://admin.example.org/users/a")), "too short")
	require.False(t, human.Matches(id("spiffe://admin.example.org/users/a/b/c")), "too long")
	require.False(t, human.Matches(id("spiffe://admin.example.org/users2/a/b")))
	require.False(t, human.Matches(id("spiffe://partner.example.net/users/a/b")), "other domain")

	require.True(t, svc.Matches(id("spiffe://anything.example/ns/a/sa/b")), "path-only service matches any domain")
	require.False(t, svc.Matches(id("spiffe://anything.example/ns/a")))

	all, err := (&Config{}).ServiceMatcher()
	require.NoError(t, err)
	require.True(t, all.Matches(id("spiffe://x.example/anything")), "no service template: all match")
}

func TestIDTemplate_Errors(t *testing.T) {
	t.Parallel()
	for _, tmpl := range []string{"users/{x}", "/", "/users{x}", "/users/", "/users/{x", "/users/x}", "spiffe://Bad_TD!/users/{x}", "spiffe://td", "spiffe://{td}/users/{x}"} {
		_, err := (&Config{ServiceIDTemplate: tmpl}).ServiceMatcher()
		require.Error(t, err, tmpl)
	}
}
