package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"go.temporal.io/server/common/config"
)

const minimalConfig = `log:
  stdout: true
  level: info
persistence:
  defaultStore: s
  visibilityStore: s
  numHistoryShards: 1
  datastores:
    s:
      sql:
        pluginName: sqlite
        databaseName: default
        connectAddr: localhost
        connectProtocol: tcp
        connectAttributes:
          mode: memory
          cache: private
`

func env(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func write(t *testing.T, path, body string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
}

func TestLoadTemporalConfig_File(t *testing.T) {
	t.Parallel()
	f := filepath.Join(t.TempDir(), "mounted.yaml")
	write(t, f, minimalConfig)
	cfg, err := loadTemporalConfig(env(map[string]string{"TEMPORAL_SERVER_CONFIG_FILE_PATH": f}))
	require.NoError(t, err)
	require.Equal(t, "info", cfg.Log.Level)
}

func TestLoadTemporalConfig_FileConflicts(t *testing.T) {
	t.Parallel()
	// Set-but-empty counts as set, as in the stock CLI.
	for _, k := range []string{"TEMPORAL_ROOT", "TEMPORAL_CONFIG_DIR", "TEMPORAL_ENVIRONMENT", "TEMPORAL_AVAILABILITY_ZONE", config.EnvKeyAvailabilityZoneTypo} {
		_, err := loadTemporalConfig(env(map[string]string{"TEMPORAL_SERVER_CONFIG_FILE_PATH": "/x.yaml", k: "v"}))
		require.ErrorContains(t, err, "TEMPORAL_SERVER_CONFIG_FILE_PATH", k)
	}
}

func TestLoadTemporalConfig_Dir(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	// Chart-style mount: <root>/<dir>/base.yaml, default env "development".
	write(t, filepath.Join(root, "etc", "base.yaml"), minimalConfig)
	write(t, filepath.Join(root, "etc", "development.yaml"), "log:\n  level: debug\n")
	cfg, err := loadTemporalConfig(env(map[string]string{
		"TEMPORAL_ROOT":       root,
		"TEMPORAL_CONFIG_DIR": "etc",
	}))
	require.NoError(t, err)
	require.Equal(t, "debug", cfg.Log.Level)
}

func TestLoadTemporalConfig_DirAbsolute(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write(t, filepath.Join(dir, "base.yaml"), minimalConfig)
	write(t, filepath.Join(dir, "docker.yaml"), "log:\n  level: warn\n")
	cfg, err := loadTemporalConfig(env(map[string]string{
		"TEMPORAL_CONFIG_DIR":  dir,
		"TEMPORAL_ENVIRONMENT": "docker",
	}))
	require.NoError(t, err)
	require.Equal(t, "warn", cfg.Log.Level)
}

func TestLoadTemporalConfig_EmbeddedWhenUnset(t *testing.T) {
	// Root alone does not select the dir mode, as upstream.
	t.Setenv("BIND_ON_IP", "127.0.0.1")
	t.Setenv("CASSANDRA_SEEDS", "127.0.0.1")
	cfg, err := loadTemporalConfig(env(map[string]string{"TEMPORAL_ROOT": "/etc/temporal"}))
	require.NoError(t, err)
	require.NotNil(t, cfg)
}

func TestLoadTemporalConfig_EmptyVarCountsAsSet(t *testing.T) {
	t.Parallel()
	_, err := loadTemporalConfig(env(map[string]string{"TEMPORAL_SERVER_CONFIG_FILE_PATH": "/x.yaml", "TEMPORAL_CONFIG_DIR": ""}))
	require.ErrorContains(t, err, "cannot use")
	// Empty dir selects dir mode (root "."), not the embedded template.
	_, err = loadTemporalConfig(env(map[string]string{"TEMPORAL_CONFIG_DIR": ""}))
	require.ErrorContains(t, err, "config files")
}

func TestLoadTemporalConfig_AbsoluteDirWithExplicitRootJoins(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	// Upstream joins: <root>/<abs dir>.
	write(t, filepath.Join(root, "etc", "x", "base.yaml"), minimalConfig)
	_, err := loadTemporalConfig(env(map[string]string{"TEMPORAL_ROOT": root, "TEMPORAL_CONFIG_DIR": "/etc/x"}))
	require.NoError(t, err)
}
