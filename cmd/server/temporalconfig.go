package main

import (
	"errors"
	"fmt"
	"path"

	"go.temporal.io/server/common/config"
)

// Defaults of the stock `temporal-server start` flags. The stock image runs
// with WORKDIR /etc/temporal, so "." plus "config" resolves to
// /etc/temporal/config, where the stock Helm chart mounts its config.
const (
	defaultRoot = "."
	defaultDir  = "config"
	defaultEnv  = "development"
)

// loadTemporalConfig loads Temporal's own server config the way the stock
// `temporal-server start` does, so the stock Helm chart and image env vars
// keep working unchanged. As in the stock CLI, a variable counts as set when
// it is present, even if empty.
//
//  1. TEMPORAL_SERVER_CONFIG_FILE_PATH: load that one file. Combining it
//     with TEMPORAL_ROOT, TEMPORAL_CONFIG_DIR, TEMPORAL_ENVIRONMENT or
//     TEMPORAL_AVAILABILITY_ZONE is an error, as upstream.
//  2. Any of the dir, env or zone vars set: load <root>/<dir>/base.yaml,
//     then <env>.yaml, then the zone file. Unset parts take upstream defaults.
//  3. None set: the embedded template, filled from env vars. This is the
//     stock default too; the config directory is NOT read unless selected.
//
// One addition to upstream: an absolute dir with no explicit root is used
// as-is. Upstream joins it onto the default root ("."), which turns "/etc/x"
// into the relative "etc/x". With an explicit root, behavior is upstream's.
//
// lookup is os.LookupEnv in production; tests pass a map lookup.
func loadTemporalConfig(lookup func(string) (string, bool)) (*config.Config, error) {
	file, fileSet := lookup(config.EnvKeyConfigFile)
	root, rootSet := lookup(config.EnvKeyRoot)
	dir, dirSet := lookup(config.EnvKeyConfigDir)
	env, envSet := lookup(config.EnvKeyEnvironment)
	zone, zoneSet := lookup(config.EnvKeyAvailabilityZone)
	if !zoneSet {
		zone, zoneSet = lookup(config.EnvKeyAvailabilityZoneTypo)
	}

	switch {
	case fileSet:
		if rootSet || dirSet || envSet || zoneSet {
			return nil, errors.New("cannot use " + config.EnvKeyRoot + ", " + config.EnvKeyConfigDir +
				", " + config.EnvKeyEnvironment + " or " + config.EnvKeyAvailabilityZone +
				" with " + config.EnvKeyConfigFile)
		}
		return config.Load(config.WithConfigFile(file))
	case dirSet || envSet || zoneSet:
		if !rootSet {
			root = defaultRoot
		}
		if !dirSet {
			dir = defaultDir
		}
		if !envSet {
			env = defaultEnv
		}
		if !path.IsAbs(dir) || (rootSet && root != defaultRoot) {
			dir = path.Join(root, dir)
		}
		return config.Load(
			config.WithEnv(env),
			config.WithConfigDir(dir),
			config.WithZone(zone),
		)
	default:
		cfg, err := config.Load(config.WithEmbedded())
		if err != nil {
			return nil, fmt.Errorf("embedded config: %w", err)
		}
		return cfg, nil
	}
}
