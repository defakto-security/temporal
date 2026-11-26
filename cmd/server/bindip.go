package main

import (
	"fmt"
	"net"
	"os"
)

const (
	envBindOnIP         = "BIND_ON_IP"
	envBroadcastAddress = "TEMPORAL_BROADCAST_ADDRESS"
)

// setBindEnv does what the stock image's entrypoint.sh does before it starts
// the server, so a drop-in image behaves the same under the stock chart:
//
//   - BIND_ON_IP unset: resolve this host's name and use the first address.
//   - BIND_ON_IP is a wildcard (0.0.0.0 or ::0) and TEMPORAL_BROADCAST_ADDRESS
//     is unset: set it to the resolved address.
//
// Values the operator set are never overwritten. The env vars are read by
// Temporal's built-in config template, and by any config file that uses them.
func setBindEnv(getenv func(string) string, setenv func(k, v string) error, hostname func() (string, error), lookup func(string) ([]string, error)) error {
	var resolved string
	resolve := func() (string, error) {
		if resolved != "" {
			return resolved, nil
		}
		h, err := hostname()
		if err != nil {
			return "", fmt.Errorf("resolving host name: %w", err)
		}
		addrs, err := lookup(h)
		if err != nil {
			return "", fmt.Errorf("resolving host %q for %s: %w", h, envBindOnIP, err)
		}
		if len(addrs) == 0 {
			return "", fmt.Errorf("resolving host %q for %s: no addresses", h, envBindOnIP)
		}
		resolved = addrs[0]
		return resolved, nil
	}

	bind := getenv(envBindOnIP)
	if bind == "" {
		ip, err := resolve()
		if err != nil {
			return err
		}
		bind = ip
		if err := setenv(envBindOnIP, bind); err != nil {
			return err
		}
	}
	if (bind == "0.0.0.0" || bind == "::0") && getenv(envBroadcastAddress) == "" {
		ip, err := resolve()
		if err != nil {
			return err
		}
		return setenv(envBroadcastAddress, ip)
	}
	return nil
}

// setBindEnvFromHost runs setBindEnv against the real process and resolver.
func setBindEnvFromHost() error {
	return setBindEnv(os.Getenv, os.Setenv, os.Hostname, net.LookupHost)
}
