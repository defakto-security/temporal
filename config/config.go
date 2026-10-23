// Package config defines the defakto-spiffe-temporal config contract: the
// versioned schema a customer's ConfigMap fills in (trust domain, issuer /
// audience / JWKS for token verification, the DevID path template the
// human/service derivation keys on, and the path to the Cedar policy).
//
// This is the stable surface a customer configures; it is deliberately
// separate from go.temporal.io/server's own config, which stays stock.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"go.yaml.in/yaml/v3"
)

// EnvConfigPath names the environment variable holding the path to this
// module's config file (the one the customer's ConfigMap mounts). It is
// distinct from Temporal's own config dir.
const EnvConfigPath = "DEFAKTO_SPIFFE_TEMPORAL_CONFIG"

// SchemaVersion is the current config-contract version. A loaded config whose
// Version does not match is rejected at startup rather than best-effort parsed.
const SchemaVersion = 1

// DefaultDevIDTemplate is the human-identity path template assumed when the
// customer does not override it. The human/service role derivation is a
// prefix test against the rendered form of this template.
const DefaultDevIDTemplate = "/users/{domain}/{username}"

// Config is the parsed, validated config contract.
type Config struct {
	// Version pins the schema. Must equal SchemaVersion.
	Version int `yaml:"version"`

	// TrustDomain is the Defakto SPIFFE trust domain this cluster authenticates
	// against, e.g. "corp.defakto.security".
	TrustDomain string `yaml:"trustDomain"`

	// DevIDTemplate is the DevID path template for human identities. The
	// leading literal segment (before the first placeholder) is the prefix the
	// human/service test keys on. Defaults to DefaultDevIDTemplate.
	DevIDTemplate string `yaml:"devIDTemplate"`

	// Human holds the portal-issued-OIDC verification parameters used to
	// validate human bearer tokens forwarded from Temporal Web. Optional until
	// Milestone 2 (Temporal Web authentication).
	Human HumanTokenConfig `yaml:"human"`

	// PolicyPath is the filesystem path to the customer-owned Cedar policy,
	// mounted from the ConfigMap. The authorizer loads, validates, and
	// hot-reloads it, failing closed on absent/invalid.
	PolicyPath string `yaml:"policyPath"`
}

// HumanTokenConfig carries the parameters for verifying portal-issued OIDC
// tokens (Milestone 2). forwardHeaders is transport, not trust: the frontend
// must verify signature/issuer/audience/expiry against the portal JWKS.
type HumanTokenConfig struct {
	Issuer   string `yaml:"issuer"`
	Audience string `yaml:"audience"`
	JWKSURL  string `yaml:"jwksURL"`
}

// Load reads and validates the config at path. An empty path, a missing file,
// or an invalid document is an error: the server must not start half-configured.
func Load(path string) (*Config, error) {
	if path == "" {
		return nil, fmt.Errorf("config: %s is unset; the ConfigMap must mount a config file", EnvConfigPath)
	}
	raw, err := os.ReadFile(path) //nolint:gosec // path is operator-supplied config, not user input.
	if err != nil {
		return nil, fmt.Errorf("config: reading %q: %w", path, err)
	}
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true) // reject unknown keys rather than silently dropping them.
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("config: parsing %q: %w", path, err)
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config: %q: %w", path, err)
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.DevIDTemplate == "" {
		c.DevIDTemplate = DefaultDevIDTemplate
	}
}

// Validate checks the required invariants of the config contract.
func (c *Config) Validate() error {
	var errs []error
	if c.Version != SchemaVersion {
		errs = append(errs, fmt.Errorf("version %d is unsupported (want %d)", c.Version, SchemaVersion))
	}
	if c.TrustDomain == "" {
		errs = append(errs, errors.New("trustDomain is required"))
	}
	if c.PolicyPath == "" {
		errs = append(errs, errors.New("policyPath is required"))
	}
	return errors.Join(errs...)
}
