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
	"maps"
	"os"
	"regexp"

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

	// Attributes adds to or overrides the principal attributes a Cedar policy
	// can read (`principal.<name>`). Each value is an RE2 regular expression
	// with exactly one capture group. It is anchored at both ends, so it must
	// match the caller's whole SPIFFE ID (add `.*` for the parts you ignore);
	// the captured text is the attribute value, or "" when it does not match. A name that equals a default (trust_domain, ns, sa) replaces it.
	Attributes map[string]string `yaml:"attributes"`

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

// applyDefaults fills optional fields that were left empty.
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
	if _, err := c.AttributeRules(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// DefaultAttributes are the principal attributes available with no config.
// They cover the Kubernetes SPIFFE ID shape spiffe://<td>/ns/<ns>/sa/<sa>. An
// ID of another shape yields "" for ns and sa rather than an error.
var DefaultAttributes = map[string]string{
	"trust_domain": `spiffe://([^/]+)(?:/.*)?`,
	"ns":           `spiffe://[^/]+/ns/([^/]+)/sa/[^/]+`,
	"sa":           `spiffe://[^/]+/ns/[^/]+/sa/([^/]+)`,
}

// cedarIdent is what Cedar accepts after `principal.`.
var cedarIdent = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// cedarReserved cannot be used as an attribute name in dot form.
var cedarReserved = map[string]bool{
	"true": true, "false": true, "if": true, "then": true, "else": true,
	"in": true, "is": true, "like": true, "has": true,
	"principal": true, "action": true, "resource": true, "context": true,
	"permit": true, "forbid": true, "when": true, "unless": true,
}

// AttributeRules returns the compiled attribute rules: DefaultAttributes with
// the customer's Attributes layered on top. It reports every bad name or
// pattern so a ConfigMap typo is caught at startup, not at the first request.
func (c *Config) AttributeRules() (map[string]*regexp.Regexp, error) {
	merged := make(map[string]string, len(DefaultAttributes)+len(c.Attributes))
	maps.Copy(merged, DefaultAttributes)
	maps.Copy(merged, c.Attributes)

	rules := make(map[string]*regexp.Regexp, len(merged))
	var errs []error
	for name, pattern := range merged {
		if !cedarIdent.MatchString(name) || cedarReserved[name] {
			errs = append(errs, fmt.Errorf("attributes: %q is not a usable Cedar attribute name", name))
			continue
		}
		// Anchor both ends so a rule matches the whole ID, never a substring
		// of a lookalike path.
		re, err := regexp.Compile(`^(?:` + pattern + `)$`)
		if err != nil {
			errs = append(errs, fmt.Errorf("attributes.%s: %w", name, err))
			continue
		}
		if re.NumSubexp() != 1 {
			errs = append(errs, fmt.Errorf("attributes.%s: pattern needs exactly one capture group, has %d", name, re.NumSubexp()))
			continue
		}
		rules[name] = re
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return rules, nil
}
