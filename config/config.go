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
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// EnvConfigPath names the environment variable holding the path to this
// module's config file (the one the customer's ConfigMap mounts). It is
// distinct from Temporal's own config dir.
const EnvConfigPath = "DEFAKTO_SPIFFE_TEMPORAL_CONFIG"

// SchemaVersion is the current config-contract version. A loaded config whose
// Version does not match is rejected at startup rather than best-effort parsed.
const SchemaVersion = 1

// Config is the parsed, validated config contract.
type Config struct {
	// Version pins the schema. Must equal SchemaVersion.
	Version int `yaml:"version"`

	// WorkloadAPI says where to get the keys that verify a caller's JWT-SVID.
	// Trust domains are not listed: the SPIFFE agent decides which bundles it
	// holds (including federated ones), and the Cedar policy decides what each
	// trust domain may do, through `principal.trust_domain`.
	WorkloadAPI WorkloadAPIConfig `yaml:"workloadAPI"`

	// ClientCertAuth lets a caller with no `authorization` header be identified
	// by its mTLS client certificate, if that is an X.509-SVID with one
	// canonical SPIFFE ID as its URI SAN. Temporal's worker and scheduler need
	// this, as they dial the frontend over mTLS only. A header always wins.
	// Temporal's TLS must verify the chain (tls.frontend.server.requireClientAuth
	// and clientCaFiles); the mapper then checks the cert against the roots of
	// its own trust domain, from the Workload API. Without a verified chain the
	// cert is ignored. Default off.
	ClientCertAuth bool `yaml:"clientCertAuth"`

	// DevIDTemplate is the SPIFFE ID template for human identities. An ID is
	// human only if its whole path fits the template: each {placeholder} is one
	// non-empty path segment. Write the full form,
	// "spiffe://admin.example.org/users/{domain}/{username}", to accept humans
	// from one trust domain only. The literal part before the first placeholder
	// must end in "/". Empty means no identity is human. A path-only form
	// ("/users/{domain}/{username}") matches the path in ANY trust domain, and
	// is refused unless HumanFromAnyTrustDomain is true.
	DevIDTemplate string `yaml:"devIDTemplate"`

	// HumanFromAnyTrustDomain allows a path-only DevIDTemplate. Do not set it
	// if the agent federates with other trust domains.
	HumanFromAnyTrustDomain bool `yaml:"humanFromAnyTrustDomain"`

	// ServiceIDTemplate optionally limits which identities are services, with
	// the same grammar as DevIDTemplate. An ID that is neither human nor a
	// service gets no role class and is denied. Empty means every ID that is
	// not human is a service.
	ServiceIDTemplate string `yaml:"serviceIDTemplate"`

	// Human holds the portal-issued-OIDC verification parameters used to
	// validate human bearer tokens forwarded from Temporal Web. Optional until
	// Milestone 2 (Temporal Web authentication).
	Human HumanTokenConfig `yaml:"human"`

	// Attributes adds to or overrides the principal attributes a Cedar policy
	// can read (`principal.<name>`). Each value is an RE2 regular expression
	// with exactly one capture group, matched against the caller's SPIFFE ID
	// without the "spiffe://" scheme (a leading "spiffe://" in the pattern is
	// stripped). It is anchored at both ends, so it must
	// match the whole ID (add `.*` for the parts you ignore);
	// the captured text is the attribute value, or "" when it does not match. A name that equals a default (ns, sa) replaces it. trust_domain is always the ID's own trust domain and cannot be set here.
	Attributes map[string]string `yaml:"attributes"`

	// DatabaseIAM turns on RDS IAM authentication for Temporal's Postgres
	// stores (IRSA, no stored password). Off by default.
	DatabaseIAM DatabaseIAMConfig `yaml:"databaseIAM"`

	// PolicyPath is the filesystem path to the customer-owned Cedar policy,
	// mounted from the ConfigMap. The authorizer loads, validates, and
	// hot-reloads it, failing closed on absent/invalid.
	PolicyPath string `yaml:"policyPath"`

	// ShadowPolicyPath is an optional candidate Cedar policy. When set, every
	// call is also evaluated against the candidate; the live decision is still
	// the one enforced. Disagreements are logged: would_deny (live allowed,
	// candidate denies) and would_allow (live denied, candidate allows). In the
	// metric, a disagreement is shadow_decision="delta". Used to test a narrower policy before it
	// replaces the live one. Empty disables shadow mode.
	ShadowPolicyPath string `yaml:"shadowPolicyPath"`

	// DecisionLog selects which authorization decisions are logged: "off"
	// (default; only evaluation errors and shadow/identity divergences, would_deny and would_allow, are logged), "deny", or
	// "all" (every decision, with principal, attributes, namespace, API and verb).
	DecisionLog string `yaml:"decisionLog"`

	// IdentityMode controls the checks that run before any policy: a caller
	// must be authenticated, have a role class, and present a canonical SPIFFE
	// ID. "enforce" (default) denies a call that fails them.
	// "observe" allows it anyway, logs it as would_deny, and counts it as
	// decision="allow" with the
	// reason, so you can find callers without a valid identity before turning
	// enforcement on. Policy decisions are unaffected: a missing or broken live
	// policy still denies, and calls to forbidden-all, break-glass or
	// unclassified APIs stay denied. Observe is no stricter than running with
	// no authorizer at all; do not leave it on once callers are identified.
	IdentityMode string `yaml:"identityMode"`
}

// Identity modes for Config.IdentityMode.
const (
	IdentityModeEnforce = "enforce"
	IdentityModeObserve = "observe"
)

// Decision-log levels for Config.DecisionLog.
const (
	DecisionLogOff  = "off"
	DecisionLogDeny = "deny"
	DecisionLogAll  = "all"
)

// DatabaseIAMConfig configures RDS IAM database authentication. When enabled,
// every SQL store in Temporal's own config must use pluginName postgres12_pgx,
// have TLS on, and leave password unset.
type DatabaseIAMConfig struct {
	// Enabled switches IAM auth on.
	Enabled bool `yaml:"enabled"`
	// Region is the RDS region. Empty means the AWS_REGION env var.
	Region string `yaml:"region"`
	// RefreshInterval is how often a new token is signed in the background.
	// A token lasts 15 minutes. Default 10m; at least MinRefreshInterval; at most 14m.
	RefreshInterval time.Duration `yaml:"refreshInterval"`
}

// MinRefreshInterval is the shortest allowed databaseIAM.refreshInterval.
// Shorter values would hammer STS/credential providers for no benefit.
const MinRefreshInterval = 30 * time.Second

// WorkloadAPIConfig configures the SPIFFE Workload API source that supplies
// JWT bundles. The agent streams bundles over a local socket; a token is
// verified against that in-memory copy, with no call per request.
type WorkloadAPIConfig struct {
	// Address is the agent socket, e.g. unix:///run/spiffe/agent.sock. Empty
	// means the SPIFFE_ENDPOINT_SOCKET env var.
	Address string `yaml:"address"`
	// Audience is the one aud every accepted JWT-SVID must carry (a token with
	// extra audiences is refused). Required. Make it unique per cluster, such
	// as "temporal/prod-us-east-2", so a token for one cluster is useless on
	// another. A JWT-SVID is a bearer token: serve the frontend over TLS.
	Audience string `yaml:"audience"`
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
	if c.IdentityMode == "" {
		c.IdentityMode = IdentityModeEnforce
	}
	if c.DecisionLog == "" {
		c.DecisionLog = DecisionLogOff
	}
	if c.DatabaseIAM.Enabled && c.DatabaseIAM.RefreshInterval == 0 {
		c.DatabaseIAM.RefreshInterval = 10 * time.Minute
	}
}

// Validate checks the required invariants of the config contract.
func (c *Config) Validate() error {
	var errs []error
	if c.Version != SchemaVersion {
		errs = append(errs, fmt.Errorf("version %d is unsupported (want %d)", c.Version, SchemaVersion))
	}
	if c.WorkloadAPI.Audience == "" {
		errs = append(errs, errors.New("workloadAPI.audience is required"))
	}
	if _, err := c.HumanMatcher(); err != nil {
		errs = append(errs, err)
	}
	if _, err := c.ServiceMatcher(); err != nil {
		errs = append(errs, err)
	}
	if c.PolicyPath == "" {
		errs = append(errs, errors.New("policyPath is required"))
	}
	switch c.DecisionLog {
	case "", DecisionLogOff, DecisionLogDeny, DecisionLogAll:
	default:
		errs = append(errs, fmt.Errorf("decisionLog %q must be one of off, deny, all", c.DecisionLog))
	}
	switch c.IdentityMode {
	case "", IdentityModeEnforce, IdentityModeObserve:
	default:
		errs = append(errs, fmt.Errorf("identityMode %q must be one of enforce, observe", c.IdentityMode))
	}
	if c.ShadowPolicyPath != "" && filepath.Clean(c.ShadowPolicyPath) == filepath.Clean(c.PolicyPath) {
		errs = append(errs, errors.New("shadowPolicyPath must differ from policyPath"))
	}
	if _, err := c.AttributeRules(); err != nil {
		errs = append(errs, err)
	}
	if iam := c.DatabaseIAM; iam.Enabled && (iam.RefreshInterval < MinRefreshInterval || iam.RefreshInterval > 14*time.Minute) {
		errs = append(errs, errors.New("databaseIAM.refreshInterval must be between 30s and 14m (tokens last 15m)"))
	}
	return errors.Join(errs...)
}

// SPIFFEScheme is the prefix every SPIFFE ID starts with. Attribute patterns
// are matched against the ID without it (a leading copy in a pattern is
// stripped at load), so `<td>/ns/<ns>/sa/<sa>` is what a pattern sees.
const SPIFFEScheme = "spiffe://"

// TrustDomainAttribute is the principal attribute holding the caller's trust
// domain. The authorizer sets it from the parsed SPIFFE ID, never from a
// pattern, so config cannot override it: policies rely on it as the boundary
// between trust domains.
const TrustDomainAttribute = "trust_domain"

// DefaultAttributes are the pattern-based principal attributes available with
// no config (trust_domain is set separately, see TrustDomainAttribute). They
// cover the Kubernetes SPIFFE ID shape spiffe://<td>/ns/<ns>/sa/<sa>. An ID of
// another shape yields "" for ns and sa rather than an error. Patterns see the
// ID without "spiffe://".
var DefaultAttributes = map[string]string{
	"ns": `[^/]+/ns/([^/]+)/sa/[^/]+`,
	"sa": `[^/]+/ns/[^/]+/sa/([^/]+)`,
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
		// Patterns see the ID without "spiffe://"; drop a leading copy so
		// either spelling works. Anchor both ends so a rule matches the whole
		// ID, never a substring of a lookalike path.
		if name == TrustDomainAttribute {
			errs = append(errs, fmt.Errorf("attributes.%s: trust_domain is set from the SPIFFE ID and cannot be overridden", name))
			continue
		}
		pattern = strings.TrimPrefix(pattern, SPIFFEScheme)
		if strings.Contains(pattern, "spiffe:") {
			errs = append(errs, fmt.Errorf("attributes.%s: patterns see the ID without spiffe://; remove it from the pattern", name))
			continue
		}
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
