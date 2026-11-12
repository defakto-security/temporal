package config

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// IDMatcher decides whether a SPIFFE ID fits an ID template such as
// "spiffe://admin.example.org/users/{domain}/{username}". The whole path must
// fit: each {placeholder} stands for one non-empty path segment, and every
// other character is literal. Issuance policy, not the holder, controls the
// result. The zero value matches nothing.
type IDMatcher struct {
	// td is the required trust domain; zero means any.
	td       spiffeid.TrustDomain
	re       *regexp.Regexp
	matchAll bool
}

// Matches reports whether id fits the template.
func (m IDMatcher) Matches(id spiffeid.ID) bool {
	if m.matchAll {
		return true
	}
	if m.re == nil {
		return false
	}
	if !m.td.IsZero() && id.TrustDomain() != m.td {
		return false
	}
	return m.re.MatchString(id.Path())
}

// placeholder is one {name} in an ID template.
var placeholder = regexp.MustCompile(`\{[^{}/]*\}`)

// HumanMatcher compiles DevIDTemplate. An empty template means no identity is
// human. A path-only template matches any trust domain and is refused unless
// HumanFromAnyTrustDomain is set.
func (c *Config) HumanMatcher() (IDMatcher, error) {
	if c.DevIDTemplate == "" {
		return IDMatcher{}, nil
	}
	m, pinned, err := compileIDTemplate("devIDTemplate", c.DevIDTemplate)
	if err != nil {
		return IDMatcher{}, err
	}
	if !pinned && !c.HumanFromAnyTrustDomain {
		return IDMatcher{}, fmt.Errorf("devIDTemplate %q has no trust domain, so a federated domain could mint humans: "+
			"write it as spiffe://<trust-domain>/..., or set humanFromAnyTrustDomain: true", c.DevIDTemplate)
	}
	return m, nil
}

// ServiceMatcher compiles ServiceIDTemplate. An empty template matches every
// identity, so anything that is not human is a service.
func (c *Config) ServiceMatcher() (IDMatcher, error) {
	if c.ServiceIDTemplate == "" {
		return IDMatcher{matchAll: true}, nil
	}
	m, _, err := compileIDTemplate("serviceIDTemplate", c.ServiceIDTemplate)
	return m, err
}

// compileIDTemplate turns a template into a matcher. It reports whether the
// template pins a trust domain. The literal text before the first placeholder
// must end in "/" and be longer than "/" alone, so "/users/" does not match
// "/users2/x" and the template cannot match every ID.
func compileIDTemplate(name, tmpl string) (IDMatcher, bool, error) {
	var m IDMatcher
	path, pinned := tmpl, false
	if rest, ok := strings.CutPrefix(tmpl, SPIFFEScheme); ok {
		host, p, found := strings.Cut(rest, "/")
		if !found {
			return m, false, fmt.Errorf("%s %q: no path after the trust domain", name, tmpl)
		}
		td, err := spiffeid.TrustDomainFromString(host)
		if err != nil || strings.ContainsAny(host, "{}") {
			return m, false, fmt.Errorf("%s %q: bad trust domain %q", name, tmpl, host)
		}
		m.td, path, pinned = td, "/"+p, true
	}
	if !strings.HasPrefix(path, "/") {
		return m, false, fmt.Errorf("%s %q: must start with / or %s", name, tmpl, SPIFFEScheme)
	}
	locs := placeholder.FindAllStringIndex(path, -1)
	if len(locs) == 0 {
		return m, false, fmt.Errorf("%s %q: needs at least one {placeholder}", name, tmpl)
	}
	prefix := path[:locs[0][0]]
	switch {
	case !strings.HasSuffix(prefix, "/"):
		return m, false, fmt.Errorf("%s: the literal part before the first placeholder must end in /", name)
	case prefix == "/":
		return m, false, errors.New(name + ": the literal prefix must be longer than /, or every ID would match")
	}

	var b strings.Builder
	b.WriteString("^")
	last := 0
	for _, loc := range locs {
		if err := writeLiteral(&b, path[last:loc[0]]); err != nil {
			return m, false, fmt.Errorf("%s %q: %w", name, tmpl, err)
		}
		b.WriteString("[^/]+")
		last = loc[1]
	}
	if err := writeLiteral(&b, path[last:]); err != nil {
		return m, false, fmt.Errorf("%s %q: %w", name, tmpl, err)
	}
	b.WriteString("$")
	m.re = regexp.MustCompile(b.String())
	return m, pinned, nil
}

// writeLiteral adds literal template text to a pattern.
func writeLiteral(b *strings.Builder, s string) error {
	if strings.ContainsAny(s, "{}") {
		return errors.New("stray { or }")
	}
	b.WriteString(regexp.QuoteMeta(s))
	return nil
}
