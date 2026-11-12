package authn

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/require"
	"go.temporal.io/server/common/authorization"
	"go.temporal.io/server/common/log"
	"go.temporal.io/server/common/log/tag"

	spiffeconfig "github.com/defakto-security/temporal/config"
)

const (
	homeTD    = "admin.example.org"
	foreignTD = "partner.example.net"
	aud       = "temporal"
	keyID     = "k1"
)

// signer signs test tokens. Each trust domain has its own key in the bundle
// set, as a federated agent would hold, so a token signed by the wrong
// domain's key must fail.
type signer struct {
	key     *ecdsa.PrivateKey // the home domain's key
	foreign *ecdsa.PrivateKey // the federated domain's key
	bundles *jwtbundle.Set
}

func newSigner(t *testing.T) *signer {
	t.Helper()
	home, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	foreign, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	var bs []*jwtbundle.Bundle
	for td, key := range map[string]*ecdsa.PrivateKey{homeTD: home, foreignTD: foreign} {
		b := jwtbundle.New(spiffeid.RequireTrustDomainFromString(td))
		require.NoError(t, b.AddJWTAuthority(keyID, key.Public()))
		bs = append(bs, b)
	}
	return &signer{key: home, foreign: foreign, bundles: jwtbundle.NewSet(bs...)}
}

func (s *signer) sign(t *testing.T, key *ecdsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	sg, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", keyID),
	)
	require.NoError(t, err)
	tok, err := jwt.Signed(sg).Claims(claims).Serialize()
	require.NoError(t, err)
	return tok
}

func claimsFor(sub, audience string, exp time.Time) map[string]any {
	return map[string]any{"sub": sub, "aud": []string{audience}, "exp": exp.Unix()}
}

func newMapper(t *testing.T, s *signer, template string) *ClaimMapper {
	t.Helper()
	cfg := &spiffeconfig.Config{DevIDTemplate: template, HumanFromAnyTrustDomain: true}
	m, err := NewClaimMapper(cfg, NewVerifier(s.bundles, aud), log.NewNoopLogger())
	require.NoError(t, err)
	return m
}

func TestGetClaims(t *testing.T) {
	t.Parallel()
	s := newSigner(t)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	future, past := time.Now().Add(time.Hour), time.Now().Add(-time.Hour)

	const (
		svc    = "spiffe://" + homeTD + "/ns/payments/sa/worker"
		human  = "spiffe://" + homeTD + "/users/example.org/alice"
		fHuman = "spiffe://" + foreignTD + "/users/example.org/mallory"
		fSvc   = "spiffe://" + foreignTD + "/ns/a/sa/b"
	)
	pinned := "spiffe://" + homeTD + "/users/{domain}/{username}"
	pathOnly := "/users/{domain}/{username}"

	cases := []struct {
		name     string
		template string
		token    func() string
		want     RoleClass
		subject  string
	}{
		{"service", pinned, func() string { return s.sign(t, s.key, claimsFor(svc, aud, future)) }, RoleClassService, svc},
		{"bearer prefix", pinned, func() string { return "Bearer " + s.sign(t, s.key, claimsFor(svc, aud, future)) }, RoleClassService, svc},
		{"lowercase bearer", pinned, func() string { return "bearer " + s.sign(t, s.key, claimsFor(svc, aud, future)) }, RoleClassService, svc},
		{"human in pinned domain", pinned, func() string { return s.sign(t, s.key, claimsFor(human, aud, future)) }, RoleClassHuman, human},
		{"federated service accepted", pinned, func() string { return s.sign(t, s.foreign, claimsFor(fSvc, aud, future)) }, RoleClassService, fSvc},
		{"DevID path in foreign domain is a service when pinned", pinned, func() string { return s.sign(t, s.foreign, claimsFor(fHuman, aud, future)) }, RoleClassService, fHuman},
		{"path-only template matches any domain", pathOnly, func() string { return s.sign(t, s.foreign, claimsFor(fHuman, aud, future)) }, RoleClassHuman, fHuman},
		{"non-default template", "/people/{name}", func() string {
			return s.sign(t, s.key, claimsFor("spiffe://"+homeTD+"/people/bob", aud, future))
		}, RoleClassHuman, "spiffe://" + homeTD + "/people/bob"},
		{"no template: nobody is human", "", func() string { return s.sign(t, s.key, claimsFor(human, aud, future)) }, RoleClassService, human},
		{"human template needs the whole path", pinned, func() string {
			return s.sign(t, s.key, claimsFor("spiffe://"+homeTD+"/users/alice", aud, future))
		}, RoleClassService, "spiffe://" + homeTD + "/users/alice"},
		{"similar path is not human", pinned, func() string {
			return s.sign(t, s.key, claimsFor("spiffe://"+homeTD+"/users2/x", aud, future))
		}, RoleClassService, "spiffe://" + homeTD + "/users2/x"},

		{"foreign key cannot sign a home-domain ID", pinned, func() string { return s.sign(t, s.foreign, claimsFor(svc, aud, future)) }, RoleClassUnknown, ""},
		{"home key cannot sign a foreign-domain ID", pinned, func() string { return s.sign(t, s.key, claimsFor(fSvc, aud, future)) }, RoleClassUnknown, ""},
		{"two audiences", pinned, func() string {
			c := claimsFor(svc, aud, future)
			c["aud"] = []string{aud, "other-service"}
			return s.sign(t, s.key, c)
		}, RoleClassUnknown, ""},
		{"no exp", pinned, func() string {
			c := claimsFor(svc, aud, future)
			delete(c, "exp")
			return s.sign(t, s.key, c)
		}, RoleClassUnknown, ""},
		{"expired", pinned, func() string { return s.sign(t, s.key, claimsFor(svc, aud, past)) }, RoleClassUnknown, ""},
		{"wrong audience", pinned, func() string { return s.sign(t, s.key, claimsFor(svc, "other", future)) }, RoleClassUnknown, ""},
		{"signed by unknown key", pinned, func() string { return s.sign(t, other, claimsFor(svc, aud, future)) }, RoleClassUnknown, ""},
		{"trust domain with no bundle", pinned, func() string {
			return s.sign(t, s.key, claimsFor("spiffe://unknown.example/ns/a/sa/b", aud, future))
		}, RoleClassUnknown, ""},
		{"non-canonical subject", pinned, func() string {
			return s.sign(t, s.key, claimsFor("spiffe://"+homeTD+"/ns/a/sa/b/", aud, future))
		}, RoleClassUnknown, ""},
		{"not a SPIFFE ID", pinned, func() string { return s.sign(t, s.key, claimsFor("alice", aud, future)) }, RoleClassUnknown, ""},
		{"garbage", pinned, func() string { return "not.a.jwt" }, RoleClassUnknown, ""},
		{"empty", pinned, func() string { return "" }, RoleClassUnknown, ""},
		{"two tokens", pinned, func() string { return "a b" }, RoleClassUnknown, ""},
		{"huge", pinned, func() string { return string(make([]byte, maxTokenBytes+1)) }, RoleClassUnknown, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := newMapper(t, s, tc.template)
			got, err := m.GetClaims(&authorization.AuthInfo{AuthToken: tc.token()})
			require.NoError(t, err, "a bad token must reach the authorizer as an unknown class, not an error")
			require.Equal(t, tc.want, got.Extensions)
			require.Equal(t, tc.subject, got.Subject)
			require.Zero(t, got.System, "the mapper grants nothing")
		})
	}
}

func TestGetClaims_NoAuthInfo(t *testing.T) {
	t.Parallel()
	m := newMapper(t, newSigner(t), "")
	for _, ai := range []*authorization.AuthInfo{nil, {}} {
		got, err := m.GetClaims(ai)
		require.NoError(t, err)
		require.Equal(t, RoleClassUnknown, got.Extensions)
		require.Empty(t, got.Subject)
	}
}

func TestNewClaimMapper_BadTemplate(t *testing.T) {
	t.Parallel()
	v := NewVerifier(newSigner(t).bundles, aud)
	for _, tmpl := range []string{"users/{x}", "/", "/users{x}", "spiffe://Bad_TD!/users/{x}", "spiffe://td", "spiffe://{td}/users/{x}"} {
		_, err := NewClaimMapper(&spiffeconfig.Config{DevIDTemplate: tmpl, HumanFromAnyTrustDomain: true}, v, log.NewNoopLogger())
		require.Error(t, err, tmpl)
	}
}

func TestNewClaimMapper_NilVerifier(t *testing.T) {
	t.Parallel()
	_, err := NewClaimMapper(&spiffeconfig.Config{}, nil, log.NewNoopLogger())
	require.ErrorContains(t, err, "verifier")
}

// With a serviceIDTemplate, an authenticated ID that fits neither template gets
// no role class.
func TestGetClaims_ServiceTemplate(t *testing.T) {
	t.Parallel()
	s := newSigner(t)
	cfg := &spiffeconfig.Config{
		DevIDTemplate:     "spiffe://" + homeTD + "/users/{d}/{u}",
		ServiceIDTemplate: "/ns/{ns}/sa/{sa}",
	}
	m, err := NewClaimMapper(cfg, NewVerifier(s.bundles, aud), log.NewNoopLogger())
	require.NoError(t, err)
	exp := time.Now().Add(time.Hour)
	for sub, want := range map[string]RoleClass{
		"spiffe://" + homeTD + "/ns/a/sa/b":      RoleClassService,
		"spiffe://" + homeTD + "/user/a/b":       RoleClassUnknown, // a typo is not a service
		"spiffe://" + homeTD + "/users/ex/alice": RoleClassHuman,
	} {
		got, err := m.GetClaims(&authorization.AuthInfo{AuthToken: s.sign(t, s.key, claimsFor(sub, aud, exp))})
		require.NoError(t, err)
		require.Equal(t, want, got.Extensions, sub)
	}
}

// Tokens an attacker can build without the key never verify.
func TestGetClaims_HostileAlgorithms(t *testing.T) {
	t.Parallel()
	s := newSigner(t)
	m := newMapper(t, s, "")
	c := claimsFor("spiffe://"+homeTD+"/ns/a/sa/b", aud, time.Now().Add(time.Hour))
	b64 := base64.RawURLEncoding.EncodeToString
	payload, err := json.Marshal(c)
	require.NoError(t, err)

	hs, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte("0123456789abcdef0123456789abcdef")},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", keyID))
	require.NoError(t, err)
	hmacTok, err := jwt.Signed(hs).Claims(c).Serialize()
	require.NoError(t, err)

	noKid, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: s.key}, (&jose.SignerOptions{}).WithType("JWT"))
	require.NoError(t, err)
	noKidTok, err := jwt.Signed(noKid).Claims(c).Serialize()
	require.NoError(t, err)

	for name, tok := range map[string]string{
		"alg none":    b64([]byte(`{"alg":"none","typ":"JWT","kid":"k1"}`)) + "." + b64(payload) + ".",
		"HS256":       hmacTok,
		"missing kid": noKidTok,
	} {
		got, err := m.GetClaims(&authorization.AuthInfo{AuthToken: tok})
		require.NoError(t, err, name)
		require.Equal(t, RoleClassUnknown, got.Extensions, name)
	}
}

// captureLog records Warn calls.
type captureLog struct {
	log.Logger
	mu    sync.Mutex
	lines []string
}

func (c *captureLog) Warn(msg string, tags ...tag.Tag) {
	var b strings.Builder
	b.WriteString(msg)
	for _, t := range tags {
		fmt.Fprintf(&b, " %v", t)
	}
	c.mu.Lock()
	c.lines = append(c.lines, b.String())
	c.mu.Unlock()
}

// A rejected token is logged with a reason, never with the token, and a burst
// of bad tokens does not produce a burst of log lines.
func TestGetClaims_WarningIsSampledAndTokenFree(t *testing.T) {
	t.Parallel()
	s := newSigner(t)
	lg := &captureLog{Logger: log.NewNoopLogger()}
	m, err := NewClaimMapper(&spiffeconfig.Config{}, NewVerifier(s.bundles, aud), lg)
	require.NoError(t, err)

	token := s.sign(t, s.key, claimsFor("spiffe://"+homeTD+"/ns/a/sa/b", "other", time.Now().Add(time.Hour)))
	for range 50 {
		_, err := m.GetClaims(&authorization.AuthInfo{AuthToken: token})
		require.NoError(t, err)
	}
	lg.mu.Lock()
	defer lg.mu.Unlock()
	require.Len(t, lg.lines, 1, "the burst is sampled to one line")
	require.Contains(t, lg.lines[0], "wrong_audience")
	require.NotContains(t, lg.lines[0], token)
	require.NotContains(t, lg.lines[0], strings.Split(token, ".")[1], "no part of the token is logged")
}

// A Workload API that never answers fails startup at the timeout.
func TestWorkloadAPIVerifier_Timeout(t *testing.T) {
	t.Parallel()
	sock := filepath.Join(t.TempDir(), "agent.sock")
	start := time.Now()
	_, _, err := WorkloadAPIVerifier(context.Background(), spiffeconfig.WorkloadAPIConfig{Address: "unix://" + sock, Audience: aud}, 300*time.Millisecond)
	require.Error(t, err)
	require.Less(t, time.Since(start), 5*time.Second)
}

func TestDenyAllVerifier(t *testing.T) {
	t.Parallel()
	m, err := NewClaimMapper(&spiffeconfig.Config{}, DenyAllVerifier(), log.NewNoopLogger())
	require.NoError(t, err)
	got, err := m.GetClaims(&authorization.AuthInfo{AuthToken: "a.b.c"})
	require.NoError(t, err)
	require.Equal(t, RoleClassUnknown, got.Extensions)
}
