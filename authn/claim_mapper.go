// Package authn maps a Defakto SPIFFE identity to Temporal Claims and a derived
// role_class. It performs authentication only — it assigns no verb grants. The
// SVID proves who the caller is; what they may do is decided by the authorizer.
//
// A caller presents a JWT-SVID in the `authorization` header (Bearer). It is
// verified against bundles the local SPIFFE agent streams over the Workload
// API, so the check reads an in-memory copy and makes no call per request.
// Every trust domain the agent holds a bundle for is accepted; the Cedar policy
// decides what each may do. X.509 is transport (mTLS), not authorization.
// role_class is a structural template test on the SPIFFE ID, forge-resistant
// because issuance policy — not the holder — controls the path.
package authn

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"go.temporal.io/server/common/authorization"
	"go.temporal.io/server/common/log"
	"go.temporal.io/server/common/log/tag"

	spiffeconfig "github.com/defakto-security/temporal/config"
)

// RoleClass is the single load-bearing identity distinction: service vs human.
// It is derived structurally from the SPIFFE ID, never asserted by the caller.
type RoleClass string

const (
	// RoleClassService is any workload SVID (K8s or Linux node-group path shape).
	RoleClassService RoleClass = "service"
	// RoleClassHuman is a Defakto Developer Identity (DevID) SVID or a
	// portal-issued OIDC token. Carries an on-call sub-state handled downstream.
	RoleClassHuman RoleClass = "human"
	// RoleClassUnknown is an identity that matched no known shape. The
	// authorizer must treat it as unauthorized (fail closed).
	RoleClassUnknown RoleClass = ""
)

// AuthType is the Claims.AuthType this mapper sets.
const AuthType = "spiffe"

// maxTokenBytes bounds the work spent on a hostile header. Real JWT-SVIDs are
// well under 4 KiB.
const maxTokenBytes = 8 << 10

// warnEvery is the shortest gap between "rejecting JWT-SVID" warnings. An
// unauthenticated caller can send bad tokens as fast as it likes, so the log is
// sampled; the count of skipped warnings is attached to the next one.
const warnEvery = time.Second

// maxLoggedErrorBytes bounds the verifier error text in a warning. That text
// can carry attacker-chosen strings (the unverified subject and audience).
const maxLoggedErrorBytes = 200

// Verifier checks a JWT-SVID and returns its subject. Implementations must
// verify the signature, expiry and audience. They should not call out per
// token.
type Verifier interface {
	Verify(token string) (spiffeid.ID, error)
}

// bundleVerifier verifies against any jwtbundle.Source, for one audience.
type bundleVerifier struct {
	bundles  jwtbundle.Source
	audience []string
}

// NewVerifier builds a Verifier over a JWT bundle source (in production, the
// Workload API's JWTSource) that requires the given audience.
func NewVerifier(bundles jwtbundle.Source, audience string) Verifier {
	return &bundleVerifier{bundles: bundles, audience: []string{audience}}
}

// Verify implements Verifier.
func (v *bundleVerifier) Verify(token string) (spiffeid.ID, error) {
	svid, err := jwtsvid.ParseAndValidate(token, v.bundles, v.audience)
	if err != nil {
		return spiffeid.ID{}, err
	}
	// Exactly one audience: a token minted for several services could be
	// replayed against any of them.
	if len(svid.Audience) != 1 {
		return spiffeid.ID{}, fmt.Errorf("token must carry exactly one audience, has %d", len(svid.Audience))
	}
	// Hold the subject to its canonical form, so one workload cannot be
	// presented under two spellings.
	if sub, _ := svid.Claims["sub"].(string); sub != svid.ID.String() {
		return spiffeid.ID{}, fmt.Errorf("subject %q is not a canonical SPIFFE ID", sub)
	}
	return svid.ID, nil
}

// denyAll is a Verifier that refuses every token.
type denyAll struct{}

// Verify implements Verifier.
func (denyAll) Verify(string) (spiffeid.ID, error) {
	return spiffeid.ID{}, errors.New("this process does not verify tokens")
}

// DenyAllVerifier refuses every token. Use it in a process that runs no
// service taking client calls, so it needs no SPIFFE agent.
func DenyAllVerifier() Verifier { return denyAll{} }

// WorkloadAPIVerifier opens the Workload API JWT source described by cfg and
// waits (up to timeout) for the first bundles. Close it on shutdown.
func WorkloadAPIVerifier(ctx context.Context, cfg spiffeconfig.WorkloadAPIConfig, timeout time.Duration) (Verifier, func() error, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var opts []workloadapi.JWTSourceOption
	if cfg.Address != "" {
		opts = append(opts, workloadapi.WithClientOptions(workloadapi.WithAddr(cfg.Address)))
	}
	src, err := workloadapi.NewJWTSource(ctx, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("workload API: %w", err)
	}
	return NewVerifier(src, cfg.Audience), src.Close, nil
}

// ClaimMapper implements authorization.ClaimMapper against Defakto SPIFFE.
type ClaimMapper struct {
	verify  Verifier
	human   spiffeconfig.IDMatcher
	service spiffeconfig.IDMatcher
	logger  log.Logger

	lastWarn   atomic.Int64 // unix nanos of the last warning
	suppressed atomic.Int64 // warnings skipped since then
}

var _ authorization.ClaimMapper = (*ClaimMapper)(nil)

// NewClaimMapper builds a ClaimMapper from the config contract.
func NewClaimMapper(cfg *spiffeconfig.Config, v Verifier, logger log.Logger) (*ClaimMapper, error) {
	if v == nil {
		return nil, errors.New("claim mapper: a verifier is required")
	}
	human, err := cfg.HumanMatcher()
	if err != nil {
		return nil, err
	}
	service, err := cfg.ServiceMatcher()
	if err != nil {
		return nil, err
	}
	return &ClaimMapper{verify: v, human: human, service: service, logger: logger}, nil
}

// GetClaims maps the request's auth info to Temporal Claims.
//
// It puts the derived RoleClass in Claims.Extensions and leaves the Role
// bitmask empty: grants are the authorizer's job, not the claim mapper's.
//
// A missing or bad token is NOT an error. Temporal would reject the call
// before the authorizer sees it, which would also defeat identityMode=observe.
// The mapper returns RoleClassUnknown instead, and the authorizer denies it
// (fail closed) or, in observe mode, logs it.
func (m *ClaimMapper) GetClaims(authInfo *authorization.AuthInfo) (*authorization.Claims, error) {
	unknown := &authorization.Claims{AuthType: AuthType, Extensions: RoleClassUnknown}
	if authInfo == nil {
		return unknown, nil
	}
	token, ok := bearerToken(authInfo.AuthToken)
	if !ok {
		return unknown, nil
	}
	id, err := m.verify.Verify(token)
	if err != nil {
		m.warnRejected(err)
		return unknown, nil
	}
	var class RoleClass
	switch {
	case m.human.Matches(id):
		class = RoleClassHuman
	case m.service.Matches(id):
		class = RoleClassService
	default:
		// Authenticated, but the identity fits neither template.
		m.warnRejected(errors.New("identity fits neither devIDTemplate nor serviceIDTemplate"))
		return unknown, nil
	}
	return &authorization.Claims{Subject: id.String(), AuthType: AuthType, Extensions: class}, nil
}

// bearerToken extracts the token from an `authorization` header value. The
// "Bearer " scheme is optional and case-insensitive.
func bearerToken(h string) (string, bool) {
	h = strings.TrimSpace(h)
	if len(h) >= 7 && strings.EqualFold(h[:7], "bearer ") {
		h = strings.TrimSpace(h[7:])
	}
	if h == "" || len(h) > maxTokenBytes || strings.ContainsAny(h, " \t\r\n") {
		return "", false
	}
	return h, true
}

// warnRejected logs a rejected token at most once per warnEvery. The line
// never holds the token; the error text is quoted and cut short.
func (m *ClaimMapper) warnRejected(err error) {
	now := time.Now().UnixNano()
	last := m.lastWarn.Load()
	if now-last < int64(warnEvery) || !m.lastWarn.CompareAndSwap(last, now) {
		m.suppressed.Add(1)
		return
	}
	text := err.Error()
	if len(text) > maxLoggedErrorBytes {
		text = text[:maxLoggedErrorBytes]
	}
	m.logger.Warn("rejecting JWT-SVID",
		tag.NewStringTag("reason", rejectReason(err)),
		tag.NewStringTag("error", fmt.Sprintf("%q", text)),
		tag.NewInt64("suppressed", m.suppressed.Swap(0)))
}

// rejectReason names why a token failed, from a fixed set.
func rejectReason(err error) string {
	e := err.Error()
	switch {
	case strings.Contains(e, "neither devIDTemplate"):
		return "unmatched_identity"
	case strings.Contains(e, "expired"):
		return "expired"
	case strings.Contains(e, "audience"):
		return "wrong_audience"
	case strings.Contains(e, "no bundle found"):
		return "unknown_trust_domain"
	case strings.Contains(e, "no JWT authority"), strings.Contains(e, "unable to get claims"):
		return "bad_signature"
	case strings.Contains(e, "canonical"), strings.Contains(e, "invalid subject"):
		return "bad_subject"
	case strings.Contains(e, "unable to parse"), strings.Contains(e, "header"), strings.Contains(e, "missing"):
		return "malformed"
	}
	return "invalid"
}
