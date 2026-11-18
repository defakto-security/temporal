package authz

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"

	cedar "github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"go.temporal.io/server/common/authorization"
	"go.temporal.io/server/common/log"
	"go.temporal.io/server/common/log/tag"
	"go.temporal.io/server/common/metrics"
	"go.temporal.io/server/common/primitives"

	"github.com/defakto-security/temporal/authn"
	spiffeconfig "github.com/defakto-security/temporal/config"
)

// Cedar entity/action types. These mirror schema/temporal.cedarschema and are
// the shape the reference policy.cedar is written against.
const (
	entityRoleClass types.EntityType = "RoleClass"
	entityWorkload  types.EntityType = "Workload"
	entityNamespace types.EntityType = "Namespace"
	actionAccess    types.EntityType = "Action"
)

// CedarAuthorizer implements authorization.Authorizer by evaluating the
// customer-owned Cedar policy over (role_class, namespace, verb_class).
type CedarAuthorizer struct {
	policies *policySource
	// shadow is the optional candidate policy. It never changes a decision.
	shadow      *policySource
	attrs       attributeRules
	logger      log.Logger
	metrics     metrics.Handler
	decisionLog string
	// observeIdentity allows a call that fails the pre-policy identity checks
	// and reports it as would_deny instead.
	observeIdentity bool

	// namespaces bounds the metric namespace tag; see namespaceTag.
	nsMu       sync.Mutex
	namespaces map[string]struct{}
}

// maxMetricNamespaces caps distinct namespace tag values.
const maxMetricNamespaces = 256

// otherNamespace labels every namespace outside the tracked set.
const otherNamespace = "_other"

var _ authorization.Authorizer = (*CedarAuthorizer)(nil)

// Decision labels used in logs and metrics.
const (
	decisionAllow     = "allow"
	decisionDeny      = "deny"
	decisionWouldDeny = "would_deny"
	// shadowDelta is the shadow_decision metric value when the candidate policy
	// disagrees with the live one.
	shadowDelta = "delta"
	// would_allow: the live policy denied, the candidate would allow.
	decisionWouldAllow = "would_allow"

	metricDecisions = "defakto_authz_decisions"
)

// Reason codes. A fixed set, so they are safe as a metric tag. Result.Reason
// keeps the longer human text.
const (
	reasonAllowed          = "allowed"
	reasonDeniedByPolicy   = "denied_by_policy"
	reasonPolicyError      = "policy_error"
	reasonNoPolicy         = "no_policy"
	reasonUnauthenticated  = "unauthenticated"
	reasonUnknownRoleClass = "unknown_role_class"
	reasonMalformedSubject = "malformed_subject"
	reasonUnknownVerb      = "unknown_verb"
)

// NewCedarAuthorizer loads and begins watching the customer policy (and the
// shadow candidate, when configured). It returns an error (refusing server
// start) when either cannot be loaded cleanly.
func NewCedarAuthorizer(cfg *spiffeconfig.Config, logger log.Logger) (*CedarAuthorizer, error) {
	rules, err := cfg.AttributeRules()
	if err != nil {
		return nil, err
	}
	ps, err := newPolicySource(cfg.PolicyPath, logger)
	if err != nil {
		return nil, err
	}
	a := &CedarAuthorizer{
		policies:    ps,
		attrs:       newAttributeRules(rules),
		logger:      logger,
		metrics:     metrics.NoopMetricsHandler,
		decisionLog: cfg.DecisionLog,

		observeIdentity: cfg.IdentityMode == spiffeconfig.IdentityModeObserve,
		namespaces:      make(map[string]struct{}),
	}
	if a.observeIdentity {
		logger.Warn("identityMode=observe: calls without a valid identity are ALLOWED and only reported; " +
			"forbidden-all, break-glass and unclassified APIs stay denied")
	}
	if cfg.ShadowPolicyPath != "" {
		sh, err := newPolicySource(cfg.ShadowPolicyPath, logger)
		if err != nil {
			_ = ps.Close()
			return nil, fmt.Errorf("shadow policy: %w", err)
		}
		a.shadow = sh
	}
	return a, nil
}

// WithMetrics sets the handler that receives decision counters. The default is
// a no-op.
func (a *CedarAuthorizer) WithMetrics(h metrics.Handler) *CedarAuthorizer {
	// The authorizer only runs in the frontend. Temporal tags each service's own
	// handler with service_name; this one is the untagged root, so tag it here to
	// line up with Temporal's own authorization metrics.
	a.metrics = h.WithTags(metrics.ServiceNameTag(primitives.FrontendService))
	return a
}

// Close stops the policy watchers.
func (a *CedarAuthorizer) Close() error {
	err := a.policies.Close()
	if a.shadow != nil {
		if e := a.shadow.Close(); err == nil {
			err = e
		}
	}
	return err
}

// Authorize decides a single call. It fails closed: a nil policy set (never
// loaded cleanly), an unknown verb class, or an unknown role class all deny.
// The shadow policy, if any, is evaluated only after the live decision is made
// and cannot change it.
func (a *CedarAuthorizer) Authorize(_ context.Context, caller *authorization.Claims, target *authorization.CallTarget) (authorization.Result, error) {
	if target == nil {
		return deny("no call target"), nil
	}
	d := decisionRecord{apiName: target.APIName, namespace: target.Namespace}
	if caller != nil {
		d.subject = caller.Subject
	}
	res := a.decide(caller, target, &d)
	d.decision = decisionAllow
	d.reason = res.Reason
	if res.Decision != authorization.DecisionAllow {
		d.decision = decisionDeny
	}

	// Identity observe mode: a call that failed a pre-policy identity check is
	// let through and reported, so callers without a valid identity can be
	// found before enforcement is turned on.
	// Even then, the verbs the reference policy forbids for everyone
	// (forbidden-all, break-glass) stay denied, so a caller never gains those
	// by dropping its credential.
	if a.observeIdentity && d.identityFailure && !alwaysDenied(VerbClassOf(target.APIName)) {
		d.forgiven = true
		d.decision = decisionAllow
		res = authorization.Result{Decision: authorization.DecisionAllow}
	}

	a.runShadow(&d, res.Decision == authorization.DecisionAllow)
	a.record(&d)
	return res, nil
}

// alwaysDenied reports verb classes that observe mode never forgives.
func alwaysDenied(v VerbClass) bool {
	return v == VerbForbiddenAll || v == VerbBreakGlass || v == VerbUnknown
}

// deny builds a denial Result carrying reason.
func deny(reason string) authorization.Result {
	return authorization.Result{Decision: authorization.DecisionDeny, Reason: reason}
}

// decide runs the live policy.
func (a *CedarAuthorizer) decide(caller *authorization.Claims, target *authorization.CallTarget, d *decisionRecord) authorization.Result {
	ps := a.policies.policySet()
	if ps == nil {
		return d.fail(reasonNoPolicy, "no policy loaded", false)
	}

	// Temporal invokes the authorizer even for an unauthenticated call: when a
	// request carries no client certificate and no authorization header,
	// GetAuthInfo returns nil and the frontend passes caller == nil here. A
	// bare type assertion on caller.Extensions would then panic — and on a
	// STREAMING RPC (e.g. AdminService/StreamWorkflowReplicationMessages) no
	// interceptor recovers it, so an anonymous caller could crash the frontend.
	// Fail closed on nil instead.
	if caller == nil {
		return d.fail(reasonUnauthenticated, "unauthenticated", true)
	}

	roleClass, ok := caller.Extensions.(authn.RoleClass)
	if !ok || roleClass == authn.RoleClassUnknown {
		return d.fail(reasonUnknownRoleClass, "unknown role class", true)
	}
	d.roleClass = string(roleClass)

	principal, entities, ok := a.attrs.principalEntities(caller.Subject, roleClass)
	if !ok {
		return d.fail(reasonMalformedSubject, "malformed subject", true)
	}
	d.attributes = attributesOf(entities, principal)

	verb := VerbClassOf(target.APIName)
	if verb == VerbUnknown {
		return d.fail(reasonUnknownVerb, "unknown verb class: "+target.APIName, false)
	}
	d.verb = string(verb)

	req := cedar.Request{
		Principal: principal,
		Action:    cedar.NewEntityUID(actionAccess, types.String(verb)),
		Resource:  cedar.NewEntityUID(entityNamespace, types.String(target.Namespace)),
	}
	d.req, d.entities = &req, entities

	allowed, evalErr := a.evaluate(ps, entities, req)
	switch {
	case evalErr != "":
		a.logger.Error("cedar policy evaluation error; denying",
			tag.NewStringTag("apiName", target.APIName),
			tag.NewStringTag("diagnostics", evalErr))
		return d.fail(reasonPolicyError, "policy evaluation error", false)
	case allowed:
		return authorization.Result{Decision: authorization.DecisionAllow}
	}
	return d.fail(reasonDeniedByPolicy, "denied by policy", false)
}

// evaluate runs one policy set. Cedar SKIPS any policy whose condition errors
// during evaluation (for example `when { principal.x }` on a missing
// attribute), so a broader permit could win where a deny was intended. Any
// evaluation error is therefore reported to the caller, which fails closed;
// it is never silently ignored.
func (a *CedarAuthorizer) evaluate(ps *cedar.PolicySet, entities types.EntityMap, req cedar.Request) (allowed bool, evalErr string) {
	decision, diag := cedar.Authorize(ps, entities, req)
	if len(diag.Errors) > 0 {
		return false, fmt.Sprintf("%v", diag.Errors)
	}
	return decision == cedar.Allow, ""
}

// runShadow evaluates the candidate policy for every call that reached policy
// evaluation, whatever the live decision, and flags a disagreement in either
// direction: would_deny (live allowed, candidate denies) or would_allow (live
// denied, candidate allows). A candidate error is logged and otherwise ignored.
// Nothing here affects the live decision.
func (a *CedarAuthorizer) runShadow(d *decisionRecord, liveAllowed bool) {
	if a.shadow == nil || d.req == nil {
		return
	}
	ps := a.shadow.policySet()
	if ps == nil {
		a.logger.Error("shadow policy not loaded; skipping", tag.NewStringTag("apiName", d.apiName))
		return
	}
	allowed, evalErr := a.evaluate(ps, d.entities, *d.req)
	switch {
	case evalErr != "":
		a.logger.Error("shadow policy evaluation error; ignoring",
			tag.NewStringTag("apiName", d.apiName),
			tag.NewStringTag("diagnostics", evalErr))
	case liveAllowed && !allowed:
		d.shadowDelta = decisionWouldDeny
	case !liveAllowed && allowed:
		d.shadowDelta = decisionWouldAllow
	}
}

// record logs and counts one decision.
func (a *CedarAuthorizer) record(d *decisionRecord) {
	a.count(d)
	// Always logged: a disagreement is the signal shadow and observe mode exist
	// to give. The metric carries the same fact as shadow_decision="delta" or a
	// decision="allow" with an identity reason.
	switch {
	case d.shadowDelta != "":
		a.logger.Warn("authz divergence", d.tags(d.shadowDelta)...)
	case d.forgiven:
		a.logger.Warn("authz divergence", d.tags(decisionWouldDeny)...)
	}
	switch a.decisionLog {
	case spiffeconfig.DecisionLogAll:
		a.logger.Info("authz decision", d.tags("")...)
	case spiffeconfig.DecisionLogDeny:
		if d.decision == decisionDeny {
			a.logger.Info("authz decision", d.tags("")...)
		}
	}
}

// count increments the decision counter once per call. decision is the live
// outcome. shadow_decision equals it unless the candidate policy disagrees, in
// which case it is "delta"; the direction follows from decision (live allow plus
// delta is would_deny). A call forgiven by identityMode=observe is
// decision="allow" with the identity failure as reason. Tags are bounded:
// decision, shadow_decision, verb class and reason are closed sets, and
// namespace is capped (see namespaceTag).
func (a *CedarAuthorizer) count(d *decisionRecord) {
	verb := d.verb
	if verb == "" {
		verb = "none"
	}
	shadow := d.decision
	if d.shadowDelta != "" {
		shadow = shadowDelta
	}
	a.metrics.Counter(metricDecisions).Record(1,
		metrics.StringTag("decision", d.decision),
		metrics.StringTag("shadow_decision", shadow),
		metrics.StringTag("verb", verb),
		metrics.StringTag("reason", d.reasonCode()),
		metrics.NamespaceTag(a.namespaceTag(d)))
}

// namespaceTag returns the namespace to use as a metric tag. The namespace comes
// from the request, so an unauthenticated or denied caller could otherwise mint
// unlimited series. A namespace is tracked only after an authenticated call that
// the live policy allowed, and at most maxMetricNamespaces are tracked; every
// other value is reported as "_other".
func (a *CedarAuthorizer) namespaceTag(d *decisionRecord) string {
	a.nsMu.Lock()
	defer a.nsMu.Unlock()
	if _, ok := a.namespaces[d.namespace]; ok {
		return d.namespace
	}
	if d.decision == decisionAllow && !d.identityFailure && len(a.namespaces) < maxMetricNamespaces {
		a.namespaces[d.namespace] = struct{}{}
		return d.namespace
	}
	return otherNamespace
}

// decisionRecord is everything one decision log line or counter needs.
type decisionRecord struct {
	subject, roleClass, namespace, apiName, verb string
	attributes                                   map[string]string
	decision, reason                             string
	// code is the fixed reason code; identityFailure marks a pre-policy
	// identity check that failed.
	code            string
	identityFailure bool
	// shadowDelta is would_deny or would_allow when the candidate disagreed.
	shadowDelta string
	// forgiven marks a pre-policy identity failure that observe mode allowed.
	forgiven bool

	// req and entities are kept so the shadow policy sees the same input.
	req      *cedar.Request
	entities types.EntityMap
}

// fail records a denial and returns it.
func (d *decisionRecord) fail(code, reason string, identity bool) authorization.Result {
	d.code, d.identityFailure = code, identity
	return authorization.Result{Decision: authorization.DecisionDeny, Reason: reason}
}

// tags builds the log fields. divergence is would_deny or would_allow on a
// divergence line and "" otherwise.
func (d *decisionRecord) tags(divergence string) []tag.Tag {
	shadow := d.decision
	if d.shadowDelta != "" {
		shadow = shadowDelta
	}
	return []tag.Tag{
		tag.NewStringTag("decision", d.decision),
		tag.NewStringTag("shadowDecision", shadow),
		tag.NewStringTag("divergence", divergence),
		tag.NewStringTag("principal", d.subject),
		tag.NewStringTag("roleClass", d.roleClass),
		tag.NewAnyTag("attributes", d.attributes),
		tag.NewStringTag("namespace", d.namespace),
		tag.NewStringTag("apiName", d.apiName),
		tag.NewStringTag("verb", d.verb),
		tag.NewStringTag("reason", d.reason),
		tag.NewStringTag("reasonCode", d.reasonCode()),
	}
}

// reasonCode is the bounded reason label: "allowed" unless a check failed.
func (d *decisionRecord) reasonCode() string {
	if d.code == "" {
		return reasonAllowed
	}
	return d.code
}

// attributesOf reads the derived attribute values back off the principal.
func attributesOf(entities types.EntityMap, uid types.EntityUID) map[string]string {
	e, ok := entities[uid]
	if !ok {
		return nil
	}
	out := make(map[string]string, e.Attributes.Len())
	for k, v := range e.Attributes.All() {
		if s, ok := v.(types.String); ok {
			out[string(k)] = string(s)
		}
	}
	return out
}

// attributeRules is the compiled attribute mapping, in a fixed order so the
// entity record is built the same way every time.
type attributeRules struct {
	names []string
	res   []*regexp.Regexp
}

// newAttributeRules orders the compiled patterns by attribute name.
func newAttributeRules(m map[string]*regexp.Regexp) attributeRules {
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	r := attributeRules{names: names, res: make([]*regexp.Regexp, len(names))}
	for i, n := range names {
		r.res[i] = m[n]
	}
	return r
}

// principalEntities builds the Cedar principal and the entity map for a caller.
//
// The principal is the caller's SPIFFE ID as a Workload entity, so a policy can
// match one exact identity. The role class is its parent, so role-class
// policies are written `principal in RoleClass::"service"`. Attributes come
// from the configured rules (config.DefaultAttributes plus the customer's
// `attributes`). Every rule always yields a value, "" when its pattern does not
// match, so a policy that reads an attribute never errors on a missing one.
// Write deny rules as allow-lists: `forbid ... when { principal.ns == "prod" }`
// does not fire for an ID whose ns is "".
//
// The subject must already be a canonical SPIFFE ID. Anything else (a port,
// uppercase, a trailing slash, escapes, empty or dot segments) is rejected, so
// one workload can never appear under two Workload entities. Which trust
// domains may do what is the policy's job (`principal.trust_domain`, which is the
// ID's own trust domain and cannot be overridden). Patterns
// run against the ID without "spiffe://".
func (r attributeRules) principalEntities(subject string, class authn.RoleClass) (types.EntityUID, types.EntityMap, bool) {
	id, err := spiffeid.FromString(subject)
	if err != nil || id.String() != subject {
		return types.EntityUID{}, nil, false
	}

	// trust_domain comes from the parsed ID, not a pattern: policies rely on
	// it as the boundary between trust domains.
	attrs := make(types.RecordMap, len(r.names)+1)
	attrs[types.String(spiffeconfig.TrustDomainAttribute)] = types.String(id.TrustDomain().Name())
	for i, name := range r.names {
		var val string
		if m := r.res[i].FindStringSubmatch(strings.TrimPrefix(subject, spiffeconfig.SPIFFEScheme)); m != nil {
			val = m[1]
		}
		attrs[types.String(name)] = types.String(val)
	}

	roleUID := cedar.NewEntityUID(entityRoleClass, types.String(class))
	workloadUID := cedar.NewEntityUID(entityWorkload, types.String(subject))
	return workloadUID, types.EntityMap{
		roleUID: types.Entity{UID: roleUID},
		workloadUID: types.Entity{
			UID:        workloadUID,
			Parents:    types.NewEntityUIDSet(roleUID),
			Attributes: types.NewRecord(attrs),
		},
	}, true
}
