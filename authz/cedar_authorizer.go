package authz

import (
	"context"
	"fmt"
	"regexp"
	"sort"

	cedar "github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"go.temporal.io/server/common/authorization"
	"go.temporal.io/server/common/log"
	"go.temporal.io/server/common/log/tag"

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
	attrs    attributeRules
	logger   log.Logger
}

var _ authorization.Authorizer = (*CedarAuthorizer)(nil)

// NewCedarAuthorizer loads and begins watching the customer policy. It returns
// an error (refusing server start) when the policy cannot be loaded cleanly.
func NewCedarAuthorizer(cfg *spiffeconfig.Config, logger log.Logger) (*CedarAuthorizer, error) {
	rules, err := cfg.AttributeRules()
	if err != nil {
		return nil, err
	}
	ps, err := newPolicySource(cfg.PolicyPath, logger)
	if err != nil {
		return nil, err
	}
	td, err := spiffeid.TrustDomainFromString(cfg.TrustDomain)
	if err != nil {
		return nil, fmt.Errorf("trustDomain %q: %w", cfg.TrustDomain, err)
	}
	return &CedarAuthorizer{policies: ps, attrs: newAttributeRules(rules, td), logger: logger}, nil
}

// Authorize decides a single call. It fails closed: a nil policy set (never
// loaded cleanly), an unknown verb class, or an unknown role class all deny.
func (a *CedarAuthorizer) Authorize(_ context.Context, caller *authorization.Claims, target *authorization.CallTarget) (authorization.Result, error) {
	ps := a.policies.policySet()
	if ps == nil {
		return deny("no policy loaded"), nil
	}

	// Temporal invokes the authorizer even for an unauthenticated call: when a
	// request carries no client certificate and no authorization header,
	// GetAuthInfo returns nil and the frontend passes caller == nil here. A
	// bare type assertion on caller.Extensions would then panic — and on a
	// STREAMING RPC (e.g. AdminService/StreamWorkflowReplicationMessages) no
	// interceptor recovers it, so an anonymous caller could crash the frontend.
	// Fail closed on nil instead.
	if caller == nil {
		return deny("unauthenticated"), nil
	}

	roleClass, ok := caller.Extensions.(authn.RoleClass)
	if !ok || roleClass == authn.RoleClassUnknown {
		return deny("unknown role class"), nil
	}

	principal, entities, ok := a.attrs.principalEntities(caller.Subject, roleClass)
	if !ok {
		return deny("malformed subject"), nil
	}

	verb := VerbClassOf(target.APIName)
	if verb == VerbUnknown {
		return deny("unknown verb class: " + target.APIName), nil
	}

	req := cedar.Request{
		Principal: principal,
		Action:    cedar.NewEntityUID(actionAccess, types.String(verb)),
		Resource:  cedar.NewEntityUID(entityNamespace, types.String(target.Namespace)),
	}

	// Cedar SKIPS any policy whose condition errors during evaluation (for
	// example `when { principal.x }` on a missing attribute), so a broader
	// permit could win where a deny was intended. Treat any evaluation error
	// as fail-closed: deny and log it, never silently ignore it.
	decision, diag := cedar.Authorize(ps, entities, req)
	if len(diag.Errors) > 0 {
		a.logger.Error("cedar policy evaluation error; denying",
			tag.NewStringTag("apiName", target.APIName),
			tag.NewStringTag("diagnostics", fmt.Sprintf("%v", diag.Errors)))
		return deny("policy evaluation error"), nil
	}
	if decision == cedar.Allow {
		return authorization.Result{Decision: authorization.DecisionAllow}, nil
	}
	return deny("denied by policy"), nil
}

func deny(reason string) authorization.Result {
	return authorization.Result{Decision: authorization.DecisionDeny, Reason: reason}
}

// attributeRules is the compiled attribute mapping, in a fixed order so the
// entity record is built the same way every time.
type attributeRules struct {
	td    spiffeid.TrustDomain
	names []string
	res   []*regexp.Regexp
}

func newAttributeRules(m map[string]*regexp.Regexp, td spiffeid.TrustDomain) attributeRules {
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	r := attributeRules{td: td, names: names, res: make([]*regexp.Regexp, len(names))}
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
// The subject must already be a canonical SPIFFE ID in the configured trust
// domain. Anything else (a port, uppercase, a trailing slash, escapes, empty or
// dot segments, another trust domain) is rejected, so one workload can never
// appear under two Workload entities.
func (r attributeRules) principalEntities(subject string, class authn.RoleClass) (types.EntityUID, types.EntityMap, bool) {
	id, err := spiffeid.FromString(subject)
	if err != nil || id.String() != subject || id.TrustDomain() != r.td {
		return types.EntityUID{}, nil, false
	}

	attrs := make(types.RecordMap, len(r.names))
	for i, name := range r.names {
		var val string
		if m := r.res[i].FindStringSubmatch(subject); m != nil {
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
