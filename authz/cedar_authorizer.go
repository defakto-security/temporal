package authz

import (
	"context"
	"fmt"

	cedar "github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
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
	entityNamespace types.EntityType = "Namespace"
	actionAccess    types.EntityType = "Action"
)

// CedarAuthorizer implements authorization.Authorizer by evaluating the
// customer-owned Cedar policy over (role_class, namespace, verb_class).
type CedarAuthorizer struct {
	policies *policySource
	logger   log.Logger
}

var _ authorization.Authorizer = (*CedarAuthorizer)(nil)

// NewCedarAuthorizer loads and begins watching the customer policy. It returns
// an error (refusing server start) when the policy cannot be loaded cleanly.
func NewCedarAuthorizer(cfg *spiffeconfig.Config, logger log.Logger) (*CedarAuthorizer, error) {
	ps, err := newPolicySource(cfg.PolicyPath, logger)
	if err != nil {
		return nil, err
	}
	return &CedarAuthorizer{policies: ps, logger: logger}, nil
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

	verb := VerbClassOf(target.APIName)
	if verb == VerbUnknown {
		return deny("unknown verb class: " + target.APIName), nil
	}

	req := cedar.Request{
		Principal: cedar.NewEntityUID(entityRoleClass, types.String(roleClass)),
		Action:    cedar.NewEntityUID(actionAccess, types.String(verb)),
		Resource:  cedar.NewEntityUID(entityNamespace, types.String(target.Namespace)),
	}

	// Cedar SKIPS any policy whose condition errors during evaluation. With an
	// empty entity map and no context, a customer forbid guarded by
	// `when { principal.x }` or `context.*` errors and is dropped — so a
	// broader permit could win where a deny was intended. Treat any evaluation
	// error as fail-closed: deny and log it, never silently ignore it.
	decision, diag := cedar.Authorize(ps, types.EntityMap{}, req)
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
