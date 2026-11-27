package authz

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"go.temporal.io/server/common/authorization"
	"go.temporal.io/server/common/log"

	"github.com/defakto-security/temporal/authn"
	spiffeconfig "github.com/defakto-security/temporal/config"
)

func groupsAuthorizer(t *testing.T, policy string, groups map[string][]string) (*CedarAuthorizer, error) {
	t.Helper()
	cfg := &spiffeconfig.Config{
		Version:      spiffeconfig.SchemaVersion,
		PolicyPath:   writePolicy(t, policy),
		ActionGroups: groups,
	}
	a, err := NewCedarAuthorizer(cfg, log.NewNoopLogger())
	if err == nil {
		t.Cleanup(func() { _ = a.Close() })
	}
	return a, err
}

func allowed(t *testing.T, a *CedarAuthorizer, subject, api, ns string) bool {
	t.Helper()
	res, err := a.Authorize(context.Background(), claimsFor(subject, authn.RoleClassService),
		&authorization.CallTarget{APIName: api, Namespace: ns})
	require.NoError(t, err)
	return res.Decision == authorization.DecisionAllow
}

const scope = ` when { principal.trust_domain == "corp.defakto.security" }`

// An RPC the image has no group for is denied until a permit names it. No image
// change is needed.
func TestUnknownRPCPermittedByName(t *testing.T) {
	t.Parallel()
	api := svc + "SomeBrandNewRPC"
	a, err := groupsAuthorizer(t, `permit (principal in RoleClass::"service", action in Action::"read-all", resource)`+scope+`;`, nil)
	require.NoError(t, err)
	require.False(t, allowed(t, a, svcID, api, "p"), "no permit names it")

	a, err = groupsAuthorizer(t, `permit (principal in RoleClass::"service", action == Action::"WorkflowService/SomeBrandNewRPC", resource)`+scope+`;`, nil)
	require.NoError(t, err)
	require.True(t, allowed(t, a, svcID, api, "p"))
	require.False(t, allowed(t, a, svcID, svc+"OtherNewRPC", "p"))
}

// An aggregate permit never reaches an RPC with no shipped group.
func TestAggregateDoesNotCoverUngroupedRPC(t *testing.T) {
	t.Parallel()
	a, err := groupsAuthorizer(t, `permit (principal in RoleClass::"service", action in [Action::"workflow-client", Action::"worker-ops"], resource)`+scope+`;`, nil)
	require.NoError(t, err)
	require.True(t, allowed(t, a, svcID, svc+"ListWorkflowExecutions", "p"))
	require.True(t, allowed(t, a, svcID, svc+"GetClusterInfo", "p"))
	require.False(t, allowed(t, a, svcID, svc+"SomeBrandNewRPC", "p"))
	require.False(t, allowed(t, a, svcID, svc+"TerminateWorkflowExecution", "p"), "admin is not in workflow-client")
}

// The use case that drove the design: query everywhere, signal in one namespace.
func TestQueryEverywhereSignalOnlyInOne(t *testing.T) {
	t.Parallel()
	policy := `permit (principal in RoleClass::"service", action in Action::"workflow-query", resource)` + scope + `;
permit (principal == Workload::"` + svcID + `", action in Action::"workflow-signal", resource == Namespace::"B");`
	a, err := groupsAuthorizer(t, policy, nil)
	require.NoError(t, err)
	for _, ns := range []string{"A", "B", "C"} {
		require.True(t, allowed(t, a, otherID, svc+"QueryWorkflow", ns))
	}
	require.True(t, allowed(t, a, svcID, svc+"SignalWorkflowExecution", "B"))
	require.False(t, allowed(t, a, svcID, svc+"SignalWorkflowExecution", "A"))
	require.False(t, allowed(t, a, otherID, svc+"SignalWorkflowExecution", "B"))
}

func TestAggregateWorkflowInteract(t *testing.T) {
	t.Parallel()
	a, err := groupsAuthorizer(t, `permit (principal in RoleClass::"service", action in Action::"workflow-interact", resource)`+scope+`;`, nil)
	require.NoError(t, err)
	require.True(t, allowed(t, a, svcID, svc+"QueryWorkflow", "p"))
	require.True(t, allowed(t, a, svcID, svc+"SignalWorkflowExecution", "p"))
	require.True(t, allowed(t, a, svcID, svc+"UpdateWorkflowExecution", "p"))
	require.False(t, allowed(t, a, svcID, svc+"StartWorkflowExecution", "p"))
}

// A forbid on a shipped group covers every RPC in it.
func TestForbidOnDeleteAll(t *testing.T) {
	t.Parallel()
	policy := `permit (principal in RoleClass::"service", action in [Action::"workflow-start", Action::"delete-all"], resource)` + scope + `;
forbid (principal, action in Action::"delete-all", resource);`
	a, err := groupsAuthorizer(t, policy, nil)
	require.NoError(t, err)
	require.True(t, allowed(t, a, svcID, svc+"StartWorkflowExecution", "p"))
	for _, api := range []string{
		svc + "DeleteWorkflowExecution", svc + "DeleteSchedule", svc + "DeleteActivityExecution",
		adminSvc + "DeleteWorkflowExecution",
	} {
		require.False(t, allowed(t, a, svcID, api, "p"), api)
	}
}

func TestCustomGroup(t *testing.T) {
	t.Parallel()
	groups := map[string][]string{
		"payments-ops": {"workflow-read", "WorkflowService/QueryWorkflow", "WorkflowService/SomeBrandNewRPC"},
		"wider":        {"payments-ops", "workflow-signal"},
	}
	a, err := groupsAuthorizer(t, `permit (principal in RoleClass::"service", action in Action::"wider", resource)`+scope+`;`, groups)
	require.NoError(t, err)
	for _, api := range []string{
		"ListWorkflowExecutions", "QueryWorkflow", "SomeBrandNewRPC", "SignalWorkflowExecution",
	} {
		require.True(t, allowed(t, a, svcID, svc+api, "p"), api)
	}
	require.False(t, allowed(t, a, svcID, svc+"StartWorkflowExecution", "p"))
	require.False(t, allowed(t, a, svcID, svc+"OtherNewRPC", "p"))
}

// A customer group never changes what a shipped group holds, so a forbid on the
// shipped group still covers an RPC a customer group also holds.
func TestCustomGroupCannotEscapeShippedForbid(t *testing.T) {
	t.Parallel()
	groups := map[string][]string{"mine": {"WorkflowService/DeleteWorkflowExecution", "delete-all"}}
	policy := `permit (principal in RoleClass::"service", action in Action::"mine", resource)` + scope + `;
forbid (principal, action in Action::"delete-all", resource);`
	a, err := groupsAuthorizer(t, policy, groups)
	require.NoError(t, err)
	require.False(t, allowed(t, a, svcID, svc+"DeleteWorkflowExecution", "p"))
	require.False(t, allowed(t, a, svcID, svc+"DeleteSchedule", "p"))
}

func TestCustomGroupValidation(t *testing.T) {
	t.Parallel()
	for name, g := range map[string]map[string][]string{
		"shipped name":  {"worker-ops": {"workflow-read"}},
		"unknown group": {"mine": {"no-such-group"}},
		"self cycle":    {"mine": {"mine"}},
		"two cycle":     {"a": {"b"}, "b": {"a"}},
	} {
		_, err := groupsAuthorizer(t, loadReferencePolicy(t), g)
		require.Error(t, err, name)
	}
	// Shape errors are caught by config validation.
	for name, g := range map[string]map[string][]string{
		"upper name":   {"Mine": {"workflow-read"}},
		"slash name":   {"a/b": {"workflow-read"}},
		"bad member":   {"mine": {"workflow read"}},
		"bare service": {"mine": {"WorkflowService/"}},
	} {
		c := &spiffeconfig.Config{Version: spiffeconfig.SchemaVersion, PolicyPath: "p", ActionGroups: g}
		c.WorkloadAPI.Audience = "a"
		require.Error(t, c.Validate(), name)
	}
}

// Observe mode never forgives an RPC the image has no group for.
func TestObserveNeverForgivesUngroupedRPC(t *testing.T) {
	t.Parallel()
	policy := `permit (principal in RoleClass::"service", action == Action::"WorkflowService/SomeBrandNewRPC", resource)` + scope + `;`
	a, _, _ := newAuthorizerWith(t, policy, "", spiffeconfig.DecisionLogOff, spiffeconfig.IdentityModeObserve)
	res, err := a.Authorize(context.Background(), nil, &authorization.CallTarget{APIName: svc + "SomeBrandNewRPC", Namespace: "p"})
	require.NoError(t, err)
	require.Equal(t, authorization.DecisionDeny, res.Decision)
}

// A misspelled group in a policy would match nothing. A forbid would silently
// stop forbidding, so the policy is refused at load.
func TestPolicyWithUnknownActionGroupRefused(t *testing.T) {
	t.Parallel()
	for name, pol := range map[string]string{
		"forbid typo":     `forbid (principal, action in Action::"delte-all", resource);`,
		"permit typo":     `permit (principal in RoleClass::"service", action == Action::"wrkflow-read", resource)` + scope + `;`,
		"set member typo": `permit (principal in RoleClass::"service", action in [Action::"read-all", Action::"nope"], resource)` + scope + `;`,
	} {
		_, err := groupsAuthorizer(t, pol, nil)
		require.ErrorContains(t, err, "unknown action group", name)
	}
	// An unknown group inside a condition is refused too.
	for name, pol := range map[string]string{
		"unless": `forbid (principal, action, resource) unless { action in Action::"delte-all" };`,
		"when":   `forbid (principal, action, resource) when { action in Action::"delte-all" && principal.ns == "x" };`,
		"set":    `forbid (principal, action, resource) when { action in [Action::"read-all", Action::"nope"] };`,
		"equals": `forbid (principal, action, resource) when { action == Action::"nope" };`,
	} {
		_, err := groupsAuthorizer(t, pol, nil)
		require.ErrorContains(t, err, "unknown action group", name)
	}
	_, err := groupsAuthorizer(t, `forbid (principal, action, resource) when { action in Action::"delete-all" || action == Action::"WorkflowService/NewRPC" };`, nil)
	require.NoError(t, err)

	// A customer group, a shipped group and a single RPC all load.
	pol := `permit (principal in RoleClass::"service", action in Action::"mine", resource)` + scope + `;
permit (principal in RoleClass::"service", action == Action::"WorkflowService/NewRPC", resource)` + scope + `;
forbid (principal, action in Action::"delete-all", resource);`
	_, err = groupsAuthorizer(t, pol, map[string][]string{"mine": {"workflow-read"}})
	require.NoError(t, err)
}

// cluster-admin is a shipped group, so a customer cannot redefine it.
func TestCustomGroupCannotRedefineClusterAdmin(t *testing.T) {
	t.Parallel()
	_, err := groupsAuthorizer(t, loadReferencePolicy(t), map[string][]string{"cluster-admin": {"workflow-read"}})
	require.Error(t, err)
}

// A permit on shipped groups never allows an RPC with no group. Only a permit
// that names it, or a customer group that holds it, does. A forbid still wins.
func TestShippedGroupPermitDoesNotReachUngroupedRPC(t *testing.T) {
	t.Parallel()
	api := svc + "SomeBrandNewRPC"
	wild := `permit (principal in RoleClass::"service", action in [Action::"workflow-client", Action::"cluster-admin"], resource)` + scope + `;`
	a, err := groupsAuthorizer(t, wild, nil)
	require.NoError(t, err)
	require.True(t, allowed(t, a, svcID, svc+"ListWorkflowExecutions", "p"), "grouped RPC still allowed")
	require.False(t, allowed(t, a, svcID, api, "p"), "ungrouped RPC is not")

	named := wild + `
permit (principal in RoleClass::"service", action == Action::"WorkflowService/SomeBrandNewRPC", resource)` + scope + `;`
	a, err = groupsAuthorizer(t, named, nil)
	require.NoError(t, err)
	require.True(t, allowed(t, a, svcID, api, "p"), "named RPC")

	custom := wild + `
permit (principal in RoleClass::"service", action in Action::"mine", resource)` + scope + `;`
	a, err = groupsAuthorizer(t, custom, map[string][]string{"mine": {"WorkflowService/SomeBrandNewRPC"}})
	require.NoError(t, err)
	require.True(t, allowed(t, a, svcID, api, "p"), "customer group")

	forbidden := named + `
forbid (principal, action == Action::"WorkflowService/SomeBrandNewRPC", resource);`
	a, err = groupsAuthorizer(t, forbidden, nil)
	require.NoError(t, err)
	require.False(t, allowed(t, a, svcID, api, "p"), "forbid wins")

	listed := `permit (principal in RoleClass::"service", action in [Action::"read-all", Action::"worker-ops"], resource)` + scope + `;`
	a, err = groupsAuthorizer(t, listed, nil)
	require.NoError(t, err)
	require.False(t, allowed(t, a, svcID, api, "p"), "shipped groups never hold it")
}

// cluster-admin is a shipped leaf group: a policy may name it, and a customer
// may not redefine it.
func TestClusterAdminIsShippedGroup(t *testing.T) {
	t.Parallel()
	require.True(t, isShippedGroup(GroupClusterAdmin))
	require.Contains(t, shippedGroupNames(), GroupClusterAdmin)
	_, err := groupsAuthorizer(t, `permit (principal in RoleClass::"service", action in Action::"cluster-admin", resource)`+scope+`;`, nil)
	require.NoError(t, err)
	_, err = groupsAuthorizer(t, loadReferencePolicy(t), map[string][]string{"cluster-admin": {"workflow-read"}})
	require.ErrorContains(t, err, "shipped group")
	_, err = groupsAuthorizer(t, loadReferencePolicy(t), map[string][]string{"mine": {"cluster-admin"}})
	require.NoError(t, err)
}
