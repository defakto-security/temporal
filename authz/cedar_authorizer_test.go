package authz

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	cedar "github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/require"
	"go.temporal.io/server/common/authorization"
	"go.temporal.io/server/common/log"

	"github.com/defakto-security/temporal/authn"
	spiffeconfig "github.com/defakto-security/temporal/config"
)

// referencePolicyPath is the shipped reference/policy.cedar — the exact policy a
// customer copies. go test runs with CWD set to the package directory, so this
// relative path resolves. Loading it (rather than an inline copy) means a drift
// in the shipped default is caught by this test.
const referencePolicyPath = "../reference/policy.cedar"

// loadReferencePolicy is a test helper or test case in this package.
func loadReferencePolicy(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(referencePolicyPath)
	require.NoError(t, err)
	return string(raw)
}

// newTestAuthorizer is a test helper or test case in this package.
func newTestAuthorizer(t *testing.T, policy string) *CedarAuthorizer {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.cedar")
	require.NoError(t, os.WriteFile(path, []byte(policy), 0o600))

	cfg := &spiffeconfig.Config{
		Version:     spiffeconfig.SchemaVersion,
		TrustDomain: "corp.defakto.security",
		PolicyPath:  path,
	}
	a, err := NewCedarAuthorizer(cfg, log.NewNoopLogger())
	require.NoError(t, err)
	t.Cleanup(func() { _ = a.policies.Close() })
	return a
}

const (
	svcID   = "spiffe://corp.defakto.security/ns/payments/sa/worker"
	otherID = "spiffe://corp.defakto.security/ns/billing/sa/worker"
	humanID = "spiffe://corp.defakto.security/devid/alice"
)

// claims is a test helper or test case in this package.
func claims(class authn.RoleClass) *authorization.Claims {
	subject := svcID
	if class == authn.RoleClassHuman {
		subject = humanID
	}
	return claimsFor(subject, class)
}

// claimsFor is a test helper or test case in this package.
func claimsFor(subject string, class authn.RoleClass) *authorization.Claims {
	return &authorization.Claims{Subject: subject, AuthType: "spiffe", Extensions: class}
}

// target is a test helper or test case in this package.
func target(api string) *authorization.CallTarget {
	return &authorization.CallTarget{APIName: api, Namespace: "dev_portal"}
}

const svc = "/temporal.api.workflowservice.v1.WorkflowService/"
const adminSvc = "/temporal.server.api.adminservice.v1.AdminService/"

// TestAuthorize_ReferencePolicy is a test helper or test case in this package.
func TestAuthorize_ReferencePolicy(t *testing.T) {
	t.Parallel()
	a := newTestAuthorizer(t, loadReferencePolicy(t))

	cases := []struct {
		name  string
		role  authn.RoleClass
		api   string
		allow bool
	}{
		{"service start allowed", authn.RoleClassService, svc + "StartWorkflowExecution", true},
		{"service worker poll allowed", authn.RoleClassService, svc + "PollActivityTaskQueue", true},
		{"service read-only denied", authn.RoleClassService, svc + "ListWorkflowExecutions", false},
		{"service terminate denied", authn.RoleClassService, svc + "TerminateWorkflowExecution", false},
		{"human read-only allowed", authn.RoleClassHuman, svc + "DescribeNamespace", true},
		// The reference policy ships the human break-glass permit COMMENTED OUT
		// (the on-call gate, FRY-1374, is not built), so the shipped default
		// must DENY break-glass to humans. Re-enable both the permit and this
		// expectation together once the gate exists.
		{"human break-glass denied by default policy", authn.RoleClassHuman, svc + "TerminateWorkflowExecution", false},
		{"human worker denied", authn.RoleClassHuman, svc + "PollActivityTaskQueue", false},
		{"destruction forbidden for service", authn.RoleClassService, svc + "DeleteWorkflowExecution", false},
		{"destruction forbidden for human", authn.RoleClassHuman, svc + "DeleteWorkflowExecution", false},

		// AdminService is forbidden for every role: DescribeMutableState must
		// not slip through as a WorkflowService read-only.
		{"admin describe-mutable-state denied for service", authn.RoleClassService, adminSvc + "DescribeMutableState", false},
		{"admin describe-mutable-state denied for human", authn.RoleClassHuman, adminSvc + "DescribeMutableState", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res, err := a.Authorize(context.Background(), claims(tc.role), target(tc.api))
			require.NoError(t, err)
			if tc.allow {
				require.Equal(t, authorization.DecisionAllow, res.Decision, res.Reason)
			} else {
				require.Equal(t, authorization.DecisionDeny, res.Decision)
			}
		})
	}
}

// TestAuthorize_FailClosed is a test helper or test case in this package.
func TestAuthorize_FailClosed(t *testing.T) {
	t.Parallel()
	a := newTestAuthorizer(t, loadReferencePolicy(t))

	// Unknown role class denies.
	res, err := a.Authorize(context.Background(), claims(authn.RoleClassUnknown), target(svc+"StartWorkflowExecution"))
	require.NoError(t, err)
	require.Equal(t, authorization.DecisionDeny, res.Decision)

	// Unknown verb (unclassified API) denies even for an otherwise-allowed role.
	res, err = a.Authorize(context.Background(), claims(authn.RoleClassService), target(svc+"SomeBrandNewRPC"))
	require.NoError(t, err)
	require.Equal(t, authorization.DecisionDeny, res.Decision)
}

// TestAuthorize_NilCaller guards the unauthenticated path: Temporal invokes the
// authorizer with caller == nil when a request carries no client cert and no
// authorization header. This must deny, never panic — on a streaming RPC a
// panic here would go unrecovered and could crash the frontend.
func TestAuthorize_NilCaller(t *testing.T) {
	t.Parallel()
	a := newTestAuthorizer(t, loadReferencePolicy(t))

	res, err := a.Authorize(context.Background(), nil, target(svc+"StartWorkflowExecution"))
	require.NoError(t, err)
	require.Equal(t, authorization.DecisionDeny, res.Decision)
}

// scopedPolicy confines each workload to its own namespace. It replaces the
// broad service permit, so it is the policy FRY-1429 makes expressible.
const scopedPolicy = `
permit (
  principal == Workload::"` + svcID + `",
  action in [Action::"start-signal", Action::"worker"],
  resource == Namespace::"payments"
);
permit (
  principal in RoleClass::"service",
  action in [Action::"start-signal", Action::"worker"],
  resource == Namespace::"shared"
) when { principal.ns == "billing" };
forbid (principal, action == Action::"forbidden-all", resource);
`

// TestAuthorize_PerWorkloadScoping is a test helper or test case in this package.
func TestAuthorize_PerWorkloadScoping(t *testing.T) {
	t.Parallel()
	a := newTestAuthorizer(t, scopedPolicy)

	cases := []struct {
		name    string
		subject string
		ns      string
		allow   bool
	}{
		{"workload A allowed in its namespace", svcID, "payments", true},
		{"workload A denied in another namespace", svcID, "billing", false},
		{"workload B denied in A's namespace", otherID, "payments", false},
		{"attribute rule allows matching ns", otherID, "shared", true},
		{"attribute rule denies other ns", svcID, "shared", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tgt := &authorization.CallTarget{APIName: svc + "StartWorkflowExecution", Namespace: tc.ns}
			res, err := a.Authorize(context.Background(), claimsFor(tc.subject, authn.RoleClassService), tgt)
			require.NoError(t, err)
			if tc.allow {
				require.Equal(t, authorization.DecisionAllow, res.Decision, res.Reason)
			} else {
				require.Equal(t, authorization.DecisionDeny, res.Decision)
			}
		})
	}
}

// TestAuthorize_MalformedSubjectDenied is a test helper or test case in this package.
func TestAuthorize_MalformedSubjectDenied(t *testing.T) {
	t.Parallel()
	a := newTestAuthorizer(t, loadReferencePolicy(t))

	for _, subject := range []string{"", "test", "https://corp.defakto.security/ns/a/sa/b", "spiffe:///ns/a/sa/b", "spiffe://td/ns/a/sa/b?x=1",
		"spiffe://other.example/ns/payments/sa/worker", // foreign trust domain
		"spiffe://corp.defakto.security:443/ns/a/sa/b", // port
		"spiffe://CORP.defakto.security/ns/a/sa/b",     // uppercase trust domain
		svcID + "/", // trailing slash
		"spiffe://corp.defakto.security/ns//sa/b",           // empty segment
		"spiffe://corp.defakto.security/ns/pa%79ments/sa/b", // escape
		"spiffe://corp.defakto.security/ns/a/../sa/b",       // dot segment
	} {
		res, err := a.Authorize(context.Background(), claimsFor(subject, authn.RoleClassService), target(svc+"StartWorkflowExecution"))
		require.NoError(t, err)
		require.Equal(t, authorization.DecisionDeny, res.Decision, subject)
	}
}

// mustRules is a test helper or test case in this package.
func mustRules(t *testing.T, attrs map[string]string) attributeRules {
	t.Helper()
	cfg := &spiffeconfig.Config{Attributes: attrs}
	m, err := cfg.AttributeRules()
	require.NoError(t, err)
	td, err := spiffeid.TrustDomainFromString("corp.defakto.security")
	require.NoError(t, err)
	return newAttributeRules(m, td)
}

// attrOf is a test helper or test case in this package.
func attrOf(t *testing.T, r attributeRules, subject, name string) types.Value {
	t.Helper()
	_, ents, ok := r.principalEntities(subject, authn.RoleClassService)
	require.True(t, ok)
	v, found := ents[cedar.NewEntityUID(entityWorkload, types.String(subject))].Attributes.Get(types.String(name))
	require.True(t, found, "attribute %s present", name)
	return v
}

// TestPrincipalEntities_DefaultAttributes is a test helper or test case in this package.
func TestPrincipalEntities_DefaultAttributes(t *testing.T) {
	t.Parallel()
	r := mustRules(t, nil)

	require.Equal(t, types.String("payments"), attrOf(t, r, svcID, "ns"))
	require.Equal(t, types.String("worker"), attrOf(t, r, svcID, "sa"))
	require.Equal(t, types.String("corp.defakto.security"), attrOf(t, r, svcID, "trust_domain"))

	// An ID of another shape leaves ns/sa empty, not absent.
	node := "spiffe://corp.defakto.security/node/host-1"
	require.Equal(t, types.String(""), attrOf(t, r, node, "ns"))
}

// TestPrincipalEntities_CustomAttributes is a test helper or test case in this package.
func TestPrincipalEntities_CustomAttributes(t *testing.T) {
	t.Parallel()
	r := mustRules(t, map[string]string{
		"nameSpace": `spiffe://[^/]+/ns/([^/]+)/.*`,         // new name
		"sa":        `.*/sa/([a-z]+)`,                       // overrides the default
		"team":      `spiffe://[^/]+/ns/[a-z]+-([a-z]+)/.*`, // derived piece
	})
	id := "spiffe://corp.defakto.security/ns/pay-core/sa/worker"

	require.Equal(t, types.String("pay-core"), attrOf(t, r, id, "nameSpace"))
	require.Equal(t, types.String("core"), attrOf(t, r, id, "team"))
	require.Equal(t, types.String("worker"), attrOf(t, r, id, "sa"))
	require.Equal(t, types.String("pay-core"), attrOf(t, r, id, "ns"), "defaults stay unless overridden")
}

// TestAuthorize_CustomAttributeInPolicy is a test helper or test case in this package.
func TestAuthorize_CustomAttributeInPolicy(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.cedar")
	policy := `permit (principal in RoleClass::"service", action in [Action::"start-signal"], resource)
	  when { principal.nameSpace == "payments" };`
	require.NoError(t, os.WriteFile(path, []byte(policy), 0o600))
	cfg := &spiffeconfig.Config{
		Version: spiffeconfig.SchemaVersion, TrustDomain: "corp.defakto.security", PolicyPath: path,
		Attributes: map[string]string{"nameSpace": `.*/ns/([^/]+)/.*`},
	}
	a, err := NewCedarAuthorizer(cfg, log.NewNoopLogger())
	require.NoError(t, err)
	t.Cleanup(func() { _ = a.policies.Close() })

	res, err := a.Authorize(context.Background(), claimsFor(svcID, authn.RoleClassService), target(svc+"StartWorkflowExecution"))
	require.NoError(t, err)
	require.Equal(t, authorization.DecisionAllow, res.Decision, res.Reason)
	res, err = a.Authorize(context.Background(), claimsFor(otherID, authn.RoleClassService), target(svc+"StartWorkflowExecution"))
	require.NoError(t, err)
	require.Equal(t, authorization.DecisionDeny, res.Decision)
}

// An attribute name the config never defined is a Cedar evaluation error, which
// the authorizer turns into a deny (never an allow).
func TestAuthorize_UndefinedAttributeDenies(t *testing.T) {
	t.Parallel()
	a := newTestAuthorizer(t, `permit (principal, action, resource) when { principal.nameSpace == "payments" };`)
	res, err := a.Authorize(context.Background(), claimsFor(svcID, authn.RoleClassService), target(svc+"StartWorkflowExecution"))
	require.NoError(t, err)
	require.Equal(t, authorization.DecisionDeny, res.Decision)
}

// A custom pattern must match the whole ID: a lookalike path that merely
// contains the pattern yields "".
func TestPrincipalEntities_PatternsAreAnchored(t *testing.T) {
	t.Parallel()
	r := mustRules(t, map[string]string{"loose": `/ns/(payments)/`})
	require.Equal(t, types.String(""), attrOf(t, r, "spiffe://corp.defakto.security/x/ns/payments/sa/y", "loose"))
}

// Old-style `principal == RoleClass::"x"` policies are refused at load.
func TestPolicyLoad_RejectsLegacyRoleClassScope(t *testing.T) {
	t.Parallel()
	for _, pol := range []string{
		`permit (principal == RoleClass::"service", action, resource);`,
		`forbid (principal is RoleClass, action, resource);`,
	} {
		path := filepath.Join(t.TempDir(), "policy.cedar")
		require.NoError(t, os.WriteFile(path, []byte(pol), 0o600))
		cfg := &spiffeconfig.Config{Version: spiffeconfig.SchemaVersion, TrustDomain: "corp.defakto.security", PolicyPath: path}
		_, err := NewCedarAuthorizer(cfg, log.NewNoopLogger())
		require.ErrorContains(t, err, "principal in RoleClass")
	}
}

// A legacy RoleClass comparison hidden in when/unless is refused at load.
func TestPolicyLoad_RejectsLegacyRoleClassCondition(t *testing.T) {
	t.Parallel()
	for _, pol := range []string{
		`permit (principal, action, resource) when { principal == RoleClass::"service" };`,
		`forbid (principal, action, resource) unless { principal != RoleClass::"human" };`,
		`permit (principal, action, resource) when { principal is RoleClass };`,
	} {
		path := filepath.Join(t.TempDir(), "policy.cedar")
		require.NoError(t, os.WriteFile(path, []byte(pol), 0o600))
		cfg := &spiffeconfig.Config{Version: spiffeconfig.SchemaVersion, TrustDomain: "corp.defakto.security", PolicyPath: path}
		_, err := NewCedarAuthorizer(cfg, log.NewNoopLogger())
		require.ErrorContains(t, err, "principal in RoleClass", pol)
	}
}

// An ID with no path still yields a trust_domain.
func TestPrincipalEntities_PathlessTrustDomain(t *testing.T) {
	t.Parallel()
	r := mustRules(t, nil)
	require.Equal(t, types.String("corp.defakto.security"), attrOf(t, r, "spiffe://corp.defakto.security", "trust_domain"))
}
