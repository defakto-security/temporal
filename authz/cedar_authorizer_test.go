package authz

import (
	"context"
	"os"
	"path/filepath"
	"testing"

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

func loadReferencePolicy(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(referencePolicyPath)
	require.NoError(t, err)
	return string(raw)
}

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

func claims(class authn.RoleClass) *authorization.Claims {
	return &authorization.Claims{Subject: "test", AuthType: "spiffe", Extensions: class}
}

func target(api string) *authorization.CallTarget {
	return &authorization.CallTarget{APIName: api, Namespace: "dev_portal"}
}

const svc = "/temporal.api.workflowservice.v1.WorkflowService/"
const adminSvc = "/temporal.server.api.adminservice.v1.AdminService/"

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
		{"human break-glass allowed by policy", authn.RoleClassHuman, svc + "TerminateWorkflowExecution", true},
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
