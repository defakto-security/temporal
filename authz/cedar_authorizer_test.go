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

// referencePolicy mirrors reference/policy.cedar. Kept inline so the test is
// self-contained and does not depend on the repo-relative file path.
const referencePolicy = `
permit (principal == RoleClass::"service",
        action in [Action::"start-signal", Action::"worker"], resource);
permit (principal == RoleClass::"human",
        action == Action::"read-only", resource);
permit (principal == RoleClass::"human",
        action == Action::"break-glass", resource);
forbid (principal, action == Action::"forbidden-all", resource);
`

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

func TestAuthorize_ReferencePolicy(t *testing.T) {
	t.Parallel()
	a := newTestAuthorizer(t, referencePolicy)

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
	a := newTestAuthorizer(t, referencePolicy)

	// Unknown role class denies.
	res, err := a.Authorize(context.Background(), claims(authn.RoleClassUnknown), target(svc+"StartWorkflowExecution"))
	require.NoError(t, err)
	require.Equal(t, authorization.DecisionDeny, res.Decision)

	// Unknown verb (unclassified API) denies even for an otherwise-allowed role.
	res, err = a.Authorize(context.Background(), claims(authn.RoleClassService), target(svc+"SomeBrandNewRPC"))
	require.NoError(t, err)
	require.Equal(t, authorization.DecisionDeny, res.Decision)
}
