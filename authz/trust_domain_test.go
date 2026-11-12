package authz

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cedar-policy/cedar-go/types"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/require"
	"go.temporal.io/server/common/authorization"
	"go.temporal.io/server/common/log"
	"go.yaml.in/yaml/v3"

	"github.com/defakto-security/temporal/authn"
	spiffeconfig "github.com/defakto-security/temporal/config"
)

func loadPolicy(t *testing.T, pol string) error {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.cedar")
	require.NoError(t, os.WriteFile(path, []byte(pol), 0o600))
	_, err := NewCedarAuthorizer(&spiffeconfig.Config{Version: spiffeconfig.SchemaVersion, PolicyPath: path}, log.NewNoopLogger())
	return err
}

// A permit that never reads principal.trust_domain would admit every
// federated domain, so it is refused at load.
func TestPolicyLoad_RejectsUnscopedPermit(t *testing.T) {
	t.Parallel()
	for _, pol := range []string{
		`permit (principal in RoleClass::"service", action, resource);`,
		`permit (principal, action, resource) when { principal.ns == "payments" };`,
		`permit (principal in RoleClass::"human", action, resource) when { principal.sa == "x" };`,
		`permit (principal, action, resource) when { context.trust_domain == "corp.defakto.security" };`,
		`permit (principal, action, resource) when { resource.trust_domain == "corp.defakto.security" };`,
		`permit (principal, action, resource) when { {"trust_domain": "x"}.trust_domain == "x" };`,
	} {
		require.ErrorContains(t, loadPolicy(t, pol), "principal.trust_domain", pol)
	}
}

// Scoped permits, exact-Workload permits, and any forbid load.
func TestPolicyLoad_AcceptsScopedPolicies(t *testing.T) {
	t.Parallel()
	for _, pol := range []string{
		`permit (principal in RoleClass::"service", action, resource) when { principal.trust_domain == "corp.defakto.security" };`,
		`permit (principal in RoleClass::"service", action, resource) unless { principal.trust_domain != "corp.defakto.security" };`,
		`permit (principal == Workload::"spiffe://corp.defakto.security/ns/a/sa/b", action, resource);`,
		`forbid (principal, action == Action::"forbidden-all", resource);`,
	} {
		require.NoError(t, loadPolicy(t, pol), pol)
	}
}

// The shipped ConfigMap's embedded policy must load, and must keep a federated
// service out while letting the home service in.
func TestReferenceConfigMapPolicy(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("../reference/configmap.example.yaml")
	require.NoError(t, err)
	var cm struct {
		Data map[string]string `yaml:"data"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &cm))
	a := newTestAuthorizer(t, cm.Data["policy.cedar"])

	res := call(t, a, svcID, "payments")
	require.Equal(t, authorization.DecisionAllow, res.Decision, res.Reason)
	res = call(t, a, "spiffe://partner.example.net/ns/payments/sa/worker", "payments")
	require.Equal(t, authorization.DecisionDeny, res.Decision, "a federated domain must not match the home-domain permit")
}

// A federated ID whose path mimics the home domain still reads as its own
// trust domain: the attribute comes from the parsed ID.
func TestPrincipalEntities_TrustDomainFromID(t *testing.T) {
	t.Parallel()
	r := mustRules(t, nil)
	require.Equal(t, types.String("partner.example"), attrOf(t, r, "spiffe://partner.example/ns/x/sa/corp.defakto.security", "trust_domain"))
}

// rejectingVerifier fails every token, as a forged token would.
type rejectingVerifier struct{}

func (rejectingVerifier) Verify(string) (spiffeid.ID, error) { return spiffeid.ID{}, errors.New("bad") }

// End to end: a forged token reaches the authorizer as an unknown class. Enforce
// denies it. Observe lets it through and reports it, but still denies the
// verbs observe never forgives.
func TestForgedToken_MapperThenAuthorizer(t *testing.T) {
	t.Parallel()
	cfg := &spiffeconfig.Config{}
	m, err := authn.NewClaimMapper(cfg, rejectingVerifier{}, log.NewNoopLogger())
	require.NoError(t, err)
	claims, err := m.GetClaims(&authorization.AuthInfo{AuthToken: "Bearer a.b.c"})
	require.NoError(t, err)

	start := &authorization.CallTarget{APIName: svc + "StartWorkflowExecution", Namespace: "payments"}
	terminate := &authorization.CallTarget{APIName: svc + "TerminateWorkflowExecution", Namespace: "payments"}

	enf, _, _ := newAuthorizerWith(t, loadReferencePolicy(t), "", spiffeconfig.DecisionLogOff, spiffeconfig.IdentityModeEnforce)
	res, err := enf.Authorize(context.Background(), claims, start)
	require.NoError(t, err)
	require.Equal(t, authorization.DecisionDeny, res.Decision)

	obs, logger, _ := newAuthorizerWith(t, loadReferencePolicy(t), "", spiffeconfig.DecisionLogOff, spiffeconfig.IdentityModeObserve)
	res, err = obs.Authorize(context.Background(), claims, start)
	require.NoError(t, err)
	require.Equal(t, authorization.DecisionAllow, res.Decision)
	require.Len(t, logger.decisions(decisionWouldDeny), 1)
	res, err = obs.Authorize(context.Background(), claims, terminate)
	require.NoError(t, err)
	require.Equal(t, authorization.DecisionDeny, res.Decision, "break-glass is never forgiven")
}
