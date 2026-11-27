package authz

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.temporal.io/server/common/authorization"
	"go.temporal.io/server/common/metrics"

	"github.com/defakto-security/temporal/authn"
	spiffeconfig "github.com/defakto-security/temporal/config"
)

// reloadMetrics records the policy reload counter and the loaded-at gauge.
type reloadMetrics struct {
	metrics.Handler
	mu      sync.Mutex
	results []string
	loaded  []float64
}

func newReloadMetrics() *reloadMetrics { return &reloadMetrics{Handler: metrics.NoopMetricsHandler} }

func (h *reloadMetrics) WithTags(...metrics.Tag) metrics.Handler { return h }

func (h *reloadMetrics) Counter(name string) metrics.CounterIface {
	return reloadCounterFunc(func(tags []metrics.Tag) {
		if name != metricPolicyReload {
			return
		}
		h.mu.Lock()
		defer h.mu.Unlock()
		for _, t := range tags {
			if t.Key == "result" {
				h.results = append(h.results, t.Value)
			}
		}
	})
}

func (h *reloadMetrics) Gauge(name string) metrics.GaugeIface {
	return reloadGaugeFunc(func(v float64) {
		if name != metricPolicyLoadedAt {
			return
		}
		h.mu.Lock()
		defer h.mu.Unlock()
		h.loaded = append(h.loaded, v)
	})
}

func (h *reloadMetrics) count(result string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, r := range h.results {
		if r == result {
			n++
		}
	}
	return n
}

type reloadCounterFunc func([]metrics.Tag)

func (f reloadCounterFunc) Record(_ int64, tags ...metrics.Tag) { f(tags) }

type reloadGaugeFunc func(float64)

func (f reloadGaugeFunc) Record(v float64, _ ...metrics.Tag) { f(v) }

const (
	allowStartPolicy = `permit (principal in RoleClass::"service", action in Action::"workflow-start", resource)` + scope + `;`
	denyAllPolicy    = `forbid (principal, action, resource);`
)

// A policy edit takes effect without a restart. A broken edit or a deleted file
// keeps the previous policy live, and each outcome is counted. A file next to
// the policy does not trigger a reload.
func TestPolicyReload(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.cedar")
	write := func(body string) { require.NoError(t, os.WriteFile(path, []byte(body), 0o600)) }
	write(allowStartPolicy)

	logger := newCaptureLogger()
	a, err := NewCedarAuthorizer(&spiffeconfig.Config{Version: spiffeconfig.SchemaVersion, PolicyPath: path}, logger)
	require.NoError(t, err)
	t.Cleanup(func() { _ = a.Close() })
	h := newReloadMetrics()
	a.WithMetrics(h, "frontend")

	require.Equal(t, authorization.DecisionAllow, call(t, a, svcID, "payments").Decision)
	require.NotEmpty(t, h.loaded, "the loaded-at gauge is published when metrics are attached")
	require.Positive(t, h.loaded[0])

	waitFor := func(what string, cond func() bool) {
		t.Helper()
		require.Eventually(t, cond, 5*time.Second, 20*time.Millisecond, what)
	}
	decision := func() authorization.Decision { return call(t, a, svcID, "payments").Decision }

	// A file that is not the policy does not reload it.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "other.txt"), []byte("x"), 0o600))
	time.Sleep(4 * reloadDebounce)
	require.Zero(t, h.count("ok")+h.count("error"))

	// A good edit applies.
	write(denyAllPolicy)
	waitFor("good edit reloads", func() bool { return h.count("ok") == 1 })
	require.Equal(t, authorization.DecisionDeny, decision())

	// A broken edit keeps the policy that was live, and is counted as an error.
	write("this is not cedar")
	waitFor("bad edit is counted", func() bool { return h.count("error") == 1 })
	require.Equal(t, authorization.DecisionDeny, decision(), "previous policy stays live")

	// A deleted file does the same.
	write(allowStartPolicy)
	waitFor("good edit after bad reloads", func() bool { return h.count("ok") == 2 })
	require.Equal(t, authorization.DecisionAllow, decision())
	require.NoError(t, os.Remove(path))
	waitFor("deleted file is counted", func() bool { return h.count("error") == 2 })
	require.Equal(t, authorization.DecisionAllow, decision(), "previous policy stays live")

	var logged bool
	logger.mu.Lock()
	for _, l := range logger.lines {
		logged = logged || (l.level == "error" && l.msg == "cedar policy reload failed; keeping previous policy")
	}
	logger.mu.Unlock()
	require.True(t, logged, "a failed reload is logged")
}

// A policy path that is a symlink to a sibling file reloads when the real file
// changes, because the event names the target, not the link.
func TestPolicyReload_SymlinkToSiblingFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "real.cedar")
	link := filepath.Join(dir, "policy.cedar")
	require.NoError(t, os.WriteFile(target, []byte(allowStartPolicy), 0o600))
	require.NoError(t, os.Symlink("real.cedar", link))

	a, err := NewCedarAuthorizer(&spiffeconfig.Config{Version: spiffeconfig.SchemaVersion, PolicyPath: link}, newCaptureLogger())
	require.NoError(t, err)
	t.Cleanup(func() { _ = a.Close() })
	h := newReloadMetrics()
	a.WithMetrics(h, "frontend")
	require.Equal(t, authorization.DecisionAllow, call(t, a, svcID, "payments").Decision)

	require.NoError(t, os.WriteFile(target, []byte(denyAllPolicy), 0o600))
	require.Eventually(t, func() bool { return h.count("ok") == 1 }, 5*time.Second, 20*time.Millisecond)
	require.Equal(t, authorization.DecisionDeny, call(t, a, svcID, "payments").Decision)
}

// identityMode observe lets a call with no valid identity through without
// evaluating the policy, so a customer forbid does not stop it. A call with a
// valid identity is still decided by the policy. This is deliberate: observe is
// the data-gathering stage of a rollout and must not block traffic.
func TestIdentityMode_ObserveDoesNotEvaluateForbidForInvalidIdentity(t *testing.T) {
	t.Parallel()
	policy := loadReferencePolicy(t) + `
forbid (principal, action in Action::"workflow-start", resource == Namespace::"prod");
`
	start := &authorization.CallTarget{APIName: svc + "StartWorkflowExecution", Namespace: "prod"}
	valid := claimsFor(svcID, authn.RoleClassService)

	enf, _, _ := newAuthorizerWith(t, policy, "", spiffeconfig.DecisionLogOff, spiffeconfig.IdentityModeEnforce)
	res, err := enf.Authorize(t.Context(), nil, start)
	require.NoError(t, err)
	require.Equal(t, authorization.DecisionDeny, res.Decision, "enforce denies a call with no identity")

	obs, logger, _ := newAuthorizerWith(t, policy, "", spiffeconfig.DecisionLogOff, spiffeconfig.IdentityModeObserve)
	res, err = obs.Authorize(t.Context(), nil, start)
	require.NoError(t, err)
	require.Equal(t, authorization.DecisionAllow, res.Decision, "observe forgives it; the forbid is not evaluated")
	require.Len(t, logger.decisions(decisionWouldDeny), 1, "and reports it")

	res, err = obs.Authorize(t.Context(), valid, start)
	require.NoError(t, err)
	require.Equal(t, authorization.DecisionDeny, res.Decision, "a valid identity is still decided by the forbid")
}

// workflow-start holds SignalWithStart and ExecuteMultiOperation, so a caller
// with only workflow-start can also signal through them. A custom role is how
// to grant a start that cannot signal. This test pins the group's contents.
func TestWorkflowStartHoldsSignalWithStart(t *testing.T) {
	t.Parallel()
	a, err := groupsAuthorizer(t, allowStartPolicy, nil)
	require.NoError(t, err)
	for _, api := range []string{"StartWorkflowExecution", "SignalWithStartWorkflowExecution", "ExecuteMultiOperation"} {
		require.True(t, allowed(t, a, svcID, svc+api, "p"), api)
	}
	require.False(t, allowed(t, a, svcID, svc+"SignalWorkflowExecution", "p"), "a plain signal needs workflow-signal")
}

// A permit with no action scope would grant every group, the admin groups
// included, so it is refused at load. A forbid may leave the action open.
func TestPolicyLoad_RejectsPermitWithoutActionScope(t *testing.T) {
	t.Parallel()
	for _, pol := range []string{
		`permit (principal in RoleClass::"service", action, resource)` + scope + `;`,
		`permit (principal, action, resource) when { principal.trust_domain == "corp.defakto.security" };`,
		allowStartPolicy + "\n" + `permit (principal == Workload::"spiffe://corp.defakto.security/ns/a/sa/b", action, resource);`,
	} {
		err := loadPolicy(t, pol)
		require.ErrorContains(t, err, "no action scope", pol)
		require.ErrorContains(t, err, "action in [", "the message says how to fix it")
	}
	require.NoError(t, loadPolicy(t, allowStartPolicy+"\n"+denyAllPolicy))

	// The shadow policy is held to the same rule.
	cfg := &spiffeconfig.Config{
		Version:          spiffeconfig.SchemaVersion,
		PolicyPath:       writePolicy(t, allowStartPolicy),
		ShadowPolicyPath: writePolicy(t, `permit (principal, action, resource)`+scope+`;`),
	}
	_, err := NewCedarAuthorizer(cfg, newCaptureLogger())
	require.ErrorContains(t, err, "no action scope")
}

// A misspelled RPC name loads, because a policy may name a new RPC before the
// image knows it, but it is logged so a forbid that matches nothing is noticed.
func TestPolicyLoad_WarnsOnUnknownRPCName(t *testing.T) {
	t.Parallel()
	warnings := func(l *captureLogger) []logLine {
		l.mu.Lock()
		defer l.mu.Unlock()
		var out []logLine
		for _, ln := range l.lines {
			if ln.level == "warn" && strings.Contains(ln.msg, "does not know") {
				out = append(out, ln)
			}
		}
		return out
	}
	load := func(policy string, groups map[string][]string) *captureLogger {
		l := newCaptureLogger()
		a, err := NewCedarAuthorizer(&spiffeconfig.Config{
			Version: spiffeconfig.SchemaVersion, PolicyPath: writePolicy(t, policy), ActionGroups: groups,
		}, l)
		require.NoError(t, err, "a typo is a warning, never an error")
		t.Cleanup(func() { _ = a.Close() })
		return l
	}

	l := load(allowStartPolicy+`
forbid (principal, action == Action::"WorkflowService/TerminateWorkflowExection", resource);`, nil)
	w := warnings(l)
	require.Len(t, w, 1)
	require.Equal(t, "WorkflowService/TerminateWorkflowExection", w[0].fields["action"])

	// Admin and Operator RPCs are checked too.
	l = load(allowStartPolicy+`
forbid (principal, action == Action::"OperatorService/DeleteNamespaces", resource);`, nil)
	require.Len(t, warnings(l), 1)

	// A real RPC, a service the image does not know, and a group name are quiet.
	l = load(allowStartPolicy+`
forbid (principal, action == Action::"WorkflowService/TerminateWorkflowExecution", resource);
forbid (principal, action == Action::"OtherService/Anything", resource);
forbid (principal, action in Action::"delete-all", resource);`, nil)
	require.Empty(t, warnings(l))

	// A typo in a customer group member is reported too.
	l = load(allowStartPolicy, map[string][]string{"mine": {"WorkflowService/QueryWorkflow", "WorkflowService/QueryWorkflw"}})
	w = warnings(l)
	require.Len(t, w, 1)
	require.Equal(t, "WorkflowService/QueryWorkflw", w[0].fields["action"])
}
