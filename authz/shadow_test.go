package authz

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"go.temporal.io/server/common/authorization"
	"go.temporal.io/server/common/log"
	"go.temporal.io/server/common/log/tag"
	"go.temporal.io/server/common/metrics"

	"github.com/defakto-security/temporal/authn"
	spiffeconfig "github.com/defakto-security/temporal/config"
)

type logLine struct {
	level  string
	msg    string
	fields map[string]any
}

// captureLogger records every line; the embedded noop logger covers the rest.
type captureLogger struct {
	log.Logger
	mu    sync.Mutex
	lines []logLine
}

func newCaptureLogger() *captureLogger { return &captureLogger{Logger: log.NewNoopLogger()} }

func (c *captureLogger) add(level, msg string, tags []tag.Tag) {
	f := map[string]any{}
	for _, t := range tags {
		f[t.Key()] = t.Value()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines = append(c.lines, logLine{level, msg, f})
}
func (c *captureLogger) Info(m string, t ...tag.Tag)  { c.add("info", m, t) }
func (c *captureLogger) Warn(m string, t ...tag.Tag)  { c.add("warn", m, t) }
func (c *captureLogger) Error(m string, t ...tag.Tag) { c.add("error", m, t) }

func (c *captureLogger) decisions(decision string) []logLine {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []logLine
	for _, l := range c.lines {
		if l.msg == "authz decision" && l.fields["decision"] == decision {
			out = append(out, l)
		}
	}
	return out
}

type countRecord struct{ decision, verb, reason string }

// countingHandler records decision counters.
type countingHandler struct {
	metrics.Handler
	mu     sync.Mutex
	counts []countRecord
}

func (h *countingHandler) Counter(string) metrics.CounterIface     { return counterFunc(h.record) }
func (h *countingHandler) WithTags(...metrics.Tag) metrics.Handler { return h }
func (h *countingHandler) record(tags []metrics.Tag) {
	var r countRecord
	for _, t := range tags {
		switch t.Key {
		case "decision":
			r.decision = t.Value
		case "verb":
			r.verb = t.Value
		case "reason":
			r.reason = t.Value
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.counts = append(h.counts, r)
}

type counterFunc func([]metrics.Tag)

func (f counterFunc) Record(_ int64, tags ...metrics.Tag) { f(tags) }

func writePolicy(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "p.cedar")
	require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	return p
}

func newShadowAuthorizer(t *testing.T, live, shadow, level string) (*CedarAuthorizer, *captureLogger, *countingHandler) {
	t.Helper()
	return newAuthorizerWith(t, live, shadow, level, "")
}

func newAuthorizerWith(t *testing.T, live, shadow, level, identityMode string) (*CedarAuthorizer, *captureLogger, *countingHandler) {
	t.Helper()
	logger := newCaptureLogger()
	h := &countingHandler{Handler: metrics.NoopMetricsHandler}
	cfg := &spiffeconfig.Config{
		Version:     spiffeconfig.SchemaVersion,
		TrustDomain: "corp.defakto.security",
		PolicyPath:  writePolicy(t, live),
		DecisionLog: level,

		IdentityMode: identityMode,
	}
	if shadow != "" {
		cfg.ShadowPolicyPath = writePolicy(t, shadow)
	}
	a, err := NewCedarAuthorizer(cfg, logger)
	require.NoError(t, err)
	a.WithMetrics(h)
	t.Cleanup(func() { _ = a.Close() })
	return a, logger, h
}

func call(t *testing.T, a *CedarAuthorizer, subject, ns string) authorization.Result {
	t.Helper()
	res, err := a.Authorize(context.Background(), claimsFor(subject, authn.RoleClassService),
		&authorization.CallTarget{APIName: svc + "StartWorkflowExecution", Namespace: ns})
	require.NoError(t, err)
	return res
}

func TestShadow_LiveAllowsCandidateDenies(t *testing.T) {
	t.Parallel()
	a, logger, h := newShadowAuthorizer(t, loadReferencePolicy(t), scopedPolicy, spiffeconfig.DecisionLogOff)

	// Live (open) policy allows; the candidate only allows ns == own ns.
	res := call(t, a, svcID, "billing")
	require.Equal(t, authorization.DecisionAllow, res.Decision, "live decision is enforced")

	wd := logger.decisions(decisionWouldDeny)
	require.Len(t, wd, 1)
	require.Equal(t, svcID, wd[0].fields["principal"])
	require.Equal(t, "billing", wd[0].fields["namespace"])
	require.Equal(t, "start-signal", wd[0].fields["verb"])
	require.Equal(t, "worker", wd[0].fields["attributes"].(map[string]string)["sa"])
	require.Contains(t, h.counts, countRecord{decisionWouldDeny, "start-signal", reasonAllowed})
	require.Contains(t, h.counts, countRecord{decisionAllow, "start-signal", reasonAllowed})

	// Candidate agrees: no would_deny.
	logger.lines = nil
	require.Equal(t, authorization.DecisionAllow, call(t, a, svcID, "payments").Decision)
	require.Empty(t, logger.decisions(decisionWouldDeny))
}

func TestShadow_CandidateErrorDoesNotChangeLive(t *testing.T) {
	t.Parallel()
	// Reads an attribute that does not exist: Cedar errors on it.
	broken := `permit (principal, action, resource) when { principal.nope == "x" };`
	a, logger, _ := newShadowAuthorizer(t, loadReferencePolicy(t), broken, spiffeconfig.DecisionLogOff)

	res := call(t, a, svcID, "payments")
	require.Equal(t, authorization.DecisionAllow, res.Decision)
	require.Empty(t, logger.decisions(decisionWouldDeny))

	var logged bool
	for _, l := range logger.lines {
		if l.level == "error" && l.msg == "shadow policy evaluation error; ignoring" {
			logged = true
		}
	}
	require.True(t, logged, "candidate error is logged")
}

func TestShadow_LiveDeniesCandidateAllows(t *testing.T) {
	t.Parallel()
	// Live is scoped; the candidate is the open reference policy.
	a, logger, h := newShadowAuthorizer(t, scopedPolicy, loadReferencePolicy(t), spiffeconfig.DecisionLogOff)

	res := call(t, a, svcID, "billing")
	require.Equal(t, authorization.DecisionDeny, res.Decision, "live decision is enforced")
	require.Len(t, logger.decisions(decisionWouldAllow), 1)
	require.Empty(t, logger.decisions(decisionWouldDeny))
	require.Contains(t, h.counts, countRecord{decisionWouldAllow, "start-signal", reasonDeniedByPolicy})

	// Both agree on deny: no divergence.
	logger.lines = nil
	both := `forbid (principal, action, resource);`
	a2, logger2, _ := newShadowAuthorizer(t, both, both, spiffeconfig.DecisionLogOff)
	require.Equal(t, authorization.DecisionDeny, call(t, a2, svcID, "payments").Decision)
	require.Empty(t, logger2.decisions(decisionWouldAllow))
}

func TestShadow_BadCandidatePathFailsStart(t *testing.T) {
	t.Parallel()
	cfg := &spiffeconfig.Config{
		Version:          spiffeconfig.SchemaVersion,
		TrustDomain:      "corp.defakto.security",
		PolicyPath:       writePolicy(t, loadReferencePolicy(t)),
		ShadowPolicyPath: filepath.Join(t.TempDir(), "missing.cedar"),
	}
	_, err := NewCedarAuthorizer(cfg, log.NewNoopLogger())
	require.ErrorContains(t, err, "shadow policy")

	cfg.ShadowPolicyPath = writePolicy(t, "this is not cedar")
	_, err = NewCedarAuthorizer(cfg, log.NewNoopLogger())
	require.ErrorContains(t, err, "shadow policy")
}

func TestDecisionLog_Levels(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		level       string
		allows, den int
	}{
		{spiffeconfig.DecisionLogOff, 0, 0},
		{spiffeconfig.DecisionLogDeny, 0, 1},
		{spiffeconfig.DecisionLogAll, 1, 1},
	} {
		t.Run(tc.level, func(t *testing.T) {
			t.Parallel()
			a, logger, _ := newShadowAuthorizer(t, scopedPolicy, "", tc.level)
			call(t, a, svcID, "payments") // allowed
			call(t, a, svcID, "billing")  // denied
			require.Len(t, logger.decisions(decisionAllow), tc.allows)
			require.Len(t, logger.decisions(decisionDeny), tc.den)
		})
	}
}

func TestDecisionLog_FieldsOnDeny(t *testing.T) {
	t.Parallel()
	a, logger, _ := newShadowAuthorizer(t, scopedPolicy, "", spiffeconfig.DecisionLogAll)
	call(t, a, svcID, "billing")
	d := logger.decisions(decisionDeny)
	require.Len(t, d, 1)
	require.Equal(t, "denied by policy", d[0].fields["reason"])
	require.Equal(t, "service", d[0].fields["roleClass"])
	require.Equal(t, "payments", d[0].fields["attributes"].(map[string]string)["ns"])
}

func TestConfig_ShadowValidation(t *testing.T) {
	t.Parallel()
	c := spiffeconfig.Config{Version: spiffeconfig.SchemaVersion, TrustDomain: "td", PolicyPath: "/p", ShadowPolicyPath: "/p"}
	require.ErrorContains(t, c.Validate(), "must differ")
	c = spiffeconfig.Config{Version: spiffeconfig.SchemaVersion, TrustDomain: "td", PolicyPath: "/p", DecisionLog: "loud"}
	require.ErrorContains(t, c.Validate(), "decisionLog")
}

func TestIdentityMode_ObserveAllowsAndReports(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		caller *authorization.Claims
		api    string
		code   string
	}{
		{"nil caller", nil, svc + "StartWorkflowExecution", reasonUnauthenticated},
		{"no role class", &authorization.Claims{Subject: svcID, Extensions: authn.RoleClassUnknown}, svc + "StartWorkflowExecution", reasonUnknownRoleClass},
		{"bad subject", claimsFor("spiffe://other.example/ns/a/sa/b", authn.RoleClassService), svc + "StartWorkflowExecution", reasonMalformedSubject},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tgt := &authorization.CallTarget{APIName: tc.api, Namespace: "payments"}

			// enforce (default): denied.
			enf, _, _ := newAuthorizerWith(t, loadReferencePolicy(t), "", spiffeconfig.DecisionLogOff, spiffeconfig.IdentityModeEnforce)
			res, err := enf.Authorize(context.Background(), tc.caller, tgt)
			require.NoError(t, err)
			require.Equal(t, authorization.DecisionDeny, res.Decision)

			// observe: allowed, reported as would_deny with the reason code.
			obs, logger, h := newAuthorizerWith(t, loadReferencePolicy(t), "", spiffeconfig.DecisionLogOff, spiffeconfig.IdentityModeObserve)
			res, err = obs.Authorize(context.Background(), tc.caller, tgt)
			require.NoError(t, err)
			require.Equal(t, authorization.DecisionAllow, res.Decision)
			wd := logger.decisions(decisionWouldDeny)
			require.Len(t, wd, 1)
			require.Equal(t, tc.code, wd[0].fields["reasonCode"])
			var found bool
			for _, c := range h.counts {
				found = found || (c.decision == decisionWouldDeny && c.reason == tc.code)
			}
			require.True(t, found, h.counts)
		})
	}
}

func TestIdentityMode_ObserveStillEnforcesPolicy(t *testing.T) {
	t.Parallel()
	// A valid identity the policy denies stays denied in observe mode.
	a, logger, h := newAuthorizerWith(t, scopedPolicy, "", spiffeconfig.DecisionLogOff, spiffeconfig.IdentityModeObserve)
	require.Equal(t, authorization.DecisionDeny, call(t, a, svcID, "billing").Decision)
	require.Empty(t, logger.decisions(decisionWouldDeny))
	require.Contains(t, h.counts, countRecord{decisionDeny, "start-signal", reasonDeniedByPolicy})
}

func TestConfig_IdentityModeValidation(t *testing.T) {
	t.Parallel()
	c := spiffeconfig.Config{Version: spiffeconfig.SchemaVersion, TrustDomain: "td", PolicyPath: "/p", IdentityMode: "lax"}
	require.ErrorContains(t, c.Validate(), "identityMode")
}

func TestIdentityMode_ObserveNeverForgivesDangerousOrUnknownVerbs(t *testing.T) {
	t.Parallel()
	a, _, _ := newAuthorizerWith(t, loadReferencePolicy(t), "", spiffeconfig.DecisionLogOff, spiffeconfig.IdentityModeObserve)
	for _, api := range []string{
		svc + "NoSuchCall", // unclassified
		adminSvc + "CloseShard",
	} {
		for _, caller := range []*authorization.Claims{nil, claimsFor(svcID, authn.RoleClassService)} {
			res, err := a.Authorize(context.Background(), caller, &authorization.CallTarget{APIName: api, Namespace: "payments"})
			require.NoError(t, err)
			require.Equal(t, authorization.DecisionDeny, res.Decision, api)
		}
	}
}

func TestAuthorize_NilTargetFailsClosed(t *testing.T) {
	t.Parallel()
	a, _, _ := newAuthorizerWith(t, loadReferencePolicy(t), "", spiffeconfig.DecisionLogOff, "")
	res, err := a.Authorize(context.Background(), claimsFor(svcID, authn.RoleClassService), nil)
	require.NoError(t, err)
	require.Equal(t, authorization.DecisionDeny, res.Decision)
}

func TestNamespaceTag_Bounded(t *testing.T) {
	t.Parallel()
	a, _, _ := newAuthorizerWith(t, loadReferencePolicy(t), "", spiffeconfig.DecisionLogOff, "")

	// Denied and anonymous callers never mint a tracked value.
	require.Equal(t, otherNamespace, a.namespaceTag(&decisionRecord{namespace: "junk", decision: decisionDeny}))
	require.Equal(t, otherNamespace, a.namespaceTag(&decisionRecord{namespace: "junk2", decision: decisionAllow, identityFailure: true}))

	// An authenticated, allowed namespace is tracked, up to the cap.
	require.Equal(t, "payments", a.namespaceTag(&decisionRecord{namespace: "payments", decision: decisionAllow}))
	require.Equal(t, "payments", a.namespaceTag(&decisionRecord{namespace: "payments", decision: decisionDeny}))
	for i := range maxMetricNamespaces + 10 {
		a.namespaceTag(&decisionRecord{namespace: "ns" + string(rune('a'+i%26)) + string(rune('a'+i/26)), decision: decisionAllow})
	}
	require.LessOrEqual(t, len(a.namespaces), maxMetricNamespaces)
	require.Equal(t, otherNamespace, a.namespaceTag(&decisionRecord{namespace: "late", decision: decisionAllow}))
}
