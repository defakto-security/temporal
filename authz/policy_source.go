package authz

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	cedar "github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
	"github.com/cedar-policy/cedar-go/x/exp/ast"
	"github.com/fsnotify/fsnotify"
	"go.temporal.io/server/common/log"
	"go.temporal.io/server/common/log/tag"
	"go.temporal.io/server/common/metrics"

	spiffeconfig "github.com/defakto-security/temporal/config"
)

// Metric names for policy loading.
const (
	metricPolicyReload   = "defakto_authz_policy_reload"
	metricPolicyLoadedAt = "defakto_authz_policy_loaded_timestamp_seconds"
)

// reloadDebounce is how long the watcher waits after the last file event before
// it reloads. One edit raises several events, and a write in progress can leave
// a half-written file, so the reload waits for the writes to stop.
const reloadDebounce = 100 * time.Millisecond

// policySource loads the customer-owned Cedar policy from a file and hot-reloads
// it on change (fsnotify).
//
// At start the policy must load, or the server does not start. After that, a
// reload that fails (a deleted file, a syntax error, a rejected policy) keeps the
// last good policy live and is reported with a log line and the
// defakto_authz_policy_reload{result="error"} counter. The gauge
// defakto_authz_policy_loaded_timestamp_seconds shows when the live policy was
// loaded, so an alert can fire when it stays old after an edit.
type policySource struct {
	path   string
	logger log.Logger
	// kind is the metric tag that tells the live and the shadow policy apart.
	kind string

	// metrics receives the reload counter and the loaded-at gauge. Set once the
	// authorizer has its handler; nil before that.
	metrics atomic.Pointer[metrics.Handler]
	// loadedAt is the Unix time of the last good load.
	loadedAt atomic.Int64

	// current holds the last successfully-parsed *cedar.PolicySet, or nil.
	// Read on the hot path with no lock; swapped atomically on reload.
	current atomic.Pointer[cedar.PolicySet]

	// groups says which action names a policy may use. Nil skips the check.
	groups *actionGroups

	watcher *fsnotify.Watcher
}

// newPolicySource loads the policy at path once (which MUST succeed, or the
// server refuses to start) and begins watching it for changes.
func newPolicySource(path, kind string, groups *actionGroups, logger log.Logger) (*policySource, error) {
	s := &policySource{path: path, kind: kind, logger: logger, groups: groups}
	if err := s.reload(); err != nil {
		return nil, fmt.Errorf("initial policy load: %w", err)
	}
	if err := s.watch(); err != nil {
		return nil, fmt.Errorf("watching policy: %w", err)
	}
	return s, nil
}

// policySet returns the current policy set, or nil when none has ever loaded
// cleanly. A nil return means fail-closed: the authorizer denies.
func (s *policySource) policySet() *cedar.PolicySet {
	return s.current.Load()
}

// reload parses the policy file and, only on success, swaps it in. A failed
// reload leaves the previously-good policy in place rather than going dark.
func (s *policySource) reload() error {
	raw, err := os.ReadFile(s.path) //nolint:gosec // operator-supplied config path.
	if err != nil {
		return fmt.Errorf("reading policy %q: %w", s.path, err)
	}
	ps, err := cedar.NewPolicySetFromBytes(s.path, raw)
	if err != nil {
		return fmt.Errorf("parsing policy %q: %w", s.path, err)
	}
	if err := rejectLegacyPrincipalScopes(ps); err != nil {
		return fmt.Errorf("policy %q: %w", s.path, err)
	}
	if err := requireTrustDomainScope(ps); err != nil {
		return fmt.Errorf("policy %q: %w", s.path, err)
	}
	if err := rejectUnscopedActions(ps); err != nil {
		return fmt.Errorf("policy %q: %w", s.path, err)
	}
	if err := s.groups.rejectUnknownActionGroups(ps); err != nil {
		return fmt.Errorf("policy %q: %w", s.path, err)
	}
	s.warnUnknownRPCs(ps)
	s.current.Store(ps)
	s.loadedAt.Store(time.Now().Unix())
	return nil
}

// setMetrics gives the source its metrics handler and publishes the loaded-at
// gauge for the policy that is already live.
func (s *policySource) setMetrics(h metrics.Handler) {
	s.metrics.Store(&h)
	s.publishLoadedAt()
}

func (s *policySource) publishLoadedAt() {
	if h := s.metrics.Load(); h != nil {
		(*h).Gauge(metricPolicyLoadedAt).Record(float64(s.loadedAt.Load()), metrics.StringTag("policy", s.kind))
	}
}

// reloadAndReport reloads the policy after a file change and reports the result.
func (s *policySource) reloadAndReport() {
	err := s.reload()
	result := "ok"
	if err != nil {
		result = "error"
		// Keep serving the last good policy; surface the failure loudly.
		s.logger.Error("cedar policy reload failed; keeping previous policy",
			tag.NewStringTag("policy", s.kind), tag.Error(err))
	} else {
		s.logger.Info("cedar policy reloaded", tag.NewStringTag("policy", s.kind))
	}
	if h := s.metrics.Load(); h != nil {
		(*h).Counter(metricPolicyReload).Record(1,
			metrics.StringTag("policy", s.kind), metrics.StringTag("result", result))
	}
	if err == nil {
		s.publishLoadedAt()
	}
}

// rejectUnscopedActions refuses a permit with no action scope. Such a permit
// grants every RPC that has a shipped group, the admin groups included, and is
// almost always a mistake. A forbid may leave the action unscoped.
func rejectUnscopedActions(ps *cedar.PolicySet) error {
	var bad []string
	for id, p := range ps.All() {
		if a := p.AST(); a.Effect == ast.EffectPermit {
			if _, all := a.Action.(ast.ScopeTypeAll); all {
				bad = append(bad, string(id))
			}
		}
	}
	if len(bad) == 0 {
		return nil
	}
	sort.Strings(bad)
	return fmt.Errorf("%s is a permit with no action scope, which grants every group, the admin groups included; "+
		"scope it with `action in [Action::\"<group>\", ...]` (the README lists the groups)",
		strings.Join(bad, ", "))
}

// requireTrustDomainScope refuses a permit that does not mention
// principal.trust_domain, unless it names one exact Workload. Any trust domain
// the SPIFFE agent holds a bundle for (federated ones too) can authenticate,
// so an unscoped permit would admit all of them. This is a guard against
// forgetting the scope, not a proof: it checks that the condition reads the
// attribute, not what the condition does with it.
func requireTrustDomainScope(ps *cedar.PolicySet) error {
	for id, p := range ps.All() {
		a := p.AST()
		if a.Effect != ast.EffectPermit {
			continue
		}
		if sc, ok := a.Principal.(ast.ScopeTypeEq); ok && sc.Entity.Type == entityWorkload {
			continue
		}
		if !conditionsReadTrustDomain(a.Conditions) {
			return fmt.Errorf("policy %s is a permit that does not scope principal.trust_domain; "+
				"add `when { principal.trust_domain == \"<your trust domain>\" }` "+
				"(federated trust domains can authenticate, so an unscoped permit admits them)", id)
		}
	}
	return nil
}

// conditionsReadTrustDomain reports whether any when/unless body reads
// principal.trust_domain. The receiver must be the principal variable itself:
// `context.trust_domain` or a record literal's field does not count.
func conditionsReadTrustDomain(conds []ast.ConditionType) bool {
	found := false
	for _, c := range conds {
		ast.Inspect(ast.NewNode(c.Body), func(n ast.IsNode) bool {
			if t, ok := n.(ast.NodeTypeAccess); ok && string(t.Value) == spiffeconfig.TrustDomainAttribute && isPrincipalVar(t.Arg) {
				found = true
			}
			return !found
		})
	}
	return found
}

// isPrincipalVar reports whether n is the `principal` variable.
func isPrincipalVar(n ast.IsNode) bool {
	v, ok := n.(ast.NodeTypeVariable)
	return ok && v.Name == "principal"
}

// actionEntities calls visit for every Action entity a policy names, in its
// action scope and in any when or unless body.
func actionEntities(ps *cedar.PolicySet, visit func(id cedar.PolicyID, uid types.EntityUID)) {
	check := func(id cedar.PolicyID, uid types.EntityUID) {
		if uid.Type == actionAccess {
			visit(id, uid)
		}
	}
	for id, p := range ps.All() {
		switch sc := p.AST().Action.(type) {
		case ast.ScopeTypeEq:
			check(id, sc.Entity)
		case ast.ScopeTypeIn:
			check(id, sc.Entity)
		case ast.ScopeTypeInSet:
			for _, e := range sc.Entities {
				check(id, e)
			}
		}
		// An Action entity inside a when or unless body, such as
		// `unless { action in Action::"delte-all" }`, is visited the same way.
		for _, c := range p.AST().Conditions {
			ast.Inspect(ast.NewNode(c.Body), func(n ast.IsNode) bool {
				if v, ok := n.(ast.NodeValue); ok {
					switch val := v.Value.(type) {
					case types.EntityUID:
						check(id, val)
					case types.Set:
						for e := range val.All() {
							if uid, ok := e.(types.EntityUID); ok {
								check(id, uid)
							}
						}
					}
				}
				return true
			})
		}
	}
}

// rejectUnknownActionGroups refuses a policy whose action scope names a group
// that is neither shipped nor in config actionGroups. A misspelled group, such as
// "delte-all" in a forbid, would match nothing and silently stop forbidding.
// A name with a "/" is one RPC, which a policy may name even when the image does
// not know it yet, so it is not rejected; warnUnknownRPCs reports a likely typo.
// The action scope and every when or unless body are both checked.
func (g *actionGroups) rejectUnknownActionGroups(ps *cedar.PolicySet) error {
	if g == nil {
		return nil
	}
	var bad []string
	actionEntities(ps, func(id cedar.PolicyID, uid types.EntityUID) {
		name := string(uid.ID)
		if !strings.Contains(name, "/") && !g.knownGroup(name) {
			bad = append(bad, fmt.Sprintf("policy %s: unknown action group %q", id, name))
		}
	})
	if len(bad) == 0 {
		return nil
	}
	sort.Strings(bad)
	return fmt.Errorf("%s; use a shipped group, a name from config actionGroups, or one RPC as \"<Service>/<Method>\"",
		strings.Join(bad, "; "))
}

// warnUnknownRPCs logs a warning for each RPC the policy names that looks like a
// typo: a method the image's own Temporal services do not have. It cannot reject
// them, because a policy may name a new RPC before this image knows it. A
// misspelled name in a forbid would otherwise forbid nothing without any signal.
func (s *policySource) warnUnknownRPCs(ps *cedar.PolicySet) {
	actionEntities(ps, func(id cedar.PolicyID, uid types.EntityUID) {
		if name := string(uid.ID); unknownRPC(name) {
			s.logger.Warn("policy names an RPC this image does not know; a typo here matches nothing",
				tag.NewStringTag("policy", s.kind),
				tag.NewStringTag("policyID", string(id)),
				tag.NewStringTag("action", name))
		}
	})
}

// rejectLegacyPrincipalScopes refuses a policy whose principal scope is
// `== RoleClass::"x"` or `is RoleClass`. The principal is a Workload entity, so
// such a policy never matches: a permit becomes a silent outage and a forbid
// silently stops forbidding. Fail at load with the fix spelled out instead.
func rejectLegacyPrincipalScopes(ps *cedar.PolicySet) error {
	for id, p := range ps.All() {
		var legacy bool
		switch sc := p.AST().Principal.(type) {
		case ast.ScopeTypeEq:
			legacy = sc.Entity.Type == entityRoleClass
		case ast.ScopeTypeIs:
			legacy = sc.Type == entityRoleClass
		case ast.ScopeTypeIsIn:
			legacy = sc.Type == entityRoleClass
		}
		if !legacy {
			legacy = conditionsCompareRoleClass(p.AST().Conditions)
		}
		if legacy {
			return fmt.Errorf("policy %s scopes the principal to a RoleClass with == or is; "+
				"the principal is now a Workload, so use `principal in RoleClass::\"<class>\"`", id)
		}
	}
	return nil
}

// conditionsCompareRoleClass reports whether any when/unless body tests
// equality with a RoleClass entity, or uses `is RoleClass`. Such a test can
// never be true for a Workload principal, so it silently breaks the policy.
// `in RoleClass::"x"` is the supported form and is not flagged.
func conditionsCompareRoleClass(conds []ast.ConditionType) bool {
	isRole := func(n ast.IsNode) bool {
		v, ok := n.(ast.NodeValue)
		if !ok {
			return false
		}
		uid, ok := v.Value.(types.EntityUID)
		return ok && uid.Type == entityRoleClass
	}
	found := false
	for _, c := range conds {
		ast.Inspect(ast.NewNode(c.Body), func(n ast.IsNode) bool {
			switch t := n.(type) {
			case ast.NodeTypeEquals:
				found = found || isRole(t.Left) || isRole(t.Right)
			case ast.NodeTypeNotEquals:
				found = found || isRole(t.Left) || isRole(t.Right)
			case ast.NodeTypeIs:
				found = found || t.EntityType == entityRoleClass
			case ast.NodeTypeIsIn:
				found = found || t.EntityType == entityRoleClass
			}
			return !found
		})
	}
	return found
}

// watch starts the file watcher on the policy's parent directory.
func (s *policySource) watch() error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	// Watch the parent dir, not the file: a ConfigMap update replaces the file
	// via an atomic symlink swap, which a direct file watch misses.
	if err := w.Add(filepath.Dir(s.path)); err != nil {
		_ = w.Close()
		return err
	}
	s.watcher = w
	go s.loop()
	return nil
}

// relevant reports whether a directory event can change the policy: the policy
// file itself, or "..data", the symlink a mounted ConfigMap swaps on update.
func (s *policySource) relevant(ev fsnotify.Event) bool {
	name := filepath.Base(ev.Name)
	return name == filepath.Base(s.path) || name == "..data"
}

// loop reloads the policy after file events stop, until the watcher closes.
func (s *policySource) loop() {
	timer := time.NewTimer(reloadDebounce)
	timer.Stop()
	defer timer.Stop()
	for {
		select {
		case ev, ok := <-s.watcher.Events:
			if !ok {
				return
			}
			if s.relevant(ev) {
				timer.Reset(reloadDebounce)
			}
		case <-timer.C:
			s.reloadAndReport()
		case err, ok := <-s.watcher.Errors:
			if !ok {
				return
			}
			s.logger.Error("cedar policy watcher error", tag.Error(err))
		}
	}
}

// Close stops the file watcher.
func (s *policySource) Close() error {
	if s.watcher != nil {
		return s.watcher.Close()
	}
	return nil
}
