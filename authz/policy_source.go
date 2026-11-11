package authz

import (
	"fmt"
	"os"
	"sync/atomic"

	cedar "github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
	"github.com/cedar-policy/cedar-go/x/exp/ast"
	"github.com/fsnotify/fsnotify"
	"go.temporal.io/server/common/log"
	"go.temporal.io/server/common/log/tag"
)

// policySource loads the customer-owned Cedar policy from a file and hot-reloads
// it on change (fsnotify). It fails closed: an absent, unparseable, or
// schema-invalid policy leaves no usable PolicySet, and the authorizer denies.
type policySource struct {
	path   string
	logger log.Logger

	// current holds the last successfully-parsed *cedar.PolicySet, or nil.
	// Read on the hot path with no lock; swapped atomically on reload.
	current atomic.Pointer[cedar.PolicySet]

	watcher *fsnotify.Watcher
}

// newPolicySource loads the policy at path once (which MUST succeed, or the
// server refuses to start) and begins watching it for changes.
func newPolicySource(path string, logger log.Logger) (*policySource, error) {
	s := &policySource{path: path, logger: logger}
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
	s.current.Store(ps)
	return nil
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
	if err := w.Add(dirOf(s.path)); err != nil {
		_ = w.Close()
		return err
	}
	s.watcher = w
	go s.loop()
	return nil
}

// loop reloads the policy on each watcher event until the watcher closes.
func (s *policySource) loop() {
	for {
		select {
		case _, ok := <-s.watcher.Events:
			if !ok {
				return
			}
			if err := s.reload(); err != nil {
				// Keep serving the last good policy; surface the failure loudly.
				s.logger.Error("cedar policy reload failed; keeping previous policy", tag.Error(err))
			} else {
				s.logger.Info("cedar policy reloaded")
			}
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

// dirOf returns the parent directory of path.
func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			if i == 0 {
				return "/"
			}
			return path[:i]
		}
	}
	return "."
}
