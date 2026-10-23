package authz

import (
	"fmt"
	"os"
	"sync/atomic"

	cedar "github.com/cedar-policy/cedar-go"
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
	s.current.Store(ps)
	return nil
}

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
