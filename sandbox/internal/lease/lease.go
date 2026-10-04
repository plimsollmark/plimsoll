// Package lease records what a provider asked a remote service to create and has not
// yet seen deleted, so orphan reconciliation never races a create.
//
// Every provider that creates sandboxes outside this process follows one rule. A key
// naming the resource is tracked before the create request is sent, and the resource is
// stamped with this instance's identity (and, where the name is not the key, the key);
// the key is untracked once the delete has finished or given up. ReconcileOrphans then
// reaps exactly what carries this instance's stamp and no tracked key: a create whose
// answer never arrived, a teardown whose retries all failed. No age window is needed,
// because nothing in flight is untracked. What other instances left is reaped by the
// lifetime its creator declared, never through this set.
package lease

import "sync"

// Set is the keys of one provider instance's resources in flight. The zero value is
// empty and ready to use.
type Set struct {
	mu   sync.Mutex
	keys map[string]struct{}
}

// Track records key; call it before the create request is sent.
func (s *Set) Track(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.keys == nil {
		s.keys = map[string]struct{}{}
	}
	s.keys[key] = struct{}{}
}

// Untrack forgets key; call it once the delete has finished or given up, whatever
// happened, so a resource that outlived it is reconciliation's.
func (s *Set) Untrack(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.keys, key)
}

// Tracked reports whether key is in flight.
func (s *Set) Tracked(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.keys[key]
	return ok
}

// Len is how many keys are in flight.
func (s *Set) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.keys)
}
