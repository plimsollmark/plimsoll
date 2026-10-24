package providerkit

import (
	"errors"
	"fmt"
	"slices"
	"sync"
)

// Quarantine holds the sandboxes a provider is destroying and has not yet confirmed
// gone. Each name keeps a release function, normally the capacity admitted for the call
// that made the sandbox (sandbox.HoldCapacity), which runs only once a destroy confirms
// the sandbox gone. A destroy that fails leaves the name held, and the provider's
// ReconcileOrphans retries it (Retry) on every pass, whatever its age, until one
// succeeds. Nothing reuses a held name meanwhile.
//
// Before it, a docker or OpenShell sandbox whose removal failed gave its capacity back
// at once while it, and whatever the run left running in it, lived on, so the
// concurrency and memory limits stopped bounding what actually ran (review,
// 2026-10-23). agentsandbox already held its capacity this way; this is that table,
// shared.
type Quarantine struct {
	mu      sync.Mutex
	pending map[string]*quarantined
}

type quarantined struct {
	release func()
	busy    bool // a destroy is in progress
}

// Hold records that the caller is destroying name now, and keeps release until a
// destroy confirms it gone. The caller ends its destroy with Done. A nil release holds
// nothing but still keeps the name for Retry. Holding a name already held is a bug in
// the provider: names are unique per sandbox.
func (q *Quarantine) Hold(name string, release func()) {
	if release == nil {
		release = func() {}
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.pending == nil {
		q.pending = map[string]*quarantined{}
	}
	if q.pending[name] != nil {
		panic(fmt.Sprintf("providerkit: %s is already being destroyed", name))
	}
	q.pending[name] = &quarantined{release: release, busy: true}
}

// Begin claims a held name for one destroyer: false when the name is not held or a
// destroy of it is already in progress.
func (q *Quarantine) Begin(name string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	d := q.pending[name]
	if d == nil || d.busy {
		return false
	}
	d.busy = true
	return true
}

// Done ends the destroy Hold or Begin started. Gone runs the release and forgets the
// name; otherwise the name stays held for the next Retry. It returns gone.
func (q *Quarantine) Done(name string, gone bool) bool {
	q.mu.Lock()
	d := q.pending[name]
	if d == nil {
		q.mu.Unlock()
		return gone
	}
	if !gone {
		d.busy = false
		q.mu.Unlock()
		return false
	}
	delete(q.pending, name)
	q.mu.Unlock()
	d.release()
	return true
}

// Destroy runs destroy for name, holding release until it is confirmed gone: at once
// when destroy succeeds, otherwise once a later Retry does. It returns destroy's error.
func (q *Quarantine) Destroy(name string, release func(), destroy func() error) error {
	q.Hold(name, release)
	err := destroy()
	q.Done(name, err == nil)
	return err
}

// DestroyAndWait is Destroy that returns only once name is confirmed gone, which may
// take a Retry: a session's teardown, whose end gives the session's capacity back.
func (q *Quarantine) DestroyAndWait(name string, destroy func() error) {
	gone := make(chan struct{})
	_ = q.Destroy(name, func() { close(gone) }, destroy)
	<-gone
}

// Retry destroys every held name no destroy is working on, and returns how many it
// confirmed gone and why the others are still held.
func (q *Quarantine) Retry(destroy func(name string) error) (int, error) {
	gone := 0
	var errs error
	for _, name := range q.Names() {
		if !q.Begin(name) {
			continue
		}
		err := destroy(name)
		if q.Done(name, err == nil) {
			gone++
		} else {
			errs = errors.Join(errs, fmt.Errorf("%s still held: %w", name, err))
		}
	}
	return gone, errs
}

// Held reports whether name is held.
func (q *Quarantine) Held(name string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.pending[name] != nil
}

// Names lists the held names, sorted.
func (q *Quarantine) Names() []string {
	q.mu.Lock()
	defer q.mu.Unlock()
	names := make([]string, 0, len(q.pending))
	for n := range q.pending {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}
