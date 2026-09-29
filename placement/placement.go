// Package placement chooses which plimsoll daemon runs a request, and sends it
// there. It is a library a caller links, not a service. The daemon checks the
// selected software rule before dispatch; each daemon still serves one provider
// with its own credentials in its own process, which is the reason plimsoll has no multi-provider daemon
// (docs/seams.md).
//
// What it does, in order, for every request:
//
//   - Filter by what the daemons state: the payload kind, isolation floor,
//     grant support and, when asked, the selected software identity. The
//     request carries the software rule so the daemon checks it before dispatch.
//   - Rank what is left by the caller's preference, which defaults to the order
//     the daemons were given.
//   - Send, and retry on another daemon only when the refusal proves nothing ran
//     (the not-dispatched mark with reason unsupported, isolation, environment or
//     capacity). An
//     error without that mark may have executed and is never re-sent.
//
// Each daemon keeps the caller's own credential: a Pool is built from clients the
// caller created, so a profile's allowed_callers and a minted token's subject stay
// the caller's identity, not the router's.
package placement

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/plimsollmark/plimsoll/client"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// Backend is one daemon the router may use.
type Backend struct {
	// Name identifies the backend in errors and in a Choice; it is the caller's
	// label, not anything the daemon states. Required and unique in a Pool.
	Name string
	// Client is the caller's own client for that daemon, with the caller's
	// credential and grant profiles already configured.
	Client *client.Remote
}

// Pool is a set of backends and the description each one last gave. It is safe for
// concurrent use; its descriptions are refreshed by Refresh, never by a run.
type Pool struct {
	backends []Backend
	ttl      time.Duration

	mu    sync.Mutex
	seen  map[string]seen
	order []string
}

type seen struct {
	info client.Info
	at   time.Time
	err  error
}

// ErrNoBackend means no backend in the pool can take the request. It wraps
// sandbox.ErrUnsupported and is marked not dispatched, because nothing ran.
var ErrNoBackend = errors.New("placement: no backend can take this request")

// ErrEnvironmentMismatch means a backend ran the request and its run record states
// an environment other than the one the requirement named: the Describe answer that
// chose it was stale or wrong. The run happened, so it is unmarked and never retried,
// like the client's isolation evidence check; the result comes back with it.
var ErrEnvironmentMismatch = errors.New("placement: the run's record states another environment than the requirement")

// New returns a pool over backends. descriptionTTL is how long a daemon's
// Describe answer is reused; 0 means a minute. A backend whose description is
// missing or stale is described again when the next request needs it, so a daemon
// that was down is picked up without restarting the caller.
func New(backends []Backend, descriptionTTL time.Duration) (*Pool, error) {
	if len(backends) == 0 {
		return nil, errors.New("placement: a pool needs at least one backend")
	}
	if descriptionTTL <= 0 {
		descriptionTTL = time.Minute
	}
	names := make(map[string]struct{}, len(backends))
	for _, b := range backends {
		switch {
		case strings.TrimSpace(b.Name) == "":
			return nil, errors.New("placement: every backend needs a name")
		case b.Client == nil:
			return nil, fmt.Errorf("placement: backend %q has no client", b.Name)
		}
		if _, dup := names[b.Name]; dup {
			return nil, fmt.Errorf("placement: two backends are named %q", b.Name)
		}
		names[b.Name] = struct{}{}
	}
	p := &Pool{backends: slices.Clone(backends), ttl: descriptionTTL, seen: map[string]seen{}}
	for _, b := range backends {
		p.order = append(p.order, b.Name)
	}
	return p, nil
}

// Requirement is what a request needs of a backend, beyond the request itself.
type Requirement struct {
	// Backend names the one backend to use. The others are not considered, and a
	// backend that cannot take the request is an error rather than a fallback: the
	// caller asked for this one.
	Backend string
	// Provider, when set, keeps only backends whose Describe reports this provider
	// id ("docker", "e2b", "openshell", ...).
	Provider string
	// MinimumIsolation is the floor. The router merges it with the payload's own
	// floor (the stronger wins), keeps only backends whose evidence meets it, and
	// stamps it onto the payload, so the daemon checks it again before dispatch and
	// the client checks the returned evidence against it.
	MinimumIsolation sandbox.IsolationClass
	// Environment filters by the exact outer image or interpreter identity. Placement
	// selects from Describe, then checks the returned record after dispatch; use Software
	// when code must be refused before dispatch unless its selected image is approved.
	Environment string
	// Software selects the platform image by an exact identity or an approved
	// set. The rule is also sent to the daemon for a pre-dispatch check and is
	// bound to the signed run record. Empty means no software restriction.
	Software sandbox.SoftwareRule
	// GrantProfile says the request carries a grant, so a backend must support
	// grants for the payload kind. The profile itself lives on each daemon, and the
	// client was configured with its name; this is only the capability check.
	GrantProfile bool
	// Prefer ranks the backends that pass the filter; the first is tried first. With
	// no Prefer the pool's own order is used.
	Prefer func(a, b client.Info) int
}

// Choice is where a request ran, and what was tried before it.
type Choice struct {
	Backend string
	// Retried lists the backends that refused before this one, each with the reason
	// the refusal carried, in order. Empty when the first backend took the request.
	Retried []Refusal
}

// Refusal is one backend's refusal that provably ran nothing.
type Refusal struct {
	Backend string
	Reason  sandbox.Refusal
	Err     error
}

func (r Refusal) String() string { return r.Backend + ": " + r.Reason.String() }

// Refresh describes every backend, in parallel, and records what each said. A
// caller may run it at startup and on a timer; the pool also describes a backend
// on demand when its description is missing or stale. It returns the first error,
// after recording every answer, so a caller can log a backend that is down without
// the pool refusing to work.
func (p *Pool) Refresh(ctx context.Context) error {
	var wg sync.WaitGroup
	results := make([]seen, len(p.backends))
	for i, b := range p.backends {
		wg.Add(1)
		go func() {
			defer wg.Done()
			info, err := b.Client.Describe(ctx)
			results[i] = seen{info: info, at: time.Now(), err: err}
		}()
	}
	wg.Wait()
	var first error
	p.mu.Lock()
	for i, b := range p.backends {
		p.seen[b.Name] = results[i]
		if results[i].err != nil && first == nil {
			first = fmt.Errorf("placement: describing %s: %w", b.Name, results[i].err)
		}
	}
	p.mu.Unlock()
	return first
}

// Describe returns what a backend last said, describing it when that is missing or
// stale.
func (p *Pool) Describe(ctx context.Context, name string) (client.Info, error) {
	for _, b := range p.backends {
		if b.Name != name {
			continue
		}
		p.mu.Lock()
		s, ok := p.seen[name]
		p.mu.Unlock()
		if ok && s.err == nil && time.Since(s.at) < p.ttl {
			return s.info, nil
		}
		info, err := b.Client.Describe(ctx)
		p.mu.Lock()
		p.seen[name] = seen{info: info, at: time.Now(), err: err}
		p.mu.Unlock()
		return info, err
	}
	return client.Info{}, fmt.Errorf("placement: no backend named %q", name)
}

// kind is the payload kind a request needs, as the filter reads it.
type kind int

const (
	kindJavaScript kind = iota
	kindProject
	kindModule
)

// candidates are the backends that can take a request, in the order to try them.
func (p *Pool) candidates(ctx context.Context, k kind, req Requirement) ([]Backend, error) {
	var kept []Backend
	var infos []client.Info
	var why []string
	for _, b := range p.backends {
		if req.Backend != "" && b.Name != req.Backend {
			continue
		}
		info, err := p.Describe(ctx, b.Name)
		if err != nil {
			why = append(why, b.Name+": "+err.Error())
			continue
		}
		if reason := unfit(info, k, req); reason != "" {
			why = append(why, b.Name+": "+reason)
			continue
		}
		kept = append(kept, b)
		infos = append(infos, info)
	}
	if len(kept) == 0 {
		return nil, notDispatched(fmt.Errorf("%w: %w (%s)", ErrNoBackend, sandbox.ErrUnsupported, strings.Join(why, "; ")))
	}
	if req.Prefer != nil {
		idx := make([]int, len(kept))
		for i := range idx {
			idx[i] = i
		}
		slices.SortStableFunc(idx, func(a, b int) int { return req.Prefer(infos[a], infos[b]) })
		ranked := make([]Backend, len(kept))
		for i, j := range idx {
			ranked[i] = kept[j]
		}
		kept = ranked
	}
	return kept, nil
}

// unfit says why a backend cannot take the request, or "" when it can.
func unfit(info client.Info, k kind, req Requirement) string {
	if req.Provider != "" && info.Sandbox != req.Provider {
		return "provider is " + info.Sandbox + ", not " + req.Provider
	}
	env := info.Environments.JavaScript
	switch k {
	case kindProject:
		if !info.SupportsProject {
			return "no project support"
		}
		env = info.Environments.Project
		if req.GrantProfile && !info.SupportsProjectGrants {
			return "no project grants"
		}
	case kindModule:
		if !info.SupportsModule {
			return "no module support"
		}
		env = info.Environments.Module
		if req.GrantProfile {
			return "a module run cannot carry a grant"
		}
	default:
		if req.GrantProfile && !info.SupportsJavaScriptGrants {
			return "no snippet grants"
		}
	}
	if err := sandbox.CheckMinimumIsolation(info.Isolation, req.MinimumIsolation); err != nil {
		return "isolation is " + info.Isolation.String() + ", below " + req.MinimumIsolation.String()
	}
	if req.Environment != "" && env.Identity != req.Environment {
		got := env.Identity
		if got == "" {
			got = "none stated"
		}
		return "environment is " + got + ", not " + req.Environment
	}
	if !req.Software.Allows(env.SoftwareIdentity) {
		return "selected software is outside the approved rule"
	}
	return ""
}

// floor merges the requirement's floor with the one the payload carries. Both are
// lower bounds, so the effective floor is the stronger; an invalid one is refused
// rather than outvoted. The result both chooses the backend and rides on the
// payload: a backend whose tier dropped after its last Describe then refuses before
// dispatch, or its answer fails the client's evidence check, instead of running the
// request below the floor the caller placed it with.
func floor(req *Requirement, payload *sandbox.IsolationClass) error {
	for _, c := range []sandbox.IsolationClass{req.MinimumIsolation, *payload} {
		if c != sandbox.IsolationUnknown && !c.Meets(sandbox.IsolationProcess) {
			return sandbox.NotDispatched(sandbox.RefusalRequest,
				fmt.Errorf("%w: minimum isolation %s is not process, container, kernel or vm", sandbox.ErrInvalidRequest, c))
		}
	}
	if *payload > req.MinimumIsolation {
		req.MinimumIsolation = *payload
	}
	*payload = req.MinimumIsolation
	return nil
}

// notDispatched marks an error the router itself raised, which ran nothing.
func notDispatched(err error) error {
	return sandbox.NotDispatched(sandbox.RefusalUnsupported, err)
}

// retryable reports whether a refusal proves nothing ran and another backend may
// take the same request. A mark of request, permission or protocol would fail the
// same way anywhere, so it is not retried either.
func retryable(err error) (sandbox.Refusal, bool) {
	reason, marked := sandbox.NotDispatchedReason(err)
	if !marked {
		return reason, false
	}
	switch reason {
	case sandbox.RefusalUnsupported, sandbox.RefusalIsolation, sandbox.RefusalCapacity, sandbox.RefusalEnvironment:
		return reason, true
	default:
		return reason, false
	}
}

// ranIn checks what a run's record states against the requirement's environment.
// The filter chose the backend from a Describe answer up to descriptionTTL old; the
// record is the daemon's statement about this run.
func ranIn(rec *sandbox.RunRecord, want string) error {
	if want == "" {
		return nil
	}
	if rec == nil || rec.Environment != want {
		got := "none stated"
		if rec != nil && rec.Environment != "" {
			got = rec.Environment
		}
		return fmt.Errorf("%w: it ran in %s, not %s; execution has occurred", ErrEnvironmentMismatch, got, want)
	}
	return nil
}

// send tries each candidate in turn, and returns the first answer that is not a
// refusal proving nothing ran. run reports whether its own error is retryable in
// the same way, so a caller-side check (an isolation evidence mismatch) is never
// retried.
func send[T any](ctx context.Context, backends []Backend, run func(context.Context, Backend) (T, error)) (T, Choice, error) {
	var zero T
	choice := Choice{}
	for i, b := range backends {
		res, err := run(ctx, b)
		if err == nil {
			choice.Backend = b.Name
			return res, choice, nil
		}
		reason, again := retryable(err)
		if !again || i == len(backends)-1 || ctx.Err() != nil {
			choice.Backend = b.Name
			return res, choice, err
		}
		choice.Retried = append(choice.Retried, Refusal{Backend: b.Name, Reason: reason, Err: err})
	}
	// Every caller passes at least one backend (candidates refuses an empty pool), and
	// the loop returns on the last one, so this is reached only by an empty list.
	return zero, choice, notDispatched(fmt.Errorf("%w: %w (no candidate)", ErrNoBackend, sandbox.ErrUnsupported))
}

// RunJavaScript places one snippet and runs it.
func (p *Pool) RunJavaScript(ctx context.Context, in sandbox.Request, req Requirement) (sandbox.Result, Choice, error) {
	if err := floor(&req, &in.MinimumIsolation); err != nil {
		return sandbox.Result{}, Choice{}, err
	}
	var err error
	req.Software, err = sandbox.MergeSoftwareRules(in.Software, req.Software)
	if err != nil {
		return sandbox.Result{}, Choice{}, err
	}
	in.Software = req.Software
	backends, err := p.candidates(ctx, kindJavaScript, req)
	if err != nil {
		return sandbox.Result{}, Choice{}, err
	}
	return send(ctx, backends, func(ctx context.Context, b Backend) (sandbox.Result, error) {
		res, err := b.Client.RunJavaScript(ctx, in)
		if err == nil {
			err = ranIn(res.Record, req.Environment)
		}
		return res, err
	})
}

// RunProject places one project and runs it.
func (p *Pool) RunProject(ctx context.Context, in sandbox.ProjectRequest, req Requirement) (sandbox.ProjectResult, Choice, error) {
	if err := floor(&req, &in.MinimumIsolation); err != nil {
		return sandbox.ProjectResult{}, Choice{}, err
	}
	var err error
	req.Software, err = sandbox.MergeSoftwareRules(in.Software, req.Software)
	if err != nil {
		return sandbox.ProjectResult{}, Choice{}, err
	}
	in.Software = req.Software
	backends, err := p.candidates(ctx, kindProject, req)
	if err != nil {
		return sandbox.ProjectResult{}, Choice{}, err
	}
	return send(ctx, backends, func(ctx context.Context, b Backend) (sandbox.ProjectResult, error) {
		res, err := b.Client.RunProject(ctx, in)
		if err == nil {
			err = ranIn(res.Record, req.Environment)
		}
		return res, err
	})
}

// RunModule places one module run.
func (p *Pool) RunModule(ctx context.Context, in sandbox.ModuleRequest, req Requirement) (sandbox.ModuleResult, Choice, error) {
	if err := floor(&req, &in.MinimumIsolation); err != nil {
		return sandbox.ModuleResult{}, Choice{}, err
	}
	var err error
	req.Software, err = sandbox.MergeSoftwareRules(in.Software, req.Software)
	if err != nil {
		return sandbox.ModuleResult{}, Choice{}, err
	}
	in.Software = req.Software
	backends, err := p.candidates(ctx, kindModule, req)
	if err != nil {
		return sandbox.ModuleResult{}, Choice{}, err
	}
	return send(ctx, backends, func(ctx context.Context, b Backend) (sandbox.ModuleResult, error) {
		res, err := b.Client.RunModule(ctx, in)
		if err == nil {
			err = ranIn(res.Record, req.Environment)
		}
		return res, err
	})
}

// OpenSession places a session: a session lives on one daemon, so the choice is
// made once, at open, and every call goes to that daemon.
func (p *Pool) OpenSession(ctx context.Context, opts client.SessionOptions, req Requirement) (*client.Session, Choice, error) {
	if err := floor(&req, &opts.MinimumIsolation); err != nil {
		return nil, Choice{}, err
	}
	var err error
	req.Software, err = sandbox.MergeSoftwareRules(opts.Software, req.Software)
	if err != nil {
		return nil, Choice{}, err
	}
	opts.Software = req.Software
	backends, err := p.candidates(ctx, kindJavaScript, req)
	if err != nil {
		return nil, Choice{}, err
	}
	var usable []Backend
	var why []string
	for _, b := range backends {
		info, err := p.Describe(ctx, b.Name)
		if err != nil || !info.SupportsSessions {
			why = append(why, b.Name+": no sessions")
			continue
		}
		usable = append(usable, b)
	}
	if len(usable) == 0 {
		return nil, Choice{}, notDispatched(fmt.Errorf("%w: %w (%s)", ErrNoBackend, sandbox.ErrUnsupported, strings.Join(why, "; ")))
	}
	return send(ctx, usable, func(ctx context.Context, b Backend) (*client.Session, error) {
		return b.Client.OpenSession(ctx, opts)
	})
}
