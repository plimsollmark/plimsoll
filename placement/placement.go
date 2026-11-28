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

	mu       sync.Mutex
	seen     map[string]seen
	inflight map[string]*flight // the describe in progress for each backend, at most one
	order    []string
}

// flight is one describe in progress. done is closed once s holds its answer. waiters
// is how many callers hold it, the one that started it included (under Pool.mu): the
// pool's own account of who shares the describe, which a test reads to know that every
// caller has arrived before it lets the daemon answer.
type flight struct {
	done    chan struct{}
	s       seen
	waiters int
}

type seen struct {
	info client.Info
	at   time.Time // when the daemon was asked, not when it answered (store)
	err  error
	// failed is when err arrived: failedTTL counts from it, since a describe that hung
	// for its whole budget would otherwise be forgotten as soon as it was stored.
	failed time.Time
}

// store keeps s for name unless the pool holds an answer that was asked for later
// (review F12): a slow Refresh that finishes after an on-demand Describe must not put
// its older answer back. The caller holds p.mu.
func (p *Pool) store(name string, s seen) {
	if cur, ok := p.seen[name]; ok && cur.at.After(s.at) {
		return
	}
	p.seen[name] = s
}

// ErrNoBackend means no backend in the pool can take the request. It wraps
// sandbox.ErrUnsupported and is marked not dispatched, because nothing ran.
var ErrNoBackend = errors.New("placement: no backend can take this request")

// ErrEnvironmentMismatch means a backend ran the request and its run record states
// an environment other than the one the requirement named: the Describe answer that
// chose it was stale or wrong. The run happened, so it is unmarked and never retried,
// like the client's isolation evidence check; the result comes back with it.
var ErrEnvironmentMismatch = errors.New("placement: the run's record states another environment than the requirement")

// ErrProviderMismatch is ErrEnvironmentMismatch's twin for Requirement.Provider: a backend
// ran the request and its run record names another provider (a daemon restarted with
// another SANDBOX_PROVIDER since it was described). Unmarked and never retried; the result
// comes back with it.
var ErrProviderMismatch = errors.New("placement: the run's record states another provider than the requirement")

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
	p := &Pool{backends: slices.Clone(backends), ttl: descriptionTTL, seen: map[string]seen{}, inflight: map[string]*flight{}}
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
	// selects from Describe; for a single run it then checks the returned record after
	// dispatch. A session is filtered only: OpenSession picks the daemon by it, and the
	// session's calls are not checked against it afterwards (hunt-quality-42). Use
	// Software when code must be refused before dispatch unless its selected image is
	// approved; a session's open sends that rule, and every call's record is held to it.
	Environment string
	// Software selects the platform image by an exact identity or an approved
	// set. The rule is also sent to the daemon for a pre-dispatch check and is
	// bound to the signed run record. Empty means no software restriction.
	Software sandbox.SoftwareRule
	// GrantProfile says a single run carries a grant, so a backend must support
	// grants for the payload kind. The profile itself lives on each daemon, and the
	// client was configured with its name; this is only the capability check.
	// OpenSession refuses it: a session's calls may be of either kind, so a session
	// names its kinds in SessionGrants.
	GrantProfile bool
	// SessionGrants, for OpenSession only, says which kinds of call in the session
	// carry a grant, so a backend must support grants for each of them. A single run
	// refuses it, since its kind is its method's.
	SessionGrants SessionGrants
	// Prefer ranks the backends that pass the filter; the first is tried first. With
	// no Prefer the pool's own order is used.
	Prefer func(a, b client.Info) int
}

// SessionGrants names the kinds of call in a placed session that carry a grant. A
// daemon states grant support for snippets and for projects separately, and a session
// opened where only the other kind is granted would refuse its granted calls.
type SessionGrants struct {
	// Snippets: the session's RunJavaScript calls carry a grant (the client was made
	// with client.WithJavaScriptGrantProfile).
	Snippets bool
	// Projects: the session's RunProject calls carry a grant (the client was made with
	// client.WithProjectGrantProfile).
	Projects bool
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
// on demand when its description is missing or stale. Each daemon's describe is
// bounded by describeBudget, as an on-demand one is, so one hung daemon holds Refresh
// for at most that long, and a describe already in progress for a backend is waited
// on rather than repeated. It returns the first error, after every answer is recorded,
// so a caller can log a backend that is down without the pool refusing to work. A
// caller whose context ends first gets its own context error, and the describes go on
// and are recorded without it.
func (p *Pool) Refresh(ctx context.Context) error {
	flights := make([]*flight, len(p.backends))
	p.mu.Lock()
	for i, b := range p.backends {
		flights[i] = p.lookup(ctx, b)
	}
	p.mu.Unlock()
	var first error
	for i, b := range p.backends {
		select {
		case <-flights[i].done:
		case <-ctx.Done():
			return fmt.Errorf("placement: refreshing the descriptions: %w", ctx.Err())
		}
		if err := flights[i].s.err; err != nil && first == nil {
			first = fmt.Errorf("placement: describing %s: %w", b.Name, err)
		}
	}
	return first
}

// An on-demand describe is bounded by describeBudget and a failed one is remembered for
// failedTTL, so one hung or down backend costs a request at most describeBudget once,
// not its whole deadline on every request: placement used to describe the candidates
// one after another inside the request's deadline and to forget every failure (review
// B2, 2026-10-23). Describe is a small metadata call, well under a second on any
// working network, so 5 s fails only a daemon that is not answering; 5 s of memory
// keeps a down backend off every request while letting a recovered one back within
// seconds.
const (
	describeBudget = 5 * time.Second
	failedTTL      = 5 * time.Second
)

// Describe returns what a backend last said, describing it when that is missing or
// stale. A failure is returned again, without asking, for failedTTL. A caller whose
// context ends first gets its own context error; the description goes on without it.
func (p *Pool) Describe(ctx context.Context, name string) (client.Info, error) {
	for _, b := range p.backends {
		if b.Name != name {
			continue
		}
		p.mu.Lock()
		s, ok := p.seen[name]
		switch {
		case ok && s.err == nil && time.Since(s.at) < p.ttl:
			p.mu.Unlock()
			return s.info, nil
		case ok && s.err != nil && time.Since(s.failed) < failedTTL:
			p.mu.Unlock()
			return client.Info{}, s.err
		}
		f := p.lookup(ctx, b)
		p.mu.Unlock()
		select {
		case <-f.done:
			return f.s.info, f.s.err
		case <-ctx.Done():
			return client.Info{}, ctx.Err()
		}
	}
	return client.Info{}, fmt.Errorf("placement: no backend named %q", name)
}

// lookup returns the describe of b in progress, starting one when there is none, so
// requests that find one backend stale wait on one answer instead of each asking the
// daemon (hunt-quality-49, 2026-11-20). The caller holds p.mu.
//
// What a describe stores is the daemon's state, read by every caller for failedTTL or
// the time-to-live, so it runs detached from the requesting caller's cancellation and
// is bounded by describeBudget alone: a caller whose deadline passed or whose client
// hung up during a describe used to leave its own "deadline exceeded" stored as the
// daemon's failure, and every caller was refused for failedTTL without the daemon
// being asked (hunt-quality-41, 2026-11-20). Its answer is stored, and the flight
// removed, under one hold of p.mu, so a later describe of the same backend was asked
// after this one answered.
func (p *Pool) lookup(ctx context.Context, b Backend) *flight {
	if f, ok := p.inflight[b.Name]; ok {
		f.waiters++
		return f
	}
	f := &flight{done: make(chan struct{}), waiters: 1}
	p.inflight[b.Name] = f
	go func() {
		asked := time.Now()
		dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), describeBudget)
		info, err := b.Client.Describe(dctx)
		cancel()
		f.s = seen{info: info, at: asked, err: err, failed: time.Now()}
		p.mu.Lock()
		p.store(b.Name, f.s)
		delete(p.inflight, b.Name)
		p.mu.Unlock()
		close(f.done)
	}()
	return f
}

// kind is the payload kind a request needs, as the filter reads it.
type kind int

const (
	kindJavaScript kind = iota
	kindProject
	kindModule
	kindSession // OpenSession: filtered on the session environment Describe states
)

// candidates are the backends that can take a request, in the order to try them.
func (p *Pool) candidates(ctx context.Context, k kind, req Requirement) ([]Backend, error) {
	switch {
	case k == kindSession && req.GrantProfile:
		return nil, sandbox.NotDispatched(sandbox.RefusalRequest, fmt.Errorf("%w: a session's calls may be snippets or projects, "+
			"so OpenSession takes the kinds that carry a grant in SessionGrants, not GrantProfile", sandbox.ErrInvalidRequest))
	case k != kindSession && req.SessionGrants != (SessionGrants{}):
		return nil, sandbox.NotDispatched(sandbox.RefusalRequest, fmt.Errorf("%w: SessionGrants is for OpenSession; "+
			"a single run says it carries a grant with GrantProfile", sandbox.ErrInvalidRequest))
	}
	if req.Backend != "" {
		if !slices.ContainsFunc(p.backends, func(b Backend) bool { return b.Name == req.Backend }) {
			return nil, notDispatched(fmt.Errorf("%w: %w (no backend in the pool is named %q)", ErrNoBackend, sandbox.ErrUnsupported, req.Backend))
		}
	}
	// Every candidate is described at once, so the slowest backend bounds the wait, not
	// the sum of them.
	described := make([]struct {
		info client.Info
		err  error
	}, len(p.backends))
	var wg sync.WaitGroup
	for i, b := range p.backends {
		if req.Backend != "" && b.Name != req.Backend {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			described[i].info, described[i].err = p.Describe(ctx, b.Name)
		}()
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		// The caller gave up while the backends were described: that is its own context
		// error, not a refusal by any backend. Nothing was sent, so it is marked, limit
		// deadline, as sandbox.RefuseGaveUp marks a session call that gave up waiting.
		return nil, sandbox.RefuseDeadline(ctx,
			fmt.Errorf("placement: the caller gave up while the backends were described: %w", err))
	}
	var kept []Backend
	var infos []client.Info
	var why []string
	for i, b := range p.backends {
		if req.Backend != "" && b.Name != req.Backend {
			continue
		}
		info, err := described[i].info, described[i].err
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
	if info.Protocol != client.Protocol {
		// A request on another number is refused before its payload is read, and that
		// refusal is not retried, so one backend on another number blocked the whole
		// pool during a rolling upgrade (review, 2026-10-26).
		return fmt.Sprintf("protocol %d, not %d", info.Protocol, client.Protocol)
	}
	if req.Provider != "" && info.Sandbox != req.Provider {
		return "provider is " + info.Sandbox + ", not " + req.Provider
	}
	env := info.Environments.JavaScript
	switch k {
	case kindSession:
		if !info.SupportsSessions {
			return "no sessions"
		}
		// A session runs every call in its one sandbox, which is not where a single
		// snippet runs on docker: filter on what the daemon states for sessions.
		env = info.SessionEnvironment
		// Each kind the session's calls carry a grant on needs that kind's grants here:
		// either kind alone let a session open where its other kind's calls are refused.
		if req.SessionGrants.Snippets && !info.SupportsJavaScriptGrants {
			return "no snippet grants"
		}
		if req.SessionGrants.Projects && !info.SupportsProjectGrants {
			return "no project grants"
		}
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
// same way anywhere, so it is not retried either (a backend on another protocol
// number is unfit before anything is sent, so a protocol refusal is a daemon that
// changed number since it was described).
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

// recorded is every requirement the filter chooses a backend by that a run record also
// states, with the record's field and the error a difference is: ranIn checks a run
// against each, so a requirement added to the filter and stated by the record is checked
// after the run by adding a row here. The Provider row was missing, and a daemon
// restarted on another provider inside descriptionTTL ran a request filtered for one
// provider on another (hunt-security-27, 2026-11-20).
var recorded = []struct {
	name string
	want func(Requirement) string
	got  func(*sandbox.RunRecord) string
	err  error
}{
	{"environment", func(r Requirement) string { return r.Environment }, func(r *sandbox.RunRecord) string { return r.Environment }, ErrEnvironmentMismatch},
	{"provider", func(r Requirement) string { return r.Provider }, func(r *sandbox.RunRecord) string { return r.Provider }, ErrProviderMismatch},
}

// ranIn checks what a run's record states against the requirement (recorded). The
// filter chose the backend from a Describe answer up to descriptionTTL old; the record
// is the daemon's statement about this run.
func ranIn(rec *sandbox.RunRecord, req Requirement) error {
	var errs []error
	for _, c := range recorded {
		want := c.want(req)
		if want == "" {
			continue
		}
		got := ""
		if rec != nil {
			got = c.got(rec)
		}
		if got != want {
			if got == "" {
				got = "none stated"
			}
			errs = append(errs, fmt.Errorf("%w: its %s is %s, not %s; execution has occurred", c.err, c.name, got, want))
		}
	}
	return errors.Join(errs...)
}

// ranAs adds ranIn's verdict to a run's error. It applies to a run that succeeded and
// to one that executed but whose Recorder failed (client.ErrNotRecorded), which still
// carries its checked record: a failing recorder must not hide where the run went.
func ranAs(rec *sandbox.RunRecord, req Requirement, err error) error {
	if err != nil && !errors.Is(err, client.ErrNotRecorded) {
		return err
	}
	if e := ranIn(rec, req); e != nil {
		return errors.Join(e, err)
	}
	return err
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
		return res, ranAs(res.Record, req, err)
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
		return res, ranAs(res.Record, req, err)
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
		return res, ranAs(res.Record, req, err)
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
	backends, err := p.candidates(ctx, kindSession, req)
	if err != nil {
		return nil, Choice{}, err
	}
	return send(ctx, backends, func(ctx context.Context, b Backend) (*client.Session, error) {
		return b.Client.OpenSession(ctx, opts)
	})
}
