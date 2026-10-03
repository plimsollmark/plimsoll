package sandbox

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// ErrAtCapacity is returned when an admission budget sheds a run rather than
// admitting it. It is a load-shed signal (retry later), NOT an infrastructure fault:
// callers should surface it as a "busy/try again" condition.
var ErrAtCapacity = errors.New("sandbox admission: at capacity, retry shortly")

// AdmissionConfig bounds how many runs — and how much run memory — may be in flight
// through a wrapped provider at once. A zero field disables that dimension.
type AdmissionConfig struct {
	// MaxConcurrent caps total in-flight runs. 0 = no concurrency cap.
	MaxConcurrent int
	// TotalMemoryMB caps the aggregate memory reserved by in-flight runs. A count is
	// not a resource budget — 100 concurrent × 256 MiB will exhaust any host — so this
	// bounds concurrent × PerRunMemoryMB. 0 = no memory budget.
	TotalMemoryMB int
	// PerRunMemoryMB is what one run is charged against TotalMemoryMB (the per-run
	// envelope, e.g. 256 for the wasm/docker defaults). Required when TotalMemoryMB is
	// set; ignored otherwise.
	PerRunMemoryMB int
}

// admissionSandbox wraps a Sandbox with concurrency + aggregate-memory admission.
// Unlike the RPC-layer limiter (one per plimsolld process, off for every in-process
// consumer), this lives at the sandbox boundary so ANY embedder — in-process,
// client-remote, or the daemon — gets the same fleet-wide budget by wrapping its
// provider once. It sheds load (never queues) with ErrAtCapacity so a flood cannot
// pile up goroutines, containers, or 256-MiB wazero runtimes.
type admissionSandbox struct {
	Sandbox
	sem chan struct{} // global concurrency; nil = no cap

	mu       sync.Mutex
	memInUse int                      // MiB reserved by in-flight runs and the session pool
	memCap   int                      // TotalMemoryMB; 0 = no memory budget
	perRun   int                      // PerRunMemoryMB charged per admitted run
	pools    map[*poolCharge]struct{} // session pool reservations not yet given back
}

// poolCharge is one StartSessionPool call's reservation against the memory budget.
// It is given back once, by whichever removes it from pools first: that call's
// failure, or a Drain that has stopped the pool. A Drain can finish while the start is
// still inside the provider, which then refuses it, so neither may assume the other
// has not run.
type poolCharge struct{ mib int }

// releasePool gives c back if it is still held. a.mu must be held.
func (a *admissionSandbox) releasePool(c *poolCharge) {
	if _, held := a.pools[c]; held {
		delete(a.pools, c)
		a.memInUse -= c.mib
	}
}

// WithAdmission wraps inner so every run passes a shared admission budget first. A
// config with no active dimension returns inner unchanged (no wrapper overhead).
// Invalid safety configuration is an error rather than silently disabling a limit.
func WithAdmission(inner Sandbox, cfg AdmissionConfig) (Sandbox, error) {
	if inner == nil {
		return nil, errors.New("sandbox admission: inner sandbox is nil")
	}
	if cfg.MaxConcurrent < 0 || cfg.TotalMemoryMB < 0 || cfg.PerRunMemoryMB < 0 {
		return nil, errors.New("sandbox admission: limits cannot be negative")
	}
	if (cfg.TotalMemoryMB == 0) != (cfg.PerRunMemoryMB == 0) {
		return nil, errors.New("sandbox admission: TotalMemoryMB and PerRunMemoryMB must be set together")
	}
	if cfg.TotalMemoryMB > 0 && cfg.PerRunMemoryMB > cfg.TotalMemoryMB {
		return nil, fmt.Errorf("sandbox admission: one run needs %d MiB but the total budget is %d MiB", cfg.PerRunMemoryMB, cfg.TotalMemoryMB)
	}
	memBudget := cfg.TotalMemoryMB > 0
	if cfg.MaxConcurrent <= 0 && !memBudget {
		return inner, nil
	}
	a := &admissionSandbox{Sandbox: inner}
	if cfg.MaxConcurrent > 0 {
		a.sem = make(chan struct{}, cfg.MaxConcurrent)
	}
	if memBudget {
		a.memCap = cfg.TotalMemoryMB
		a.perRun = cfg.PerRunMemoryMB
	}
	if g, ok := inner.(EgressGuardCapable); ok {
		return &admissionGuardSandbox{admissionSandbox: a, guard: g}, nil
	}
	return a, nil
}

// acquire reserves a concurrency slot and a memory reservation, or returns
// ErrAtCapacity having reserved nothing. The returned release undoes both exactly
// once.
func (a *admissionSandbox) acquire() (func(), error) {
	if a.sem != nil {
		select {
		case a.sem <- struct{}{}:
		default:
			return nil, refused(ErrAtCapacity)
		}
	}
	if a.memCap > 0 {
		a.mu.Lock()
		if a.memInUse+a.perRun > a.memCap {
			a.mu.Unlock()
			if a.sem != nil {
				<-a.sem
			}
			return nil, refused(ErrAtCapacity)
		}
		a.memInUse += a.perRun
		a.mu.Unlock()
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			if a.memCap > 0 {
				a.mu.Lock()
				a.memInUse -= a.perRun
				a.mu.Unlock()
			}
			if a.sem != nil {
				<-a.sem
			}
		})
	}, nil
}

func (a *admissionSandbox) RunJavaScript(ctx context.Context, req Request) (Result, error) {
	if err := a.checkMinimumIsolation(ctx, req.MinimumIsolation); err != nil {
		return Result{Sandbox: a.Name(), Isolation: a.IsolationClass()}, err
	}
	release, err := a.acquire()
	if err != nil {
		return Result{Sandbox: a.Name()}, err
	}
	defer release()
	return a.Sandbox.RunJavaScript(ctx, req)
}

func (a *admissionSandbox) RunProject(ctx context.Context, req ProjectRequest) (ProjectResult, error) {
	if err := a.checkMinimumIsolation(ctx, req.MinimumIsolation); err != nil {
		return ProjectResult{Sandbox: a.Name(), Isolation: a.IsolationClass()}, err
	}
	release, err := a.acquire()
	if err != nil {
		return ProjectResult{Sandbox: a.Name()}, err
	}
	defer release()
	return a.Sandbox.RunProject(ctx, req)
}

func (a *admissionSandbox) RunModule(ctx context.Context, req ModuleRequest) (ModuleResult, error) {
	if err := a.checkMinimumIsolation(ctx, req.MinimumIsolation); err != nil {
		return ModuleResult{Sandbox: a.Name(), Isolation: a.IsolationClass()}, err
	}
	release, err := a.acquire()
	if err != nil {
		return ModuleResult{Sandbox: a.Name()}, err
	}
	defer release()
	return a.Sandbox.RunModule(ctx, req)
}

// checkMinimumIsolation keeps deterministic security preconditions ahead of
// capacity admission. Providers still re-check the exact boundary they snapshot
// for dispatch (especially Docker); this early check prevents an impossible floor
// from consuming a semaphore or memory reservation. Unknown remote tiers pass
// through because only the remote server can enforce them atomically.
func (a *admissionSandbox) checkMinimumIsolation(ctx context.Context, minimum IsolationClass) error {
	if err := validateMinimumIsolation(minimum); err != nil {
		return refused(err)
	}
	if minimum == IsolationUnknown {
		return nil
	}
	actual := a.Sandbox.IsolationClass()
	if actual == IsolationUnknown || actual.Meets(minimum) {
		return nil
	}
	// Docker's conservative pre-Preflight report is container-tier even when it
	// is configured for runsc. Let a provider establish fresh evidence before
	// deciding that the requested floor is impossible.
	if pf, ok := a.Sandbox.(Preflighter); ok {
		if err := pf.Preflight(ctx); err != nil {
			return err
		}
		actual = a.Sandbox.IsolationClass()
		if actual == IsolationUnknown {
			return nil
		}
	}
	return CheckMinimumIsolation(actual, minimum)
}

// SupportsProjects forwards the wrapped provider's static capability so the decorator
// is transparent to a caller inspecting ProjectCapable.
func (a *admissionSandbox) SupportsProjects() bool {
	if pc, ok := a.Sandbox.(ProjectCapable); ok {
		return pc.SupportsProjects()
	}
	return false
}

// Environments forwards the wrapped provider's statement; a provider that makes
// none states nothing through the decorator either.
func (a *admissionSandbox) Environments() Environments {
	if d, ok := a.Sandbox.(Describer); ok {
		return d.Environments()
	}
	return Environments{}
}

// SupportsModules forwards the wrapped provider's static capability, like
// SupportsProjects.
func (a *admissionSandbox) SupportsModules() bool {
	if mc, ok := a.Sandbox.(ModuleCapable); ok {
		return mc.SupportsModules()
	}
	return false
}

func (a *admissionSandbox) SupportsJavaScriptGrants() bool {
	if gc, ok := a.Sandbox.(GrantCapable); ok {
		return gc.SupportsJavaScriptGrants()
	}
	return false
}

func (a *admissionSandbox) SupportsProjectGrants() bool {
	if gc, ok := a.Sandbox.(GrantCapable); ok {
		return gc.SupportsProjectGrants()
	}
	return false
}

// Preflight forwards to the wrapped provider so readiness checks still work through
// the decorator.
func (a *admissionSandbox) Preflight(ctx context.Context) error {
	if pf, ok := a.Sandbox.(Preflighter); ok {
		return pf.Preflight(ctx)
	}
	return nil
}

// The decorator must stay transparent to every optional interface the rest of
// plimsoll finds by type assertion; TestAdmissionForwardsEveryOptionalInterface
// fails when one is added to the package without being classified there. Losing
// SmokeTester, for instance, would make EnsureReady report ready without its
// behavioral proof.
var (
	_ ProjectCapable     = (*admissionSandbox)(nil)
	_ ModuleCapable      = (*admissionSandbox)(nil)
	_ GrantCapable       = (*admissionSandbox)(nil)
	_ Describer          = (*admissionSandbox)(nil)
	_ Preflighter        = (*admissionSandbox)(nil)
	_ SmokeTester        = (*admissionSandbox)(nil)
	_ OrphanReconciler   = (*admissionSandbox)(nil)
	_ Drainer            = (*admissionSandbox)(nil)
	_ SessionProvider    = (*admissionSandbox)(nil)
	_ SessionPool        = (*admissionSandbox)(nil)
	_ EgressGuardCapable = (*admissionGuardSandbox)(nil)
)

// SmokeTest forwards to the wrapped provider. A provider without one has no smoke
// test through the decorator either, which is what EnsureReady does unwrapped.
func (a *admissionSandbox) SmokeTest(ctx context.Context) error {
	if st, ok := a.Sandbox.(SmokeTester); ok {
		return st.SmokeTest(ctx)
	}
	return nil
}

// ReconcileOrphans forwards to the wrapped provider; one without off-process
// resources has none to reap.
func (a *admissionSandbox) ReconcileOrphans(ctx context.Context) (int, error) {
	if r, ok := a.Sandbox.(OrphanReconciler); ok {
		return r.ReconcileOrphans(ctx)
	}
	return 0, nil
}

// Drain forwards to the wrapped provider; one that leaves no work behind a run has
// nothing to wait for. The session pool's reservations are given back once the
// provider has drained, since its Drain stops the pool and refuses a start that has not
// installed one; a start that fails afterwards finds its reservation already given back.
func (a *admissionSandbox) Drain(ctx context.Context) error {
	if d, ok := a.Sandbox.(Drainer); ok {
		if err := d.Drain(ctx); err != nil {
			return err
		}
	}
	a.mu.Lock()
	for c := range a.pools {
		a.releasePool(c)
	}
	a.mu.Unlock()
	return nil
}

// SupportsSessions forwards the wrapped provider's answer; callers check it, not the
// method's presence, so a provider without sessions has none through the decorator.
func (a *admissionSandbox) SupportsSessions() bool {
	sp, ok := a.Sandbox.(SessionProvider)
	return ok && sp.SupportsSessions()
}

// SessionEnvironments forwards the wrapped provider's.
func (a *admissionSandbox) SessionEnvironments() Environments {
	if sp, ok := a.Sandbox.(SessionProvider); ok {
		return sp.SessionEnvironments()
	}
	return Environments{}
}

// StartSessionPool forwards to the wrapped provider; one without a pool refuses
// (ErrUnsupported), so a daemon configured for a pool fails at startup. A waiting
// member holds memory (its container's limit is one run's) but no concurrency slot,
// so the pool is charged size runs against TotalMemoryMB for as long as it runs: the
// pool refills a claimed member, so size is always what waits. OpenSession reserves a
// claimed member's session as it does any session.
func (a *admissionSandbox) StartSessionPool(ctx context.Context, size int, lifetime time.Duration) error {
	p, ok := a.Sandbox.(SessionPool)
	if !ok {
		return fmt.Errorf("%w: provider %s keeps no session pool", ErrUnsupported, a.Name())
	}
	var c *poolCharge
	if a.memCap > 0 && size > 0 {
		c = &poolCharge{mib: size * a.perRun}
		a.mu.Lock()
		if free := a.memCap - a.memInUse; c.mib > free {
			a.mu.Unlock()
			return fmt.Errorf("sandbox admission: a session pool of %d holds %d MiB, more than the %d MiB of the memory budget not in use", size, c.mib, free)
		}
		if a.pools == nil {
			a.pools = map[*poolCharge]struct{}{}
		}
		a.pools[c] = struct{}{}
		a.memInUse += c.mib
		a.mu.Unlock()
	}
	if err := p.StartSessionPool(ctx, size, lifetime); err != nil {
		if c != nil {
			a.mu.Lock()
			a.releasePool(c)
			a.mu.Unlock()
		}
		return err
	}
	return nil
}

// OpenSession admits a session as it admits a run, and keeps the reservation until
// the session has ended: its sandbox holds memory between calls as well as during
// them.
func (a *admissionSandbox) OpenSession(ctx context.Context, opts SessionOptions) (Session, error) {
	sp, ok := a.Sandbox.(SessionProvider)
	if !ok || !sp.SupportsSessions() {
		return nil, NotDispatched(RefusalUnsupported, fmt.Errorf("%w: the wrapped provider keeps no sessions", ErrUnsupported))
	}
	if err := a.checkMinimumIsolation(ctx, opts.MinimumIsolation); err != nil {
		return nil, err
	}
	release, err := a.acquire()
	if err != nil {
		return nil, err
	}
	s, err := sp.OpenSession(ctx, opts)
	if err != nil {
		release()
		return nil, err
	}
	go func() {
		<-s.Done()
		release()
	}()
	return s, nil
}

// admissionGuardSandbox is the decorator around a provider that exposes an egress
// guard. It is a separate type because an embedder mounts the guard when the type
// assertion succeeds, so the plain decorator must not claim one it cannot serve.
type admissionGuardSandbox struct {
	*admissionSandbox
	guard EgressGuardCapable
}

func (a *admissionGuardSandbox) EgressGuardPath() string { return a.guard.EgressGuardPath() }

func (a *admissionGuardSandbox) EgressGuardKnownToken(token string) bool {
	return a.guard.EgressGuardKnownToken(token)
}

func (a *admissionGuardSandbox) EgressGuardCall(ctx context.Context, token, method, rawTarget string, body []byte) EgressGuardResponse {
	return a.guard.EgressGuardCall(ctx, token, method, rawTarget, body)
}
