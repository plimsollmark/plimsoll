package sandbox

import (
	"context"
	"errors"
	"fmt"
	"sync"
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
	memInUse int // MiB reserved by in-flight runs
	memCap   int // TotalMemoryMB; 0 = no memory budget
	perRun   int // PerRunMemoryMB charged per admitted run
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
			return nil, ErrAtCapacity
		}
	}
	if a.memCap > 0 {
		a.mu.Lock()
		if a.memInUse+a.perRun > a.memCap {
			a.mu.Unlock()
			if a.sem != nil {
				<-a.sem
			}
			return nil, ErrAtCapacity
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
		return err
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
