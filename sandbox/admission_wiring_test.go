package sandbox

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
	"time"
)

// fullProvider implements Sandbox and every optional provider interface, recording
// which of them the decorator reached.
type fullProvider struct {
	Disabled
	called map[string]bool
}

func (f *fullProvider) mark(name string)                  { f.called[name] = true }
func (f *fullProvider) IsolationClass() IsolationClass    { return IsolationVM }
func (f *fullProvider) SupportsProjects() bool            { f.mark("ProjectCapable"); return true }
func (f *fullProvider) SupportsModules() bool             { f.mark("ModuleCapable"); return true }
func (f *fullProvider) SupportsJavaScriptGrants() bool    { f.mark("GrantCapable"); return true }
func (f *fullProvider) SupportsProjectGrants() bool       { return true }
func (f *fullProvider) Environments() Environments        { f.mark("Describer"); return Environments{} }
func (f *fullProvider) Preflight(context.Context) error   { f.mark("Preflighter"); return nil }
func (f *fullProvider) SmokeTest(context.Context) error   { f.mark("SmokeTester"); return nil }
func (f *fullProvider) Drain(context.Context) error       { f.mark("Drainer"); return nil }
func (f *fullProvider) EgressGuardPath() string           { f.mark("EgressGuardCapable"); return "/guard" }
func (f *fullProvider) BillingTeardown() time.Duration    { f.mark("Metered"); return time.Second }
func (f *fullProvider) EgressGuardKnownToken(string) bool { return false }
func (f *fullProvider) SupportsSessions() bool            { return true }
func (f *fullProvider) SessionEnvironments() Environments { return Environments{} }
func (f *fullProvider) ReconcileOrphans(context.Context) (int, error) {
	f.mark("OrphanReconciler")
	return 0, nil
}
func (f *fullProvider) EgressGuardCall(context.Context, string, string, string, []byte) EgressGuardResponse {
	return EgressGuardResponse{}
}
func (f *fullProvider) StartSessionPool(context.Context, int, time.Duration) error {
	f.mark("SessionPool")
	return nil
}
func (f *fullProvider) OpenSession(context.Context, SessionOptions) (Session, error) {
	f.mark("SessionProvider")
	return &endingSession{done: make(chan struct{})}, nil
}

// endingSession is a session that ends when closed.
type endingSession struct {
	Disabled
	done chan struct{}
}

func (s *endingSession) Isolation() IsolationClass             { return IsolationVM }
func (s *endingSession) Environments() Environments            { return Environments{} }
func (s *endingSession) ExpiresAt() time.Time                  { return time.Now().Add(time.Minute) }
func (s *endingSession) Suspend(context.Context) (bool, error) { return false, nil }
func (s *endingSession) RunCell(context.Context, CellRequest) (CellResult, error) {
	return CellResult{}, nil
}
func (s *endingSession) Close(context.Context) error { close(s.done); return nil }
func (s *endingSession) Done() <-chan struct{}       { return s.done }
func (s *endingSession) Err() error                  { return nil }

// TestAdmissionForwardsEveryOptionalInterface: wrapping a provider for admission must
// not hide any optional interface the rest of plimsoll finds by type assertion.
// Losing SmokeTester made EnsureReady report ready with no behavioral proof (external
// review of v0.10.0, finding 2, 2026-09-28). The interface list is read from this
// package's source, so a new optional interface fails here until it is classified.
func TestAdmissionForwardsEveryOptionalInterface(t *testing.T) {
	// Interfaces of the package that are not optional provider capabilities.
	notOptional := map[string]bool{"Sandbox": true, "Session": true, "CellRunner": true, "TokenMinter": true, "SubjectBoundMinter": true}
	ctx := context.Background()
	calls := map[string]func(Sandbox) bool{
		"ProjectCapable": func(s Sandbox) bool { c, ok := s.(ProjectCapable); return ok && c.SupportsProjects() },
		"ModuleCapable":  func(s Sandbox) bool { c, ok := s.(ModuleCapable); return ok && c.SupportsModules() },
		"GrantCapable":   func(s Sandbox) bool { c, ok := s.(GrantCapable); return ok && c.SupportsJavaScriptGrants() },
		"Describer": func(s Sandbox) bool {
			c, ok := s.(Describer)
			if ok {
				c.Environments()
			}
			return ok
		},
		"Preflighter": func(s Sandbox) bool { c, ok := s.(Preflighter); return ok && c.Preflight(ctx) == nil },
		"SmokeTester": func(s Sandbox) bool { c, ok := s.(SmokeTester); return ok && c.SmokeTest(ctx) == nil },
		"Drainer":     func(s Sandbox) bool { c, ok := s.(Drainer); return ok && c.Drain(ctx) == nil },
		"OrphanReconciler": func(s Sandbox) bool {
			c, ok := s.(OrphanReconciler)
			if !ok {
				return false
			}
			_, err := c.ReconcileOrphans(ctx)
			return err == nil
		},
		"EgressGuardCapable": func(s Sandbox) bool { c, ok := s.(EgressGuardCapable); return ok && c.EgressGuardPath() == "/guard" },
		"Metered":            func(s Sandbox) bool { return IsMetered(s) },
		"SessionPool": func(s Sandbox) bool {
			c, ok := s.(SessionPool)
			return ok && c.StartSessionPool(ctx, 1, time.Minute) == nil
		},
		"SessionProvider": func(s Sandbox) bool {
			c, ok := s.(SessionProvider)
			if !ok || !c.SupportsSessions() {
				return false
			}
			sess, err := c.OpenSession(ctx, SessionOptions{Lifetime: time.Minute})
			if err != nil {
				return false
			}
			return sess.Close(ctx) == nil
		},
	}

	for _, name := range packageInterfaces(t) {
		if !notOptional[name] && calls[name] == nil {
			t.Errorf("interface %s is new: classify it in this test and forward it in admission.go", name)
		}
	}
	inner := &fullProvider{called: map[string]bool{}}
	wrapped, err := WithAdmission(inner, AdmissionConfig{MaxConcurrent: 1})
	if err != nil {
		t.Fatalf("WithAdmission: %v", err)
	}
	for name, call := range calls {
		if !call(wrapped) {
			t.Errorf("the admission decorator hides or fails %s", name)
		} else if !inner.called[name] {
			t.Errorf("the admission decorator answers %s without asking the provider", name)
		}
	}
}

// TestAdmissionDoesNotClaimWhatTheProviderLacks: a provider with no sessions and no
// egress guard gets neither through the decorator, since an embedder mounts the
// guard on the type assertion alone.
func TestAdmissionDoesNotClaimWhatTheProviderLacks(t *testing.T) {
	wrapped, err := WithAdmission(Disabled{}, AdmissionConfig{MaxConcurrent: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := wrapped.(EgressGuardCapable); ok {
		t.Error("the decorator claims an egress guard the provider does not have")
	}
	sp, ok := wrapped.(SessionProvider)
	if !ok || sp.SupportsSessions() {
		t.Fatalf("SupportsSessions through the decorator of a provider without sessions: %v", ok && sp.SupportsSessions())
	}
	if _, err := sp.OpenSession(context.Background(), SessionOptions{Lifetime: time.Minute}); !errors.Is(err, ErrUnsupported) {
		t.Errorf("OpenSession: %v, want ErrUnsupported", err)
	}
	if err := wrapped.(SessionPool).StartSessionPool(context.Background(), 1, time.Minute); !errors.Is(err, ErrUnsupported) {
		t.Errorf("StartSessionPool: %v, want ErrUnsupported", err)
	}
}

// TestAdmissionHoldsASessionsSlotUntilItEnds: a session holds its admission slot for
// its whole life, and gives it back when it ends.
func TestAdmissionHoldsASessionsSlotUntilItEnds(t *testing.T) {
	wrapped, err := WithAdmission(&fullProvider{called: map[string]bool{}}, AdmissionConfig{MaxConcurrent: 1})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	sess, err := wrapped.(SessionProvider).OpenSession(ctx, SessionOptions{Lifetime: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrapped.RunJavaScript(ctx, Request{Code: "1"}); !errors.Is(err, ErrAtCapacity) {
		t.Fatalf("a run while the session holds the only slot: %v", err)
	}
	if err := sess.Close(ctx); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		_, err := wrapped.RunJavaScript(ctx, Request{Code: "1"})
		if !errors.Is(err, ErrAtCapacity) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the ended session never gave its slot back")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// packageInterfaces lists the interface types this package declares outside tests.
func packageInterfaces(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		n := e.Name()
		if !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, n, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			g, ok := d.(*ast.GenDecl)
			if !ok || g.Tok != token.TYPE {
				continue
			}
			for _, sp := range g.Specs {
				ts := sp.(*ast.TypeSpec)
				if _, ok := ts.Type.(*ast.InterfaceType); ok && ts.Name.IsExported() {
					names = append(names, ts.Name.Name)
				}
			}
		}
	}
	if len(names) == 0 {
		t.Fatal("found no interfaces; the source scan is broken")
	}
	return names
}

// A waiting pool member holds memory (its container's limit is one run's), so a pool
// started through the admission wrapper is charged size runs against TotalMemoryMB for
// as long as it runs, and Drain gives the charge back. Before the fix it was charged
// nothing, so with the pool on the budget no longer bounded the memory sandboxes hold.
func TestAdmissionChargesTheSessionPoolAgainstTheMemoryBudget(t *testing.T) {
	ctx := context.Background()
	wrapped, err := WithAdmission(&fullProvider{called: map[string]bool{}}, AdmissionConfig{TotalMemoryMB: 1024, PerRunMemoryMB: 256})
	if err != nil {
		t.Fatal(err)
	}
	if err := wrapped.(SessionPool).StartSessionPool(ctx, 2, time.Minute); err != nil {
		t.Fatal(err)
	}
	var open []Session
	for range 2 {
		s, err := wrapped.(SessionProvider).OpenSession(ctx, SessionOptions{Lifetime: time.Minute})
		if err != nil {
			t.Fatalf("a session within the budget left by a pool of 2: %v", err)
		}
		open = append(open, s)
	}
	if _, err := wrapped.(SessionProvider).OpenSession(ctx, SessionOptions{Lifetime: time.Minute}); !errors.Is(err, ErrAtCapacity) {
		t.Fatalf("a third session while the pool holds two runs' memory of four: %v", err)
	}
	for _, s := range open {
		_ = s.Close(ctx)
	}
	if err := wrapped.(Drainer).Drain(ctx); err != nil {
		t.Fatal(err)
	}
	if err := wrapped.(SessionPool).StartSessionPool(ctx, 5, time.Minute); err == nil {
		t.Fatal("a pool of 5 runs' memory started within a budget of 4")
	}
	// The closed sessions give their reservations back as they end.
	deadline := time.Now().Add(3 * time.Second)
	for {
		err := wrapped.(SessionPool).StartSessionPool(ctx, 4, time.Minute)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after Drain and the sessions' ends the whole budget is free again, but a pool of 4 was refused: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
