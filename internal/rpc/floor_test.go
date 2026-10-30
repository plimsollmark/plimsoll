package rpc

import (
	"context"
	"sync"
	"testing"

	"connectrpc.com/connect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/protocol"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// driftingSandbox is a provider whose evidence was read at startup (stated) and whose
// dispatch finds the boundary it actually has (actual), as agentsandbox reads its runtime
// class again on every run. Like every real provider it checks the request's floor against
// what the dispatch found before it runs anything.
type driftingSandbox struct {
	stated, actual sandbox.IsolationClass

	mu     sync.Mutex
	asked  int                      // dispatches that reached the provider
	ran    int                      // dispatches that ran code
	floors []sandbox.IsolationClass // each request's floor, as the provider received it
}

func (d *driftingSandbox) Name() string { return "drifting" }
func (d *driftingSandbox) IsolationClass() sandbox.IsolationClass {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.stated
}

func (d *driftingSandbox) dispatch(floor sandbox.IsolationClass) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.asked++
	d.floors = append(d.floors, floor)
	if err := sandbox.CheckMinimumIsolation(d.actual, floor); err != nil {
		return err
	}
	d.ran++
	return nil
}

func (d *driftingSandbox) RunJavaScript(_ context.Context, req sandbox.Request) (sandbox.Result, error) {
	if err := d.dispatch(req.MinimumIsolation); err != nil {
		return sandbox.Result{}, err
	}
	return sandbox.Result{Stdout: "ran", Sandbox: "drifting", Isolation: d.actual}, nil
}

func (d *driftingSandbox) RunProject(_ context.Context, req sandbox.ProjectRequest) (sandbox.ProjectResult, error) {
	if err := d.dispatch(req.MinimumIsolation); err != nil {
		return sandbox.ProjectResult{}, err
	}
	return sandbox.ProjectResult{Sandbox: "drifting", Isolation: d.actual, Outcome: sandbox.ProjectOutcomeCompleted}, nil
}

func (d *driftingSandbox) RunModule(_ context.Context, req sandbox.ModuleRequest) (sandbox.ModuleResult, error) {
	if err := d.dispatch(req.MinimumIsolation); err != nil {
		return sandbox.ModuleResult{}, err
	}
	return sandbox.ModuleResult{Sandbox: "drifting", Isolation: d.actual, Outcome: sandbox.ProjectOutcomeCompleted, Width: 1}, nil
}

func (*driftingSandbox) SupportsProjects() bool { return true }
func (*driftingSandbox) SupportsModules() bool  { return true }

func (d *driftingSandbox) counts() (asked, ran int, floors []sandbox.IsolationClass) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.asked, d.ran, append([]sandbox.IsolationClass(nil), d.floors...)
}

// floorKinds are the three payload kinds of Run, each with no caller minimum unless
// floor is set.
func floorKinds() []struct {
	name string
	run  func(svc *SandboxService, floor string) error
} {
	send := func(svc *SandboxService, floor string, payload func(*plimsollv1.RunRequest)) error {
		req := &plimsollv1.RunRequest{Protocol: protocol.Number, MinimumIsolation: floor}
		payload(req)
		_, err := svc.Run(authenticatedContext("alice"), connect.NewRequest(req))
		return err
	}
	return []struct {
		name string
		run  func(svc *SandboxService, floor string) error
	}{
		{"snippet", func(svc *SandboxService, floor string) error {
			return send(svc, floor, func(r *plimsollv1.RunRequest) {
				r.Payload = &plimsollv1.RunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: "1"}}
			})
		}},
		{"project", func(svc *SandboxService, floor string) error {
			return send(svc, floor, func(r *plimsollv1.RunRequest) {
				r.Payload = &plimsollv1.RunRequest_Project{Project: &plimsollv1.ProjectRun{
					Files: []*plimsollv1.ProjectFile{{Path: "a.js", Content: "1"}}, Steps: []string{"node a.js"}}}
			})
		}},
		{"module", func(svc *SandboxService, floor string) error {
			return send(svc, floor, func(r *plimsollv1.RunRequest) {
				r.Payload = &plimsollv1.RunRequest_Module{Module: &plimsollv1.ModuleRun{Model: "vanderpol",
					Rows: []*plimsollv1.ModuleRow{{Values: []float64{1, 2}}}, EndTime: 1, Step: 0.1}}
			})
		}},
	}
}

// A hardened daemon proved kernel isolation at startup; its provider's boundary falls to
// container afterwards (a runtime class replaced under a running daemon). A caller that set
// no minimum must still be refused, not dispatched, for the isolation reason, on every
// payload kind: whether the drop shows in the provider's stated evidence (the pipeline's
// check refuses before the provider is asked) or only at dispatch (the provider's own check
// refuses before it runs anything, because the daemon's floor travels in the request).
func TestTheDaemonFloorHoldsOnEveryRun(t *testing.T) {
	for _, k := range floorKinds() {
		t.Run(k.name, func(t *testing.T) {
			stale := &driftingSandbox{stated: sandbox.IsolationKernel, actual: sandbox.IsolationContainer}
			svc := NewSandboxService(stale)
			svc.Floor = sandbox.IsolationKernel
			err := k.run(svc, "")
			if connect.CodeOf(err) != connect.CodeFailedPrecondition {
				t.Fatalf("drop seen only at dispatch: %v; want FailedPrecondition", err)
			}
			wantNotDispatched(t, "drop seen only at dispatch", err, plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_ISOLATION)
			if asked, ran, floors := stale.counts(); asked != 1 || ran != 0 || floors[0] != sandbox.IsolationKernel {
				t.Fatalf("drop seen only at dispatch: asked %d, ran %d, floors %v; want the daemon's floor in the request and nothing run", asked, ran, floors)
			}

			seen := &driftingSandbox{stated: sandbox.IsolationContainer, actual: sandbox.IsolationContainer}
			svc = NewSandboxService(seen)
			svc.Floor = sandbox.IsolationKernel
			err = k.run(svc, "")
			wantNotDispatched(t, "drop in the stated evidence", err, plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_ISOLATION)
			if asked, _, _ := seen.counts(); asked != 0 {
				t.Fatalf("drop in the stated evidence: the provider was asked %d times; want a refusal before it", asked)
			}
			if total, _ := svc.RunCounts(); total != 0 {
				t.Fatalf("runs total = %d; want the refusal before admission", total)
			}
		})
	}
}

// With no floor of its own (a daemon not in hardened mode), the same provider dispatches a
// run that names no minimum at the tier it finds, as before; with one, the stronger of the
// daemon's floor and the caller's minimum is the floor the provider receives.
func TestTheDaemonFloorMergesWithTheCallersMinimum(t *testing.T) {
	for _, k := range floorKinds() {
		t.Run(k.name, func(t *testing.T) {
			plain := &driftingSandbox{stated: sandbox.IsolationKernel, actual: sandbox.IsolationContainer}
			if err := k.run(NewSandboxService(plain), ""); err != nil {
				t.Fatalf("no daemon floor: %v; want the run dispatched as before", err)
			}
			if asked, ran, floors := plain.counts(); asked != 1 || ran != 1 || floors[0] != sandbox.IsolationUnknown {
				t.Fatalf("no daemon floor: asked %d, ran %d, floors %v", asked, ran, floors)
			}
			for _, c := range []struct {
				caller string
				want   sandbox.IsolationClass
			}{
				{"", sandbox.IsolationKernel},
				{"process", sandbox.IsolationKernel},
				{"container", sandbox.IsolationKernel},
				{"kernel", sandbox.IsolationKernel},
				{"vm", sandbox.IsolationVM},
			} {
				vm := &driftingSandbox{stated: sandbox.IsolationVM, actual: sandbox.IsolationVM}
				svc := NewSandboxService(vm)
				svc.Floor = sandbox.IsolationKernel
				if err := k.run(svc, c.caller); err != nil {
					t.Fatalf("caller minimum %q: %v", c.caller, err)
				}
				if _, ran, floors := vm.counts(); ran != 1 || floors[0] != c.want {
					t.Fatalf("caller minimum %q: ran %d, the provider received %v; want %s", c.caller, ran, floors, c.want)
				}
			}
		})
	}
}

// Opening a session and every call in one parse their envelope through the same floor: a
// container-tier session provider under a kernel floor opens nothing for a caller that set
// no minimum, and a session's snippet, project and cell calls are refused before the
// session runs them. The calls are tested on a session opened before the floor was set,
// which a real daemon never does (its floor is fixed before it serves); it is the only way
// to reach the call path with a session weaker than the floor.
func TestTheDaemonFloorHoldsOnSessions(t *testing.T) {
	svc, p := sessionService()
	svc.Floor = sandbox.IsolationKernel
	ctx := authenticatedContext("alice")
	_, err := svc.OpenSession(ctx, openReq())
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("open under the floor: %v; want FailedPrecondition", err)
	}
	wantNotDispatched(t, "open under the floor", err, plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_ISOLATION)
	if n := len(p.Opened()); n != 0 {
		t.Fatalf("the provider opened %d sessions under a floor it cannot meet", n)
	}

	svc.Floor = sandbox.IsolationUnknown
	opened, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatalf("open with no daemon floor: %v; want it opened as before", err)
	}
	id := opened.Msg.GetSessionId()
	svc.Floor = sandbox.IsolationKernel
	for _, c := range []struct {
		name    string
		payload func(*plimsollv1.SessionRunRequest)
	}{
		{"snippet", func(r *plimsollv1.SessionRunRequest) {
			r.Payload = &plimsollv1.SessionRunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: "1"}}
		}},
		{"project", func(r *plimsollv1.SessionRunRequest) {
			r.Payload = &plimsollv1.SessionRunRequest_Project{Project: &plimsollv1.ProjectRun{
				Files: []*plimsollv1.ProjectFile{{Path: "a.js", Content: "1"}}, Steps: []string{"node a.js"}}}
		}},
		{"cell", func(r *plimsollv1.SessionRunRequest) {
			r.Payload = &plimsollv1.SessionRunRequest_Cell{Cell: &plimsollv1.CellRun{Language: "python", Code: "x = 1"}}
		}},
	} {
		req := &plimsollv1.SessionRunRequest{Protocol: protocol.Number, SessionId: id}
		c.payload(req)
		_, err := svc.SessionRun(ctx, connect.NewRequest(req))
		if connect.CodeOf(err) != connect.CodeFailedPrecondition {
			t.Fatalf("session %s under the floor: %v; want FailedPrecondition", c.name, err)
		}
		wantNotDispatched(t, "session "+c.name, err, plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_ISOLATION)
	}
	if calls := p.Opened()[0].Calls(); calls != 0 {
		t.Fatalf("the session ran %d calls under a floor it cannot meet", calls)
	}

	svc.Floor = sandbox.IsolationUnknown
	if _, err := svc.SessionRun(ctx, callReq(id, "1")); err != nil {
		t.Fatalf("a call with no daemon floor: %v; want it run as before", err)
	}
}
