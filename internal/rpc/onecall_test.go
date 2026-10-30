package rpc

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"connectrpc.com/connect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/internal/withheld"
	"github.com/plimsollmark/plimsoll/protocol"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandboxtest"
)

// pooledService is a daemon with sessions on, a pool of pool stated, and a provider
// whose pool hands warm warm-only opens a session and which runs fresh projects.
func pooledService(pool, warm int) (*SandboxService, *sandboxtest.Pooled) {
	p := sandboxtest.NewPooled(warm)
	svc := NewSandboxService(p)
	svc.Sessions = SessionConfig{MaxSessions: 4, Pool: pool, Lifetime: time.Minute, IdleTimeout: time.Minute, DiskBytes: 1 << 20}
	return svc, p
}

func cellRequest(code string, preferWarm bool) *connect.Request[plimsollv1.RunRequest] {
	return connect.NewRequest(&plimsollv1.RunRequest{Protocol: protocol.Number, PreferWarm: preferWarm,
		Payload: &plimsollv1.RunRequest_Cell{Cell: &plimsollv1.CellRun{Language: "python", Code: code,
			Files: []*plimsollv1.ProjectFile{{Path: "in/a.csv", Content: "a"}}}}})
}

// runCell sends req and checks its answer's record as a client does.
func runCell(t *testing.T, svc *SandboxService, ctx context.Context, req *connect.Request[plimsollv1.RunRequest]) *plimsollv1.RunResponse {
	t.Helper()
	resp, err := svc.Run(ctx, req)
	if err != nil {
		t.Fatalf("Run with a cell: %v", err)
	}
	if _, err := record.Check(req.Msg, resp.Msg); err != nil {
		t.Fatalf("the answer's record does not check: %v", err)
	}
	return resp.Msg
}

// waitClosed waits until every session the provider opened has ended.
func waitClosed(t *testing.T, p *sandboxtest.Pooled) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := p.WaitEnded(ctx); err != nil {
		t.Fatalf("a pool member was not closed after its one call: %v", err)
	}
}

// With a member waiting, a cell that prefers it runs there, as the member's first cell,
// with its files: no fresh run is made, the answer says warm, its record is a single
// run's and checks, and the member is closed after.
func TestPreferWarmCellRunsInAWaitingMember(t *testing.T) {
	svc, p := pooledService(2, 1)
	resp := runCell(t, svc, authenticatedContext("alice"), cellRequest("6 * 7", true))
	cell := resp.GetCell()
	if !resp.GetWarm() || string(cell.GetStdout()) != "python 1: 6 * 7" || string(cell.GetStderr()) != "in/a.csv\n" {
		t.Fatalf("answer %+v, warm %v; want the member's cell with its file", cell, resp.GetWarm())
	}
	if !cell.GetInterpreterStarted() || !cell.GetInterpreterEnded() {
		t.Fatalf("interpreter started %v, ended %v; a Run's cell keeps nothing, so both", cell.GetInterpreterStarted(), cell.GetInterpreterEnded())
	}
	if rec := resp.GetRecord(); rec.GetSession() != "" || rec.GetSequence() != 0 {
		t.Fatalf("record %+v; want a single run's", rec)
	}
	if n := len(p.FreshRuns()); n != 0 {
		t.Fatalf("%d fresh runs; want none", n)
	}
	opened := p.Opened()
	if len(opened) != 1 || !opened[0].Options.WarmOnly || !slices.Equal(opened[0].Options.Languages, []sandbox.Language{sandbox.LanguagePython}) {
		t.Fatalf("%d opens; want one warm-only open hinted with python", len(opened))
	}
	// The member's lifetime is the call's budget plus the margin, within the session
	// lifetime the pool made it for.
	if lt := opened[0].Options.Lifetime; lt <= 0 || lt > svc.Sessions.Lifetime {
		t.Fatalf("member lifetime %v; want within the session lifetime %v", lt, svc.Sessions.Lifetime)
	}
	waitClosed(t, p)
}

// Without a pool, without the flag, and on a miss (a pool stated, none waiting), the
// cell runs fresh, as a project with the runner, and the answer says so: a miss is
// never a refusal.
func TestCellRunsFreshWithoutAMember(t *testing.T) {
	for _, tc := range []struct {
		name       string
		pool, warm int
		preferWarm bool
		opens      int
	}{
		{"no pool", 0, 1, true, 0},
		{"no flag", 2, 1, false, 0},
		{"none waiting", 2, 0, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, p := pooledService(tc.pool, tc.warm)
			resp := runCell(t, svc, authenticatedContext("alice"), cellRequest("6 * 7", tc.preferWarm))
			if resp.GetWarm() || string(resp.GetCell().GetStdout()) != "fresh python: 6 * 7" || string(resp.GetCell().GetStderr()) != "in/a.csv\n" {
				t.Fatalf("answer %+v, warm %v; want the fresh run's", resp.GetCell(), resp.GetWarm())
			}
			fresh := p.FreshRuns()
			if len(fresh) != 1 || !slices.Equal(fresh[0].Steps, []string{"python3 -I .plimsoll/run.py"}) {
				t.Fatalf("fresh runs %+v; want one project running the python runner", fresh)
			}
			if n := len(p.Opened()); n != tc.opens {
				t.Fatalf("%d sessions opened; want %d", n, tc.opens)
			}
		})
	}
}

// A member whose cell is refused before any of it ran, because its session ended first,
// is a miss: the cell runs fresh.
func TestPreferWarmMemberThatEndedRunsFresh(t *testing.T) {
	svc, p := pooledService(2, 1)
	svc.Sandbox = &endingPool{p}
	resp := runCell(t, svc, authenticatedContext("alice"), cellRequest("1", true))
	if resp.GetWarm() || len(p.FreshRuns()) != 1 {
		t.Fatalf("warm %v, %d fresh runs; want the fresh run", resp.GetWarm(), len(p.FreshRuns()))
	}
}

// endingPool hands over members that have already ended.
type endingPool struct{ *sandboxtest.Pooled }

func (e *endingPool) OpenSession(ctx context.Context, opts sandbox.SessionOptions) (sandbox.Session, error) {
	s, err := e.Pooled.OpenSession(ctx, opts)
	if err == nil {
		s.(*sandboxtest.FakeSession).End(sandbox.SessionExpired)
	}
	return s, err
}

// prefer_warm on anything but a cell is refused, not dispatched, before anything runs.
func TestPreferWarmTakesACellOnly(t *testing.T) {
	svc, p := pooledService(2, 1)
	_, err := svc.Run(authenticatedContext("alice"), connect.NewRequest(&plimsollv1.RunRequest{Protocol: protocol.Number, PreferWarm: true,
		Payload: &plimsollv1.RunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: "1"}}}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("prefer_warm on a snippet: %v; want InvalidArgument", err)
	}
	wantNotDispatched(t, "prefer_warm on a snippet", err, plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_REQUEST)
	if len(p.Opened()) != 0 || len(p.FreshRuns()) != 0 {
		t.Fatal("a refused request reached the provider")
	}
}

// A request on the protocol before prefer_warm is refused before it is read: an older
// client never gets a cell run, and nothing reaches the provider.
func TestRunCellRefusesAnOlderProtocol(t *testing.T) {
	svc, p := pooledService(2, 1)
	req := cellRequest("1", true)
	req.Msg.Protocol = 4
	_, err := svc.Run(authenticatedContext("alice"), req)
	if connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("a protocol 4 request: %v; want Unimplemented", err)
	}
	wantNotDispatched(t, "a protocol 4 request", err, plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_PROTOCOL)
	if len(p.Opened()) != 0 || len(p.FreshRuns()) != 0 || p.Warm != 1 {
		t.Fatal("a refused request reached the provider")
	}
}

// The caller's limiter, the ship scan and the floor refuse a cell that prefers a member
// before one is claimed, as they refuse a fresh run: the member stays in the pool.
func TestPreferWarmIsCheckedBeforeAMemberIsClaimed(t *testing.T) {
	t.Run("limiter", func(t *testing.T) {
		svc, p := pooledService(2, 5)
		svc.Limiter = NewCodeLimiter(0, 0, 1, 1) // one run a minute
		ctx := authenticatedContext("alice")
		runCell(t, svc, ctx, cellRequest("1", true))
		waitClosed(t, p)
		_, err := svc.Run(ctx, cellRequest("2", true))
		if !refusedCapacity(err) {
			t.Fatalf("a second cell within the minute: %v; want refused, capacity", err)
		}
		if p.Warm != 4 || len(p.Opened()) != 1 {
			t.Fatalf("%d members left, %d claimed; want the refused call to claim none", p.Warm, len(p.Opened()))
		}
	})
	t.Run("ship scan", func(t *testing.T) {
		svc, p := pooledService(2, 1)
		svc.Withheld = withheldSetOf(t, withheld.ModeRefuse, nil, withheldValue(heldOutSeed, "seeds.txt:3", ""))
		_, err := svc.Run(authenticatedContext("alice"), cellRequest("seed = "+heldOutSeed, true))
		if _, marked := notDispatchedOf(err); connect.CodeOf(err) != connect.CodePermissionDenied || !marked {
			t.Fatalf("a cell carrying a withheld value: %v; want PermissionDenied, not dispatched", err)
		}
		if p.Warm != 1 || len(p.Opened()) != 0 || len(p.FreshRuns()) != 0 {
			t.Fatal("the refused cell reached the provider")
		}
	})
	t.Run("floor", func(t *testing.T) {
		svc, p := pooledService(2, 1)
		req := cellRequest("1", true)
		req.Msg.MinimumIsolation = "vm" // the fake states container
		_, err := svc.Run(authenticatedContext("alice"), req)
		wantNotDispatched(t, "a floor above the tier", err, plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_ISOLATION)
		if p.Warm != 1 || len(p.Opened()) != 0 || len(p.FreshRuns()) != 0 {
			t.Fatal("the refused cell reached the provider")
		}
	})
}

// A call canceled while its member is claimed ran nothing: it is answered canceled and
// not dispatched, is not run fresh, and the member it claimed is closed unused.
func TestPreferWarmCanceledDuringTheClaim(t *testing.T) {
	svc, p := pooledService(2, 1)
	ctx, cancel := context.WithCancel(authenticatedContext("alice"))
	defer cancel()
	p.BeforeOpen = func() error { cancel(); return nil }
	_, err := svc.Run(ctx, cellRequest("1", true))
	if connect.CodeOf(err) != connect.CodeCanceled {
		t.Fatalf("canceled during the claim: %v; want Canceled", err)
	}
	if _, marked := notDispatchedOf(err); !marked {
		t.Fatalf("canceled during the claim: %v; want it marked not dispatched", err)
	}
	if len(p.FreshRuns()) != 0 {
		t.Fatal("a canceled call was run fresh")
	}
	waitClosed(t, p)
	if calls := p.Opened()[0].Calls(); calls != 0 {
		t.Fatalf("the claimed member ran %d calls; want none", calls)
	}
}

// A claim the cancel interrupts (the provider gives up on it) is not a miss either: the
// call is answered canceled, not dispatched, and nothing runs fresh.
func TestPreferWarmClaimInterruptedByTheCancel(t *testing.T) {
	svc, p := pooledService(2, 1)
	ctx, cancel := context.WithCancel(authenticatedContext("alice"))
	defer cancel()
	p.BeforeOpen = func() error { cancel(); return context.Canceled }
	_, err := svc.Run(ctx, cellRequest("1", true))
	if _, marked := notDispatchedOf(err); connect.CodeOf(err) != connect.CodeCanceled || !marked {
		t.Fatalf("a claim the cancel interrupted: %v; want Canceled, not dispatched", err)
	}
	if len(p.FreshRuns()) != 0 {
		t.Fatal("a canceled call was run fresh")
	}
}

// A member whose cell ended in an error that may have followed execution answers that
// error, unmarked, is not run fresh, and is closed.
func TestPreferWarmCellThatMayHaveRun(t *testing.T) {
	svc, p := pooledService(2, 1)
	svc.Sandbox = &breakingPool{p}
	_, err := svc.Run(authenticatedContext("alice"), cellRequest("1", true))
	if err == nil {
		t.Fatal("the broken cell answered")
	}
	if _, marked := notDispatchedOf(err); marked {
		t.Fatalf("an error after the cell was sent: %v; want it unmarked", err)
	}
	if len(p.FreshRuns()) != 0 {
		t.Fatal("a cell that may have run was run again fresh")
	}
	waitClosed(t, p)
}

// breakingPool hands over members whose cells fail after they were sent.
type breakingPool struct{ *sandboxtest.Pooled }

func (b *breakingPool) OpenSession(ctx context.Context, opts sandbox.SessionOptions) (sandbox.Session, error) {
	s, err := b.Pooled.OpenSession(ctx, opts)
	if err != nil {
		return nil, err
	}
	return breakingSession{s}, nil
}

type breakingSession struct{ sandbox.Session }

func (breakingSession) RunCell(context.Context, sandbox.CellRequest) (sandbox.CellResult, error) {
	return sandbox.CellResult{}, errors.New("the relay was lost after the cell was sent")
}

// A cell this daemon could not run fresh is refused at once, whether or not a member is
// waiting, so the pool's state never decides a refusal: a sessions-only provider runs
// no projects and no snippets.
func TestRunCellRefusedWhenItCannotRunFresh(t *testing.T) {
	svc, p := sessionService()
	svc.Sessions.Pool, p.Warm = 2, 1
	_, err := svc.Run(authenticatedContext("alice"), cellRequest("1", true))
	if connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("a cell on a provider without projects: %v; want Unimplemented", err)
	}
	wantNotDispatched(t, "a cell on a provider without projects", err, plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_UNSUPPORTED)
	if len(p.Opened()) != 0 {
		t.Fatal("a member was claimed for a cell refused anyway")
	}
	bad := cellRequest("1", true)
	bad.Msg.GetCell().Files = []*plimsollv1.ProjectFile{{Path: ".plimsoll/run.py", Content: "x"}}
	svc2, p2 := pooledService(2, 1)
	_, err = svc2.Run(authenticatedContext("alice"), bad)
	wantNotDispatched(t, "a file under .plimsoll/", err, plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_REQUEST)
	if len(p2.Opened()) != 0 || len(p2.FreshRuns()) != 0 {
		t.Fatal("a refused cell reached the provider")
	}
}

// The daemon's own floor (hardened mode, SANDBOX_MIN_ISOLATION) is merged into the
// request's minimum where the envelope is parsed, and a call that prefers a member is held
// to it as a fresh run is: above the provider's tier it is refused, not dispatched, before
// a member is claimed, even with no floor of its own.
func TestPreferWarmHeldToTheDaemonsFloor(t *testing.T) {
	svc, p := pooledService(2, 1)
	svc.Floor = sandbox.IsolationKernel // the fake states container
	_, err := svc.Run(authenticatedContext("alice"), cellRequest("1", true))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("a cell below the daemon's floor: %v; want FailedPrecondition", err)
	}
	wantNotDispatched(t, "a cell below the daemon's floor", err, plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_ISOLATION)
	if p.Warm != 1 || len(p.Opened()) != 0 || len(p.FreshRuns()) != 0 {
		t.Fatal("the refused cell reached the provider")
	}
}

// A member whose tier, measured when it was made, is below the floor is a miss even when
// the provider's tier now meets it: the member is closed unused and the cell runs fresh,
// held to the floor there.
func TestPreferWarmMemberBelowTheFloorRunsFresh(t *testing.T) {
	svc, p := pooledService(2, 1)
	svc.Sandbox = &kernelPool{p} // its members still measure container
	svc.Floor = sandbox.IsolationKernel
	req := cellRequest("1", true)
	resp, err := svc.Run(authenticatedContext("alice"), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Msg.GetWarm() || resp.Msg.GetIsolation() != "kernel" || len(p.FreshRuns()) != 1 {
		t.Fatalf("warm %v at %s, %d fresh runs; want the fresh run at kernel", resp.Msg.GetWarm(), resp.Msg.GetIsolation(), len(p.FreshRuns()))
	}
	waitClosed(t, p)
	if calls := p.Opened()[0].Calls(); calls != 0 {
		t.Fatalf("the member below the floor ran %d calls; want none", calls)
	}
}

// kernelPool states kernel and answers fresh runs at kernel; its members are the
// fake's, at container.
type kernelPool struct{ *sandboxtest.Pooled }

func (*kernelPool) IsolationClass() sandbox.IsolationClass { return sandbox.IsolationKernel }
func (k *kernelPool) RunProject(ctx context.Context, req sandbox.ProjectRequest) (sandbox.ProjectResult, error) {
	res, err := k.Pooled.RunProject(ctx, req)
	res.Isolation = sandbox.IsolationKernel
	return res, err
}
