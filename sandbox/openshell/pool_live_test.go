package openshell

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/plimsollmark/plimsoll/gen/go/openshell/openshellv1"
	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandbox/sessiontest"
)

// livePool is a live provider whose smoke test passed and whose session pool of size
// is started. liveProvider drains it when the test ends and checks that no sandbox of
// it is left.
func livePool(t *testing.T, size int) *Provider {
	t.Helper()
	p := liveProvider(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := p.SmokeTest(ctx); err != nil {
		t.Fatalf("SmokeTest: %v", err)
	}
	if err := p.StartSessionPool(ctx, size, 10*time.Minute); err != nil {
		t.Fatalf("StartSessionPool: %v", err)
	}
	return p
}

// A pool member is made before any session asks, with an interpreter for every
// language already running, and the next session is that member: its first cell in
// each language answers and says its interpreter is new, since no cell has defined
// anything there. The pool then makes a replacement; closing the session deletes the
// member's sandbox.
func TestOpenShellSessionPoolHandsOverAWarmMemberLive(t *testing.T) {
	p := livePool(t, 1)
	pool := p.sessionPool.Load()
	members := pool.Members()
	if len(members) != 1 {
		t.Fatalf("the pool made %v; want one member", members)
	}
	member := members[0]
	s := openLive(t, p, sandbox.SessionOptions{Lifetime: 5 * time.Minute, DiskBytes: 64 << 20})
	if s.b.name != member {
		t.Fatalf("the session runs in %s; want the pool member %s", s.b.name, member)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, lang := range p.SessionEnvironments().Project.Languages {
		start := time.Now()
		res, err := s.RunCell(ctx, sandbox.CellRequest{Language: lang, Code: "6 * 7"})
		if err != nil || res.ExitCode != 0 || !res.InterpreterStarted || strings.TrimSpace(res.Stdout) != "42" {
			t.Fatalf("first %s cell: %+v, %v; want 42 from an interpreter reported as new", lang, res, err)
		}
		t.Logf("first %s cell of a claimed member: %v", lang, time.Since(start).Round(time.Millisecond))
		if res, err = s.RunCell(ctx, sandbox.CellRequest{Language: lang, Code: "6 * 7"}); err != nil || res.InterpreterStarted {
			t.Fatalf("second %s cell: %+v, %v; want the same interpreter", lang, res, err)
		}
	}
	var replacement string
	for deadline := time.Now().Add(2 * time.Minute); replacement == "" && time.Now().Before(deadline); time.Sleep(250 * time.Millisecond) {
		if m := pool.Members(); len(m) == 1 && m[0] != member {
			replacement = m[0]
		}
	}
	if replacement == "" {
		t.Fatal("the pool made no replacement after the claim")
	}
	if err := s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.Done():
	case <-time.After(time.Minute):
		t.Fatal("the closed session's sandbox was not deleted")
	}
	if p.leases.Tracked(member) {
		t.Fatal("the claimed member is still tracked after its session closed")
	}
}

// A member deleted behind the provider's back while it waited is never handed over:
// its relays ended with it, so the next session gets a sandbox of its own that works.
func TestOpenShellSessionPoolPassesOverADeletedMemberLive(t *testing.T) {
	p := livePool(t, 1)
	member := p.sessionPool.Load().Members()[0]
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := p.client.DeleteSandbox(ctx, connect.NewRequest(&openshellv1.DeleteSandboxRequest{WorkspaceScope: ws(), Name: member})); err != nil {
		t.Fatalf("deleting the member out of band: %v", err)
	}
	if err := p.deleteAndWait(ctx, member); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second) // the relays' streams end with the sandbox
	s := openLive(t, p, sandbox.SessionOptions{Lifetime: 2 * time.Minute})
	if s.b.name == member {
		t.Fatal("the session was given the deleted member")
	}
	res, err := s.RunJavaScript(ctx, sandbox.Request{Code: `console.log("alive")`})
	if err != nil || strings.TrimSpace(res.Stdout) != "alive" {
		t.Fatalf("the session after a deleted member: %+v, %v", res, err)
	}
	for deadline := time.Now().Add(time.Minute); p.leases.Tracked(member); time.Sleep(250 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the deleted member is still tracked")
		}
	}
}

// Every session the conformance suite opens comes from the pool while the pool keeps
// up, so pooled sessions keep every promise new ones do.
func TestOpenShellSessionPoolConformanceLive(t *testing.T) {
	p := livePool(t, 2)
	langs := p.SessionEnvironments().Project.Languages
	sessiontest.Run(t, p, sessiontest.Config{Lifetime: 5 * time.Minute, ShortLifetime: 20 * time.Second, Languages: langs, ExecsWalledOff: true, Teardown: deleteBudget})
}

// The startup check plimsolld runs when sessions and a pool are on passes on a claimed
// member, as the daemon runs it: the warm path is the one startup proves.
func TestOpenShellSessionPoolSmokeTestLive(t *testing.T) {
	p := livePool(t, 1)
	member := p.sessionPool.Load().Members()[0]
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := sandbox.SessionSmokeTest(ctx, p, sandbox.SessionOptions{Lifetime: 5 * time.Minute, DiskBytes: 64 << 20}); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(p.sessionPool.Load().Members(), member) {
		t.Fatal("the smoke test did not take the waiting member")
	}
}
