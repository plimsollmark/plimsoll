package openshell

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/gen/go/openshell/openshellv1"
	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandbox/internal/poolkit"
)

// The pool's own behavior is tested in sandbox/internal/poolkit, and a member's warm
// interpreters against a real gateway (pool_live_test.go); the fake runs no
// interpreter, so these test what the pool asks of the gateway with members that warm
// none.

const testPoolLifetime = 10 * time.Minute

// bareProvider is a fake-backed provider whose image states JavaScript.
func bareProvider(t *testing.T) (*fakeGateway, *Provider, *sessionScript) {
	t.Helper()
	f, p := newFake(t)
	sc := &sessionScript{}
	f.run = sc.run
	p.mu.Lock()
	p.smoke = &smokeEvidence{Languages: []sandbox.Language{sandbox.LanguageJavaScript}}
	p.mu.Unlock()
	return f, p, sc
}

// startBarePool starts a pool of size on p whose members warm no interpreter.
func startBarePool(t *testing.T, p *Provider, size int) *openshellPool {
	t.Helper()
	h := p.poolHooks()
	h.Make = func(ctx context.Context, _ []string, label time.Time) (*session, string, error) {
		return p.makePoolMember(ctx, nil, label)
	}
	h.Attached = func(*session, string) bool { return true }
	if err := p.startPool(context.Background(), h, size, testPoolLifetime); err != nil {
		t.Fatalf("startPool: %v", err)
	}
	return p.sessionPool.Load()
}

// waitFor polls cond for up to 10 seconds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); !cond(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

// A member is a session's sandbox made ahead: sleep as its main process, the session
// label, tracked so this instance's orphan pass leaves it alone, its processes
// recorded, and a declared lifetime covering the idle bound plus the longest
// lifetime a session may be given, which bounds how long a crashed daemon's member
// lives on. Nothing else ran in it.
func TestPoolMemberIsASessionSandboxDeclaringItsIdleBound(t *testing.T) {
	f, p, sc := bareProvider(t)
	pool := startBarePool(t, p, 1)
	names := pool.Members()
	if len(names) != 1 {
		t.Fatalf("members %v; want 1", names)
	}
	sb := f.boxes[names[0]].sb
	if !slices.Equal(sb.GetSpec().GetCommand(), sessionCommand) {
		t.Fatalf("main process %q", sb.GetSpec().GetCommand())
	}
	labels := sb.GetMetadata().GetLabels()
	want := strconv.Itoa(int((poolkit.MaxIdle + testPoolLifetime) / time.Second))
	if labels[lifetimeLabel] != want || labels[sessionLabel] != "1" || labels[instanceLabel] != p.instance {
		t.Fatalf("labels %v; want a declared lifetime of %s s", labels, want)
	}
	if !p.leases.Tracked(names[0]) {
		t.Fatal("a waiting member is not tracked, so this instance's orphan pass could take it")
	}
	if n, err := p.ReconcileOrphans(context.Background()); n != 0 || err != nil {
		t.Fatalf("ReconcileOrphans = %d, %v; want the member left alone", n, err)
	}
	if got := sc.seen(); !slices.Equal(got, []string{"list"}) {
		t.Fatalf("execs in a waiting member: %v; want only the process list", got)
	}
}

// An open hands over the waiting member instead of creating a sandbox; the member is
// read back before its first call like any session, and closing the session deletes
// it. It never comes back: the next open gets the refill.
func TestOpenSessionClaimsAWaitingMemberOnce(t *testing.T) {
	f, p, _ := bareProvider(t)
	pool := startBarePool(t, p, 1)
	member := pool.Members()[0]
	creates := f.called("CreateSandbox")
	got, err := p.OpenSession(context.Background(), sandbox.SessionOptions{Lifetime: time.Minute})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	s := got.(*session)
	if s.b.name != member {
		t.Fatalf("opened %s; want the waiting member %s", s.b.name, member)
	}
	gets := f.called("GetSandbox")
	r, err := s.RunJavaScript(context.Background(), sandbox.Request{Code: "1"})
	if err != nil || r.ExitCode != 0 {
		t.Fatalf("first call: %+v, %v", r, err)
	}
	if f.called("GetSandbox") == gets {
		t.Fatal("the claimed member's first call was not read back")
	}
	waitFor(t, "the refill", func() bool { return len(pool.Members()) == 1 && pool.Members()[0] != member })
	if f.called("CreateSandbox") != creates+1 {
		t.Fatalf("%d creates after the claim; want 1, the refill", f.called("CreateSandbox")-creates)
	}
	_ = s.Close(context.Background())
	<-s.Done()
	if slices.Contains(f.live(), member) {
		t.Fatal("closing the claimed session left its sandbox")
	}
	next, err := p.OpenSession(context.Background(), sandbox.SessionOptions{Lifetime: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close(context.Background())
	if next.(*session).b.name == member {
		t.Fatal("a closed session's sandbox was handed over again")
	}
}

// An open refused before its claim (a floor the provider cannot meet) leaves the
// pool's demand as it was, and takes no member.
func TestRefusedOpenLeavesTheOpenShellPoolAlone(t *testing.T) {
	_, p, _ := bareProvider(t)
	pool := startBarePool(t, p, 1)
	member := pool.Members()[0]
	before := pool.Demand()
	for range 10 {
		_, err := p.OpenSession(context.Background(), sandbox.SessionOptions{Lifetime: time.Minute, MinimumIsolation: sandbox.IsolationVM,
			Languages: []sandbox.Language{sandbox.LanguagePython}})
		if _, refused := sandbox.NotDispatchedReason(err); !refused {
			t.Fatalf("an open with a VM floor: %v; want refused", err)
		}
	}
	if got := pool.Demand(); !maps.Equal(got, before) {
		t.Fatalf("refused opens moved the demand from %v to %v", before, got)
	}
	if m := pool.Members(); len(m) != 1 || m[0] != member {
		t.Fatalf("members %v after refused opens; want %s still waiting", m, member)
	}
}

// A warm-only open counts toward the pool's demand only once it gets a member: one
// refused for want of a member costs its caller nothing, so counted, a caller could
// steer every member to the languages it names (found in review, 2026-10-28; it was
// counted before the claim until then).
func TestWarmOnlyOpenCountsTowardDemandOnlyWithAMember(t *testing.T) {
	_, p, _ := bareProvider(t)
	p.mu.Lock()
	p.smoke = &smokeEvidence{Languages: []sandbox.Language{sandbox.LanguageJavaScript, sandbox.LanguagePython}}
	p.mu.Unlock()
	pool := startBarePool(t, p, 1)
	python := sandbox.SessionOptions{Lifetime: time.Minute, WarmOnly: true, Languages: []sandbox.Language{sandbox.LanguagePython}}
	before := pool.Demand()
	got, err := p.OpenSession(context.Background(), python)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Close(context.Background())
	claimed := pool.Demand()
	if maps.Equal(claimed, before) {
		t.Fatalf("a warm-only open that got a member left the demand at %v; want it counted", before)
	}
	if err := pool.Close(context.Background()); err != nil { // none waits from here, and none is made
		t.Fatal(err)
	}
	for range 20 {
		_, err := p.OpenSession(context.Background(), python)
		if !errors.Is(err, sandbox.ErrNoWarmSandbox) {
			t.Fatalf("a warm-only open with none waiting = %v; want refused", err)
		}
	}
	if got := pool.Demand(); !maps.Equal(got, claimed) {
		t.Fatalf("20 refused warm-only opens for Python moved the demand from %v to %v", claimed, got)
	}
}

// A member made under another gateway version is not handed over: it is deleted, and
// the open creates its sandbox as it would without a pool.
func TestPoolMemberOfAnotherGatewayVersionIsNotHandedOver(t *testing.T) {
	f, p, _ := bareProvider(t)
	pool := startBarePool(t, p, 1)
	member := pool.Members()[0]
	f.mu.Lock()
	f.info = func() (*openshellv1.GetGatewayInfoResponse, error) {
		info, err := dockerInfo()
		info.GatewayVersion = "0.1.2+upgraded"
		return info, err
	}
	f.mu.Unlock()
	got, err := p.OpenSession(context.Background(), sandbox.SessionOptions{Lifetime: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	defer got.Close(context.Background())
	if got.(*session).b.name == member {
		t.Fatal("a member made under another gateway version was handed over")
	}
	waitFor(t, "the stale member's delete", func() bool { return !slices.Contains(f.live(), member) })
}

// A member that may not outlive what its sandbox declares is not handed to a session
// asking for a longer lifetime than the pool was started for.
func TestPoolMemberIsNotHandedToALongerLifetime(t *testing.T) {
	_, p, _ := bareProvider(t)
	pool := startBarePool(t, p, 1)
	member := pool.Members()[0]
	got, err := p.OpenSession(context.Background(), sandbox.SessionOptions{Lifetime: poolkit.MaxIdle + testPoolLifetime + time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer got.Close(context.Background())
	if got.(*session).b.name == member {
		t.Fatal("a member was handed to a session that outlives its declared lifetime")
	}
}

// Drain stops the pool and deletes its waiting members before it returns.
func TestDrainDeletesWaitingMembers(t *testing.T) {
	f, p, _ := bareProvider(t)
	pool := startBarePool(t, p, 2)
	waitFor(t, "two members", func() bool { return len(pool.Members()) == 2 })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := p.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	if live := f.live(); len(live) != 0 || p.leases.Len() != 0 {
		t.Fatalf("after Drain: live %v, %d tracked; want none", live, p.leases.Len())
	}
	if err := p.StartSessionPool(context.Background(), 1, time.Minute); err == nil {
		t.Fatal("a second pool started")
	}
}

// A member whose interpreter will not start is deleted, and a pool whose first member
// fails does not start: the fake answers the launcher with a payload's "ok", which is
// no launch report.
func TestPoolWhoseMemberCannotWarmDoesNotStart(t *testing.T) {
	f, p, _ := bareProvider(t)
	err := p.StartSessionPool(context.Background(), 1, testPoolLifetime)
	if err == nil || !strings.Contains(err.Error(), "starting the javascript interpreter") {
		t.Fatalf("StartSessionPool = %v; want the interpreter's failure", err)
	}
	if p.sessionPool.Load() != nil {
		t.Fatal("a pool that failed to start stayed installed")
	}
	waitFor(t, "the failed member's delete", func() bool { return len(f.live()) == 0 && p.leases.Len() == 0 })
}

// A warm-only open takes a waiting member, and with none to hand over (no pool, or a
// pool with none waiting) is refused and creates nothing.
func TestWarmOnlyOpenOnOpenShellCreatesNothing(t *testing.T) {
	f, p, _ := bareProvider(t)
	warmOnly := sandbox.SessionOptions{Lifetime: time.Minute, WarmOnly: true}
	_, err := p.OpenSession(context.Background(), warmOnly)
	if reason, ok := sandbox.NotDispatchedReason(err); !ok || reason != sandbox.RefusalCapacity || !errors.Is(err, sandbox.ErrNoWarmSandbox) {
		t.Fatalf("a warm-only open with no pool = %v; want refused, capacity", err)
	}
	if n := f.called("CreateSandbox"); n != 0 {
		t.Fatalf("%d creates for a warm-only open with no pool", n)
	}
	pool := startBarePool(t, p, 1)
	member := pool.Members()[0]
	got, err := p.OpenSession(context.Background(), warmOnly)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Close(context.Background())
	if got.(*session).b.name != member {
		t.Fatalf("a warm-only open got %s; want the waiting member %s", got.(*session).b.name, member)
	}
	if err := pool.Close(context.Background()); err != nil { // none waits from here, and none is made
		t.Fatal(err)
	}
	creates := f.called("CreateSandbox")
	_, err = p.OpenSession(context.Background(), warmOnly)
	if !errors.Is(err, sandbox.ErrNoWarmSandbox) || f.called("CreateSandbox") != creates {
		t.Fatalf("a warm-only open with none waiting = %v after %d creates; want refused and none", err, f.called("CreateSandbox")-creates)
	}
}
