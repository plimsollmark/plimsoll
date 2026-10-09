package rpc

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/internal/clientconfig"
	"github.com/plimsollmark/plimsoll/protocol"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// A run reserves its whole possible cost, is charged what it took, and gives the rest
// back; a reservation that would take a caller, or the daemon, past its allowance for
// the day is refused not dispatched, reason capacity. A new UTC day starts from zero,
// and a run settled after midnight charges nothing to the new day.
func TestSpendCapReservesChargesAndRefuses(t *testing.T) {
	now := time.Date(2026, 10, 3, 23, 0, 0, 0, time.UTC)
	c := NewSpendCap(1000)
	c.now = func() time.Time { return now }

	settle, err := c.reserve("alice", 300, 200*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got := settle(30*time.Second, time.Time{}); got != 30 {
		t.Fatalf("charged %v; want 30", got)
	}
	settle(time.Hour, time.Time{}) // settling twice changes nothing
	if a, total := c.spent("alice"); a != 30 || total != 30 {
		t.Fatalf("after one run: alice %v, total %v; want 30 and 30", a, total)
	}
	if _, err := c.reserve("alice", 300, 271*time.Second); !refusedCapacity(err) {
		t.Fatalf("a reservation past alice's allowance: %v; want refused, not dispatched, capacity", err)
	}
	long, err := c.reserve("alice", 300, 270*time.Second)
	if err != nil {
		t.Fatalf("a reservation that fits exactly: %v", err)
	}
	if got := long(10*time.Hour, time.Time{}); got != 270 {
		t.Fatalf("a run longer than its reservation charged %v; want the reservation, 270", got)
	}

	// The daemon-wide allowance binds across callers; a caller without one of its
	// own (0) is bound by it alone.
	if _, err := c.reserve("bob", 0, 701*time.Second); !refusedCapacity(err) {
		t.Fatalf("a reservation past the daemon's allowance: %v; want refused", err)
	}
	late, err := c.reserve("bob", 0, 700*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	now = now.Add(2 * time.Hour) // a new UTC day
	if got := late(time.Second, time.Time{}); got != 1 {
		t.Fatalf("charged %v; want 1", got)
	}
	if a, total := c.spent("alice"); a != 0 || total != 0 {
		t.Fatalf("on a new day: alice %v, total %v; want 0 and 0 (yesterday's run settles into yesterday)", a, total)
	}
}

func refusedCapacity(err error) bool {
	reason, marked := notDispatchedOf(err)
	return marked && reason == plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_CAPACITY && connect.CodeOf(err) == connect.CodeResourceExhausted
}

// A run reserves its timeout as it will be clamped, plus the provider's teardown
// bound: the provider's ceiling when the request leaves the timeout to the provider's
// default or asks for more, and never past the RPC ceiling.
func TestSpendReservation(t *testing.T) {
	const teardown = 33 * time.Second
	for _, tc := range []struct{ requested, ceiling, want time.Duration }{
		{30 * time.Second, 2 * time.Minute, 30*time.Second + teardown},
		{0, 2 * time.Minute, 2*time.Minute + teardown},
		{time.Hour, 2 * time.Minute, 2*time.Minute + teardown},
		{0, 0, maxRunTimeout + teardown},
		{0, time.Hour, maxRunTimeout + teardown},
	} {
		if got := reservation(tc.requested, tc.ceiling, teardown); got != tc.want {
			t.Errorf("reservation(%v, %v) = %v; want %v", tc.requested, tc.ceiling, got, tc.want)
		}
	}
}

// The providers that bill by the second say so, with their teardown bound, through
// the admission wrapper too; the others do not. Dropping BillingTeardown would
// silently lift every cap on E2B or Docker Cloud.
func TestWhichProvidersAreMetered(t *testing.T) {
	for name, p := range map[string]sandbox.Sandbox{"e2b": &sandbox.E2B{}, "dockercloud": &sandbox.DockerCloud{}} {
		if sandbox.MeteredTeardown(p) <= 0 {
			t.Errorf("%s does not state that it bills by the second", name)
		}
		wrapped, err := sandbox.WithAdmission(p, sandbox.AdmissionConfig{MaxConcurrent: 1})
		if err != nil {
			t.Fatal(err)
		}
		if sandbox.MeteredTeardown(wrapped) != sandbox.MeteredTeardown(p) {
			t.Errorf("%s behind the admission wrapper loses its teardown bound", name)
		}
	}
	for name, p := range map[string]sandbox.Sandbox{"docker": sandbox.DefaultDocker(""), "wasm": sandbox.DefaultWasm(), "disabled": sandbox.Disabled{}} {
		if sandbox.IsMetered(p) {
			t.Errorf("%s says it bills by the second", name)
		}
	}
}

// meteredFake is a provider billed by the second whose snippets take one second.
type meteredFake struct{ fakeSandbox }

func (*meteredFake) BillingTeardown() time.Duration { return 30 * time.Second }
func (*meteredFake) SupportsModules() bool          { return false }
func (*meteredFake) Environments() sandbox.Environments {
	return sandbox.Environments{JavaScript: sandbox.PayloadEnvironment{MaxTimeout: 10 * time.Second}}
}
func (f *meteredFake) RunJavaScript(context.Context, sandbox.Request) (sandbox.Result, error) {
	time.Sleep(50 * time.Millisecond)
	return sandbox.Result{Stdout: "ok", Sandbox: "fake", Isolation: sandbox.IsolationVM}, nil
}

// Through Run: a metered provider's run draws on the caller's allowance, its audit
// line states the seconds charged, and a run the allowance cannot cover is refused
// before admission, spending no rate token. A provider that is not metered draws on
// nothing.
func TestMeteredRunsDrawOnTheCallersAllowance(t *testing.T) {
	var logs bytes.Buffer
	svc := NewSandboxService(&meteredFake{})
	svc.Logger = slog.New(slog.NewJSONHandler(&logs, nil))
	svc.Spend = NewSpendCap(0)
	svc.Limiter = NewCodeLimiter(10, 10, 1, 2)
	ctx := context.WithValue(context.Background(), principalKey{}, Principal{UserID: "alice", Scopes: []string{ScopeCodeRun}, PaidSecondsPerDay: 150})
	run := func(timeoutMs int32) error {
		_, err := svc.Run(ctx, connect.NewRequest(&plimsollv1.RunRequest{Protocol: protocol.Number, TimeoutMs: timeoutMs,
			Payload: &plimsollv1.RunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: "1"}}}))
		return err
	}
	if err := run(5000); err != nil { // reserves 35 s, charged about 0.05
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), `"paid_seconds":0.0`) {
		t.Fatalf("the audit line does not state the seconds charged: %s", logs.String())
	}
	if a, _ := svc.Spend.spent("alice"); a <= 0 || a > 1 {
		t.Fatalf("alice spent %v; want the run's fraction of a second", a)
	}
	svc.Spend = NewSpendCap(0)
	ctx = context.WithValue(context.Background(), principalKey{}, Principal{UserID: "alice", Scopes: []string{ScopeCodeRun}, PaidSecondsPerDay: 30})
	if err := run(5000); !refusedCapacity(err) { // reserves 35 s of 30
		t.Fatalf("a run its allowance cannot cover: %v; want refused, not dispatched, capacity", err)
	}
	ctx = context.WithValue(context.Background(), principalKey{}, Principal{UserID: "alice", Scopes: []string{ScopeCodeRun}, PaidSecondsPerDay: 1000})
	if err := run(5000); err != nil {
		t.Fatalf("the run after a refused one: %v (the refusal spent the rate token)", err)
	}

	plain := NewSandboxService(&fakeSandbox{})
	plain.Spend = NewSpendCap(1)
	if _, err := plain.Run(ctx, connect.NewRequest(&plimsollv1.RunRequest{Protocol: protocol.Number,
		Payload: &plimsollv1.RunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: "1"}}})); err != nil {
		t.Fatalf("a provider that is not metered was capped: %v", err)
	}
}

// A run the provider cannot run reserves nothing, so it is refused as unsupported,
// not as a spent allowance; a provider that panics still settles its reservation.
func TestMeteredRefusalsAndPanicsDoNotHoldTheAllowance(t *testing.T) {
	svc := NewSandboxService(&meteredFake{})
	svc.Spend = NewSpendCap(40) // one 5 s run reserves 35 s
	ctx := context.WithValue(context.Background(), principalKey{}, Principal{UserID: "alice", Scopes: []string{ScopeCodeRun}})
	_, err := svc.Run(ctx, connect.NewRequest(&plimsollv1.RunRequest{Protocol: protocol.Number, TimeoutMs: 5000,
		Payload: &plimsollv1.RunRequest_Module{Module: &plimsollv1.ModuleRun{Model: "vanderpol", Rows: []*plimsollv1.ModuleRow{{Values: []float64{1}}}, EndTime: 1, Step: 0.5}}}))
	if connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("a module run on a provider without modules: %v (%s); want unimplemented, not a spent allowance", err, connect.CodeOf(err))
	}
	if _, total := svc.Spend.spent("alice"); total != 0 {
		t.Fatalf("an unsupported run held %v seconds", total)
	}

	panicky := NewSandboxService(&panickingMetered{})
	panicky.Spend = NewSpendCap(40)
	func() {
		defer func() { _ = recover() }()
		_, _ = panicky.Run(ctx, connect.NewRequest(&plimsollv1.RunRequest{Protocol: protocol.Number, TimeoutMs: 5000,
			Payload: &plimsollv1.RunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: "1"}}}))
	}()
	if _, total := panicky.Spend.spent("alice"); total <= 0 || total > 1 {
		t.Fatalf("after a panic the daemon holds %v seconds; want the fraction the run took, not its 35 s reservation", total)
	}
}

type panickingMetered struct{ meteredFake }

func (*panickingMetered) RunJavaScript(context.Context, sandbox.Request) (sandbox.Result, error) {
	panic("the provider failed")
}

// The clients file's allowance reaches the caller's principal, and Uncapped names the
// callers without one.
func TestClientsCarryTheirAllowance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clients.json")
	tok := strings.Repeat("a", 40)
	other := strings.Repeat("b", 40)
	body := fmt.Sprintf(`{"clients":[{"id":"alice","token_sha256":%q,"scopes":["code:run"],"paid_seconds_per_day":600},{"id":"bob","token_sha256":%q,"scopes":["code:run"]}]}`,
		clientconfig.Fingerprint(tok), clientconfig.Fingerprint(other))
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := LoadClients(path)
	if err != nil {
		t.Fatal(err)
	}
	p, ok, err := v.VerifyToken(context.Background(), tok)
	if err != nil || !ok || p.PaidSecondsPerDay != 600 {
		t.Fatalf("alice: %+v, %v, %v", p, ok, err)
	}
	if got := v.Uncapped(); len(got) != 1 || got[0] != "bob" {
		t.Fatalf("Uncapped = %v; want [bob]", got)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(body, "600", "-1", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadClients(path); err == nil {
		t.Fatal("a negative allowance loaded")
	}
}

// A run whose microVM the provider could not delete is charged its whole reservation:
// the microVM bills until the provider's own lifetime for it ends, so the rest of the
// reservation is not given back for later calls to spend.
func TestALeakedMicroVMIsChargedItsWholeReservation(t *testing.T) {
	var logs bytes.Buffer
	svc := NewSandboxService(&leakingMetered{})
	svc.Logger = slog.New(slog.NewJSONHandler(&logs, nil))
	svc.Spend = NewSpendCap(0)
	ctx := context.WithValue(context.Background(), principalKey{}, Principal{UserID: "alice", Scopes: []string{ScopeCodeRun}})
	if _, err := svc.Run(ctx, connect.NewRequest(&plimsollv1.RunRequest{Protocol: protocol.Number, TimeoutMs: 5000,
		Payload: &plimsollv1.RunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: "1"}}})); err != nil {
		t.Fatal(err)
	}
	if _, total := svc.Spend.spent("alice"); total != 35 { // 5 s timeout + 30 s teardown bound
		t.Fatalf("a run whose microVM leaked was charged %v seconds; want its whole 35 s reservation", total)
	}
	if !strings.Contains(logs.String(), `"teardown_gave_up":true`) {
		t.Fatalf("the audit line does not say the delete gave up: %s", logs.String())
	}
}

type leakingMetered struct{ meteredFake }

func (*leakingMetered) RunJavaScript(ctx context.Context, _ sandbox.Request) (sandbox.Result, error) {
	sandbox.TeardownGaveUp(ctx)
	return sandbox.Result{Stdout: "ok", Sandbox: "fake", Isolation: sandbox.IsolationVM}, nil
}

// A run that crosses midnight spends seconds of the new day: it is counted in the new
// day in full while it runs, so the new day's allowance cannot be spent twice over,
// and charged to it for the part it ran after midnight when it settles (a run
// previously counted only in the day it started).
func TestARunAcrossMidnightCountsInTheNewDay(t *testing.T) {
	now := time.Date(2026, 10, 3, 23, 59, 0, 0, time.UTC)
	c := NewSpendCap(150)
	c.now = func() time.Time { return now }
	settle, err := c.reserve("alice", 0, 100*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(80 * time.Second) // 00:00:20 of the new day, the run still going
	if _, total := c.spent("alice"); total != 100 {
		t.Fatalf("the new day holds %v seconds while the run crossing midnight runs; want its 100", total)
	}
	if _, err := c.reserve("bob", 0, 60*time.Second); !refusedCapacity(err) {
		t.Fatalf("the new day's allowance spent twice over: %v", err)
	}
	if got := settle(90*time.Second, time.Time{}); got != 90 {
		t.Fatalf("charged %v; want the 90 s it took", got)
	}
	if _, total := c.spent("alice"); total != 30 {
		t.Fatalf("the new day holds %v seconds; want the 30 the run ran after midnight", total)
	}

	// The same when the run's settle is the first thing the cap sees after midnight.
	now = time.Date(2026, 10, 4, 23, 59, 0, 0, time.UTC)
	settle, err = c.reserve("alice", 0, 100*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(80 * time.Second)
	settle(90*time.Second, time.Time{})
	if _, total := c.spent("alice"); total != 30 {
		t.Fatalf("a run settling first after midnight left the new day %v seconds; want the 30 it ran after midnight", total)
	}
}

// A session's meter holds one reservation while its sandbox runs: a cover inside what is
// held changes nothing, one past it charges what ran and holds the new reach from now,
// and a stop charges what ran and holds nothing, so a suspended session spends nothing.
func TestSessionMeterChargesOnlyRunningTime(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	c := NewSpendCap(0)
	c.now = func() time.Time { return now }
	spent := func() float64 { a, _ := c.spent("alice"); return a }
	m := c.meter("alice", 1000)
	if err := m.cover(100 * time.Second); err != nil {
		t.Fatal(err)
	}
	if got := spent(); got != 100 {
		t.Fatalf("after the open's cover: %v held, want 100", got)
	}
	now = now.Add(10 * time.Second)
	if err := m.cover(5 * time.Second); err != nil || spent() != 100 {
		t.Fatalf("a cover inside what is held: err %v, %v held; want nothing changed", err, spent())
	}
	now = now.Add(80 * time.Second) // 90 s since the open
	if err := m.cover(100 * time.Second); err != nil || spent() != 190 {
		t.Fatalf("a cover past what is held: err %v, %v; want 90 charged and 100 held", err, spent())
	}
	now = now.Add(30 * time.Second)
	if got := m.stop(); got != 120 || spent() != 120 || m.running() {
		t.Fatalf("stop: charged %v, %v spent, running %v; want 120, 120, false", got, spent(), m.running())
	}
	now = now.Add(time.Hour) // suspended: nothing bills
	if err := m.cover(50 * time.Second); err != nil || spent() != 170 {
		t.Fatalf("the cover that resumes: err %v, %v; want 50 more held", err, spent())
	}
	now = now.Add(5 * time.Second)
	if got := m.stop(); got != 125 || spent() != 125 {
		t.Fatalf("after the second span: charged %v, %v spent; want 125", got, spent())
	}
}

// A cover the allowance cannot take is refused, not dispatched, reason capacity, in the
// session's words, and the session stays covered as far as it was.
func TestSessionMeterRefusalKeepsTheSessionCovered(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	c := NewSpendCap(0)
	c.now = func() time.Time { return now }
	spent := func() float64 { a, _ := c.spent("alice"); return a }
	m := c.meter("alice", 150)
	if err := m.cover(100 * time.Second); err != nil {
		t.Fatal(err)
	}
	now = now.Add(40 * time.Second)
	err := m.cover(120 * time.Second) // 40 charged + 120 held > 150
	if !refusedCapacity(err) || !strings.Contains(err.Error(), "this session reserves 120") {
		t.Fatalf("a cover past the allowance: %v; want refused, capacity, naming the session", err)
	}
	if got := spent(); got != 100 || !m.running() {
		t.Fatalf("after the refusal: %v spent, running %v; want the original 100 still covered", got, m.running())
	}
	now = now.Add(60 * time.Second)
	if got := m.stop(); got != 100 || spent() != 100 {
		t.Fatalf("stop: charged %v, %v spent; want 100", got, spent())
	}
}

// A run whose delete gave up is charged its whole reservation, because its microVM
// bills until the window that reservation covers ends. Settled before midnight with
// that window reaching past it, the part after midnight is the new day's (round-3
// review: it left the books at the settle, so the new day's allowance never saw it).
func TestALeakedRunSettledBeforeMidnightCountsInTheNewDay(t *testing.T) {
	now := time.Date(2026, 10, 3, 23, 59, 0, 0, time.UTC)
	c := NewSpendCap(1000)
	c.now = func() time.Time { return now }
	settle, err := c.reserve("alice", 0, 100*time.Second) // window ends 00:00:40
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(5 * time.Second)
	if got := settle(100*time.Second, time.Time{}); got != 100 { // leaked: charged the whole window
		t.Fatalf("charged %v, want the whole 100", got)
	}
	now = time.Date(2026, 10, 4, 0, 0, 1, 0, time.UTC)
	if caller, total := c.spent("alice"); caller != 40 || total != 40 {
		t.Fatalf("the new day holds %v (caller) and %v (daemon); want the 40 s the leak bills after midnight", caller, total)
	}
	now = time.Date(2026, 10, 5, 0, 0, 1, 0, time.UTC)
	if caller, _ := c.spent("alice"); caller != 0 {
		t.Fatalf("the day after holds %v; the window ended the day before", caller)
	}
}

// A leaked run owes until the time the provider said its sandbox bills until, when
// that is past the reservation's window: a slow create starts the provider's clock late,
// so the sandbox can bill past the window, and the books let it go at the window's end
// and at the midnight in between (round-7 review, 2026-10-08).
func TestALeakedRunOwesUntilTheProvidersDeadline(t *testing.T) {
	now := time.Date(2026, 10, 3, 23, 59, 0, 0, time.UTC)
	c := NewSpendCap(1000)
	c.now = func() time.Time { return now }
	settle, err := c.reserve("alice", 0, 100*time.Second) // window ends 00:00:40
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(5 * time.Second)
	bills := time.Date(2026, 10, 4, 0, 1, 40, 0, time.UTC) // 60 s past the window
	if got := settle(100*time.Second, bills); got != 160 {
		t.Fatalf("charged %v, want the window's 100 and the 60 s past it", got)
	}
	if caller, _ := c.spent("alice"); caller != 160 {
		t.Fatalf("today holds %v; want 160", caller)
	}
	now = time.Date(2026, 10, 4, 0, 0, 1, 0, time.UTC)
	if caller, total := c.spent("alice"); caller != 100 || total != 100 {
		t.Fatalf("the new day holds %v (caller) and %v (daemon); want the 100 s the leak bills after midnight", caller, total)
	}
	// A deadline inside the window changes nothing.
	now = time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	settle, err = c.reserve("bob", 0, 100*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got := settle(100*time.Second, now.Add(50*time.Second)); got != 100 {
		t.Fatalf("charged %v, want the window's 100 only", got)
	}
}

// owe charges a sandbox that bills on after its delete gave up from now to the end of
// the provider's own lifetime for it, never refused, and each midnight before that end
// counts the rest in the new day.
func TestOweChargesALeakedSandboxAcrossMidnight(t *testing.T) {
	now := time.Date(2026, 10, 3, 23, 0, 0, 0, time.UTC)
	c := NewSpendCap(100)
	c.now = func() time.Time { return now }
	if got := c.owe("alice", now.Add(2*time.Hour)); got != 7200 {
		t.Fatalf("owed %v, want 7200", got)
	}
	if caller, total := c.spent("alice"); caller != 7200 || total != 7200 {
		t.Fatalf("today holds %v and %v; want 7200 each, past the allowance (never refused)", caller, total)
	}
	if _, err := c.reserve("bob", 0, time.Second); !refusedCapacity(err) {
		t.Fatalf("a run was admitted on an allowance the leak spent: %v", err)
	}
	now = time.Date(2026, 10, 4, 0, 30, 0, 0, time.UTC)
	if caller, _ := c.spent("alice"); caller != 3600 {
		t.Fatalf("the new day holds %v; want the 3600 s the leak bills after midnight", caller)
	}
	if got := c.owe("alice", now.Add(-time.Minute)); got != 0 {
		t.Fatalf("owed %v for an end already past", got)
	}
}
