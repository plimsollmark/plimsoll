package rpc

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/internal/auditline"
	"github.com/plimsollmark/plimsoll/internal/withheld"
	"github.com/plimsollmark/plimsoll/protocol"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// The harness's source and a held-out seed, as the hackathon shipped them: the source
// under another name, the seed in a step's arguments.
const (
	harnessSource = "def step(state, u, dt):\n    return state + dt * (u - 0.3 * state)\n"
	heldOutSeed   = "731904"
	hiddenAnswer  = "0.7321"
)

func withheldSetOf(t *testing.T, mode withheld.Mode, exempt []string, entries ...map[string]any) *withheld.Set {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"version": withheld.Version, "mode": mode, "exempt_callers": exempt, "entries": entries})
	if err != nil {
		t.Fatal(err)
	}
	set, err := withheld.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func withheldValue(v, label string, mode withheld.Mode) map[string]any {
	d := withheld.ValueDigest([]byte(v))
	return map[string]any{"kind": "value", "sha256": hex.EncodeToString(d[:]), "length": len(v), "label": label, "mode": mode}
}

func withheldFile(content, label string, mode withheld.Mode) map[string]any {
	d := withheld.FileDigest([]byte(content))
	return map[string]any{"kind": "file", "sha256": hex.EncodeToString(d[:]), "label": label, "mode": mode}
}

// leakyProject ships the harness source as helpers/model.py and the seed as an argument.
func leakyProject(svc *SandboxService, ctx context.Context) (*plimsollv1.RunResponse, error) {
	resp, err := svc.Run(ctx, connect.NewRequest(&plimsollv1.RunRequest{Protocol: protocol.Number, TraceId: "episode-7",
		Payload: &plimsollv1.RunRequest_Project{Project: &plimsollv1.ProjectRun{
			Files: []*plimsollv1.ProjectFile{{Path: "agent.py", Content: "print('hi')"}, {Path: "helpers/model.py", Content: harnessSource}},
			Steps: []string{"python agent.py --seed " + heldOutSeed},
		}}}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

func snippet(svc *SandboxService, ctx context.Context, code string) (*plimsollv1.RunResponse, error) {
	resp, err := svc.Run(ctx, connect.NewRequest(&plimsollv1.RunRequest{Protocol: protocol.Number,
		Payload: &plimsollv1.RunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: code}}}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

func scanService(set *withheld.Set) (*SandboxService, *fakeSandbox, *bytes.Buffer) {
	fake := &fakeSandbox{
		jsResult:   sandbox.Result{Sandbox: "fake", Isolation: sandbox.IsolationVM},
		projResult: sandbox.ProjectResult{Sandbox: "fake", Isolation: sandbox.IsolationVM, Outcome: sandbox.ProjectOutcomeCompleted},
		modResult: sandbox.ModuleResult{Sandbox: "fake", Isolation: sandbox.IsolationVM, Outcome: sandbox.ProjectOutcomeCompleted,
			Width: 1, Runs: []sandbox.ModuleRun{{Status: 10, Outputs: []float64{1}}}},
	}
	svc := NewSandboxService(fake)
	svc.Withheld = set
	var buf bytes.Buffer
	svc.Logger = slog.New(slog.NewJSONHandler(&buf, nil))
	return svc, fake, &buf
}

// runLines decodes the run lines logged so far and empties the log.
func runLines(t *testing.T, logs *bytes.Buffer) []auditline.Run {
	t.Helper()
	runs, err := auditline.Parse(logs)
	if err != nil {
		t.Fatal(err)
	}
	logs.Reset()
	return runs
}

// A refuse-mode find ends the call before admission, marked not dispatched: the
// provider never sees it, it takes no slot and is not counted as a run, and the
// caller is told which entries and where, by label and by place, never with the content.
func TestShipScanRefusesBeforeAdmission(t *testing.T) {
	set := withheldSetOf(t, withheld.ModeRefuse, nil,
		withheldFile(harnessSource, "harness/sim.py", ""),
		withheldValue(heldOutSeed, "seeds.txt:3", ""),
		withheldValue(hiddenAnswer, "answers.txt:1", withheld.ModeAudit))
	svc, fake, logs := scanService(set)
	svc.Limiter = NewCodeLimiter(10, 10, 2, 2) // two calls a minute: the refusal spends one, on its scan
	_, err := leakyProject(svc, authenticatedContext("agent-harness"))
	reason, marked := notDispatchedOf(err)
	if connect.CodeOf(err) != connect.CodePermissionDenied || !marked || reason != plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_PERMISSION {
		t.Fatalf("got %v (marked %v, %v); want PermissionDenied, not dispatched, permission", err, marked, reason)
	}
	msg := err.Error()
	for _, want := range []string{"harness/sim.py (files[1].content)", "seeds.txt:3 (steps[0])"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not name %q: %s", want, msg)
		}
	}
	for _, leak := range []string{heldOutSeed, "helpers/model.py", "def step", "answers.txt"} {
		if strings.Contains(msg, leak) {
			t.Errorf("the refusal repeats %q: %s", leak, msg)
		}
	}
	if fake.lastProj.Files != nil {
		t.Error("the provider was handed a refused call")
	}
	if total, _ := svc.RunCounts(); total != 0 {
		t.Errorf("a refused call counted as %d runs", total)
	}
	line := logs.String()
	if !strings.Contains(line, `"msg":"withheld material refused"`) || !strings.Contains(line, `"withheld_found":["harness/sim.py","seeds.txt:3"]`) ||
		!strings.Contains(line, `"trace_id":"episode-7"`) || !strings.Contains(line, `"withheld_refused":true`) {
		t.Errorf("the refusal's audit line: %s", line)
	}
	for _, leak := range []string{heldOutSeed, "helpers/model.py", "def step"} {
		if strings.Contains(line, leak) {
			t.Errorf("the audit line repeats %q: %s", leak, line)
		}
	}
	logs.Reset()
	// A call carrying none of it runs, scanned, on the rate token the refusal left.
	if _, err := snippet(svc, authenticatedContext("agent-harness"), "console.log(1)"); err != nil {
		t.Fatalf("the clean call after a refusal: %v", err)
	}
	if runs := runLines(t, logs); len(runs) != 1 || runs[0].WithheldScan != withheldScanned || runs[0].WithheldSet != set.Digest() || runs[0].WithheldFound != nil {
		t.Fatalf("a clean call's audit line: %+v", runs)
	}
}

// An audit-mode find runs the call and is named on the operator's audit line alone:
// nothing in the response, which a caller could relay to the agent, says it.
func TestShipScanAuditsForTheOperatorAlone(t *testing.T) {
	set := withheldSetOf(t, withheld.ModeAudit, nil,
		withheldValue(heldOutSeed, "seeds.txt:3", ""),
		withheldValue(hiddenAnswer, "answers.txt:1", ""))
	svc, fake, logs := scanService(set)
	resp, err := snippet(svc, authenticatedContext("agent-harness"), "const seed = "+heldOutSeed+"; print("+hiddenAnswer+")")
	if err != nil {
		t.Fatal(err)
	}
	if fake.lastReq.Code == "" {
		t.Fatal("the call did not run")
	}
	runs := runLines(t, logs)
	if len(runs) != 1 || runs[0].WithheldScan != withheldScanned || !reflect.DeepEqual(runs[0].WithheldFound, []string{"seeds.txt:3", "answers.txt:1"}) {
		t.Fatalf("audit line: %+v", runs)
	}
	wire, err := protojson.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"seeds.txt", "answers.txt", "withheld", set.Digest()} {
		if strings.Contains(string(wire), leak) {
			t.Errorf("the response states %q: %s", leak, wire)
		}
	}
}

// The judge ships the hidden cases into its own runs, so its caller is exempt; nobody
// else is: not an anonymous caller, not a caller whose scope is the wildcard.
func TestShipScanExemptsOnlyTheListedCaller(t *testing.T) {
	set := withheldSetOf(t, withheld.ModeRefuse, []string{"judge"}, withheldValue(heldOutSeed, "seeds.txt:3", ""))
	svc, _, logs := scanService(set)
	if _, err := leakyProject(svc, authenticatedContext("judge")); err != nil {
		t.Fatalf("the exempt caller was refused: %v", err)
	}
	if runs := runLines(t, logs); len(runs) != 1 || runs[0].WithheldScan != withheldExempt || runs[0].WithheldFound != nil {
		t.Fatalf("the exempt caller's audit line: %+v", runs)
	}
	wildcard := context.WithValue(context.Background(), principalKey{}, Principal{UserID: "admin", Scopes: []string{"*"}})
	for name, ctx := range map[string]context.Context{"anonymous": context.Background(), "wildcard scope": wildcard, "another caller": authenticatedContext("agent")} {
		if _, err := leakyProject(svc, ctx); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Errorf("%s: %v; want the refusal", name, err)
		}
	}
}

// A module run carries no file: it is stated as not scanned, never as clean. Without
// a set there is no statement at all.
func TestShipScanStatesWhatItDidNotRead(t *testing.T) {
	set := withheldSetOf(t, withheld.ModeRefuse, nil, withheldValue(heldOutSeed, "seeds.txt:3", ""))
	svc, _, logs := scanService(set)
	if _, err := runMod(svc, context.Background()); err != nil {
		t.Fatal(err)
	}
	if runs := runLines(t, logs); len(runs) != 1 || runs[0].WithheldScan != withheldNotScanned || runs[0].WithheldSet != set.Digest() {
		t.Fatalf("module audit line: %+v", runs)
	}
	svc, _, logs = scanService(nil)
	if _, err := snippet(svc, context.Background(), heldOutSeed); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logs.String(), "withheld") {
		t.Fatalf("a daemon without a set stated a scan: %s", logs.String())
	}
}

// A session call is scanned like a run, and one refused is not chained: the next call
// is the session's first.
func TestShipScanRefusesASessionCallOutsideTheChain(t *testing.T) {
	svc, _ := sessionService()
	svc.Withheld = withheldSetOf(t, withheld.ModeRefuse, nil, withheldValue(heldOutSeed, "seeds.txt:3", ""))
	var logs bytes.Buffer
	svc.Logger = slog.New(slog.NewJSONHandler(&logs, nil))
	ctx := authenticatedContext("alice")
	open, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	id := open.Msg.GetSessionId()
	_, err = svc.SessionRun(ctx, callReq(id, "const seed = "+heldOutSeed))
	if _, marked := notDispatchedOf(err); connect.CodeOf(err) != connect.CodePermissionDenied || !marked {
		t.Fatalf("the session call: %v; want PermissionDenied, not dispatched", err)
	}
	// The refusal's line names the session, so the operator can find which one.
	var refusal string
	for line := range strings.Lines(logs.String()) {
		if strings.Contains(line, `"msg":"withheld material refused"`) {
			refusal = line
		}
	}
	if !strings.Contains(refusal, `"session":"`+open.Msg.GetSession()+`"`) {
		t.Errorf("the session refusal's line does not name the session %s: %q", open.Msg.GetSession(), refusal)
	}
	req := callReq(id, "console.log(1)")
	resp, err := svc.SessionRun(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := record.CheckSessionCall(req.Msg, resp.Msg.GetRun(), open.Msg.GetSession(), 0, ""); err != nil {
		t.Fatalf("the call after the refusal is not the session's first: %v", err)
	}
}

// A call whose context ends while it waits for a scan slot is refused, not dispatched.
func TestShipScanWaitingForASlotEndsWithTheCall(t *testing.T) {
	set := withheldSetOf(t, withheld.ModeRefuse, nil, withheldValue(heldOutSeed, "seeds.txt:3", ""))
	svc, fake, _ := scanService(set)
	for range cap(scans.all) {
		scans.all <- struct{}{}
	}
	defer func() {
		for range cap(scans.all) {
			<-scans.all
		}
	}()
	ctx, cancel := context.WithCancel(authenticatedContext("agent-harness"))
	cancel()
	_, err := snippet(svc, ctx, "console.log(1)")
	reason, marked := notDispatchedOf(err)
	if !marked || reason != plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_CAPACITY || connect.CodeOf(err) != connect.CodeCanceled || fake.lastReq.Code != "" {
		t.Fatalf("a call ended while waiting: %v (marked %v, %v)", err, marked, reason)
	}
}

// acquire enters the gate and waits for a slot.
func (g *scanGate) acquire(ctx context.Context, caller string, b waitBound) (func(), error) {
	turn, err := g.enter(caller, b)
	if err != nil {
		return nil, err
	}
	return turn.wait(ctx)
}

// One caller holds at most its share of the scan slots: a second scan of its own
// waits, while another caller's scan goes ahead; and a caller's entry is gone once its
// scans are.
func TestScanGateSharesSlotsAmongCallers(t *testing.T) {
	g := newScanGate(4) // one slot per caller
	b := waitBound{all: 8, perCaller: 4}
	release, err := g.acquire(context.Background(), "a", b)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := g.acquire(ctx, "a", b); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a's second scan: %v; want it to wait past its deadline", err)
	}
	releaseB, err := g.acquire(context.Background(), "b", b)
	if err != nil {
		t.Fatalf("b waited behind a: %v", err)
	}
	release()
	releaseB()
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.callers) != 0 || len(g.all) != 0 || g.users != 0 {
		t.Fatalf("after every scan: %d callers, %d slots held, %d users", len(g.callers), len(g.all), g.users)
	}
}

// The calls waiting for a scan are bounded, for one caller and in all: the next call is
// refused at once, not dispatched, reason capacity, without waiting; a call that leaves
// frees its place; and the gate is empty once every call is gone.
func TestScanGateBoundsTheCallsWaiting(t *testing.T) {
	g := newScanGate(4) // four slots, one per caller
	b := waitBound{all: 3, perCaller: 2}
	refused := func(caller string) bool {
		t.Helper()
		turn, err := g.enter(caller, b)
		if err == nil {
			turn.leave()
			return false
		}
		if reason, marked := notDispatchedOf(err); !marked || reason != plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_CAPACITY ||
			connect.CodeOf(err) != connect.CodeResourceExhausted {
			t.Fatalf("%s refused as %v (marked %v, %v); want ResourceExhausted, not dispatched, capacity", caller, err, marked, reason)
		}
		return true
	}
	var turns []*scanTurn
	enter := func(caller string) {
		t.Helper()
		turn, err := g.enter(caller, b)
		if err != nil {
			t.Fatalf("%s within the bound: %v", caller, err)
		}
		turns = append(turns, turn)
	}
	// a: its slot and two waiting; a fourth is past a's bound, while b gets in.
	for range 3 {
		enter("a")
	}
	release, err := turns[0].wait(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !refused("a") {
		t.Fatal("a's call past its bound was let in to wait")
	}
	// The daemon's bound is its four slots and three more: b, c, d and e take it to
	// seven, and then even a caller with nothing waiting is refused.
	for _, c := range []string{"b", "c", "d", "e"} {
		enter(c)
	}
	if !refused("f") {
		t.Fatal("a call past the daemon's bound was let in to wait")
	}
	// A call that leaves without a slot frees its place.
	turns[len(turns)-1].leave()
	turns = turns[:len(turns)-1]
	if refused("f") {
		t.Fatal("a place freed by a call that left was not given")
	}
	release()
	for _, turn := range turns[1:] {
		turn.leave()
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.callers) != 0 || len(g.all) != 0 || g.users != 0 {
		t.Fatalf("after every call: %d callers, %d slots held, %d users", len(g.callers), len(g.all), g.users)
	}
}

// The scan takes the call's rate token before it runs, so SANDBOX_RATE_PER_MIN bounds
// the scan's work too: a call the scan refuses has spent its token, and the next call,
// with the rate spent, is refused at constant cost without being scanned (its audit-mode
// find is never made). Admission takes no second token: a run and a session call each
// cost one.
func TestShipScanTakesTheRateTokenFirst(t *testing.T) {
	set := withheldSetOf(t, withheld.ModeRefuse, nil,
		withheldValue(heldOutSeed, "seeds.txt:3", ""),
		withheldValue(hiddenAnswer, "answers.txt:1", withheld.ModeAudit))
	svc, fake, logs := scanService(set)
	svc.Limiter = NewCodeLimiter(10, 10, 1, 1) // one call a minute
	ctx := authenticatedContext("agent-harness")
	if _, err := snippet(svc, ctx, "const seed = "+heldOutSeed); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("the leaky call: %v; want the scan's refusal", err)
	}
	logs.Reset()
	_, err := snippet(svc, ctx, "print("+hiddenAnswer+")")
	if reason, marked := notDispatchedOf(err); !marked || reason != plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_CAPACITY ||
		!strings.Contains(err.Error(), "rate limit") || fake.lastReq.Code != "" {
		t.Fatalf("the call after the refusal: %v; want the rate refusal", err)
	}
	if strings.Contains(logs.String(), "withheld") {
		t.Fatalf("a call refused for its rate was scanned: %s", logs.String())
	}
	// One token a call: a scanned run on a rate of one, and a scanned session call on a
	// rate of two, the open's and its own.
	svc, _, _ = scanService(set)
	svc.Limiter = NewCodeLimiter(10, 10, 1, 1)
	if _, err := snippet(svc, ctx, "console.log(1)"); err != nil {
		t.Fatalf("a scanned run on a fresh token was charged twice: %v", err)
	}
	ssvc, _ := sessionService()
	ssvc.Withheld = set
	ssvc.Limiter = NewCodeLimiter(10, 10, 2, 2) // the open and one call
	open, err := ssvc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ssvc.SessionRun(ctx, callReq(open.Msg.GetSessionId(), "console.log(1)")); err != nil {
		t.Fatalf("a scanned session call was charged twice: %v", err)
	}
}

// A call past the wait bound is refused by the service at once, before admission and
// before it waits: it would otherwise hold its decoded request for as long as the calls
// ahead of it take. The bound is admission's: here one call per caller.
func TestShipScanRefusesPastTheWaitBound(t *testing.T) {
	set := withheldSetOf(t, withheld.ModeRefuse, nil, withheldValue(heldOutSeed, "seeds.txt:3", ""))
	svc, fake, _ := scanService(set)
	svc.Limiter = NewCodeLimiter(4, 1, 0, 0)
	b := svc.scanWaitBound()
	if b != (waitBound{all: 4, perCaller: 1}) {
		t.Fatalf("the wait bound is %+v; want admission's 4 in all and 1 per caller", b)
	}
	// The caller's slots are held and one more of its calls waits.
	var turns []*scanTurn
	for range scans.perCaller + b.perCaller {
		turn, err := scans.enter("agent-harness", b)
		if err != nil {
			t.Fatal(err)
		}
		turns = append(turns, turn)
	}
	var releases []func()
	for _, turn := range turns[:scans.perCaller] {
		release, err := turn.wait(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		releases = append(releases, release)
	}
	defer func() {
		for _, release := range releases {
			release()
		}
		turns[len(turns)-1].leave()
	}()
	ctx, cancel := context.WithTimeout(authenticatedContext("agent-harness"), 2*time.Second)
	defer cancel()
	started := time.Now()
	_, err := snippet(svc, ctx, "console.log(1)")
	reason, marked := notDispatchedOf(err)
	if !marked || reason != plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_CAPACITY || connect.CodeOf(err) != connect.CodeResourceExhausted ||
		fake.lastReq.Code != "" {
		t.Fatalf("a call past the bound: %v (marked %v, %v); want ResourceExhausted, not dispatched, capacity", err, marked, reason)
	}
	if took := time.Since(started); took > time.Second {
		t.Fatalf("the refusal took %v: the call waited", took)
	}
	// Another caller still gets its turn.
	if _, err := snippet(svc, authenticatedContext("agent-other"), "console.log(1)"); err != nil {
		t.Fatalf("another caller: %v", err)
	}
}

// An audit-mode find is written down when it is found: a call that admission then
// refuses (here for the caller's concurrency, its one slot held) never gets a run line,
// and its find is not lost.
func TestShipScanWritesAFindTheCallNeverRan(t *testing.T) {
	set := withheldSetOf(t, withheld.ModeAudit, nil, withheldValue(heldOutSeed, "seeds.txt:3", ""))
	svc, _, logs := scanService(set)
	svc.Limiter = NewCodeLimiter(10, 1, 0, 0) // one call at a time per caller
	release, err := svc.Limiter.Hold("agent-harness")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	_, err = snippet(svc, authenticatedContext("agent-harness"), "const seed = "+heldOutSeed)
	if reason, marked := notDispatchedOf(err); !marked || reason != plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_CAPACITY ||
		!strings.Contains(err.Error(), "per-caller concurrency") {
		t.Fatalf("the call: %v; want the concurrency refusal", err)
	}
	line := logs.String()
	if !strings.Contains(line, `"msg":"withheld material found"`) || !strings.Contains(line, `"withheld_found":["seeds.txt:3"]`) ||
		!strings.Contains(line, `"withheld_refused":false`) || strings.Contains(line, heldOutSeed) {
		t.Fatalf("the find's line: %s", line)
	}
}

// archiveFile is raw as the base64 command writes it, as a harness ships an archive in
// a call (file content must be UTF-8, so a raw .tar.gz cannot ship).
func archiveFile(raw []byte) string {
	return base64.StdEncoding.EncodeToString(raw) + "\n"
}

func gzipped(t *testing.T, data []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func tarred(t *testing.T, name, content string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	if err := w.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// projectWith runs a project whose one file is content, unpacked by its step.
func projectWith(svc *SandboxService, ctx context.Context, content string) (*plimsollv1.RunResponse, error) {
	resp, err := svc.Run(ctx, connect.NewRequest(&plimsollv1.RunRequest{Protocol: protocol.Number,
		Payload: &plimsollv1.RunRequest_Project{Project: &plimsollv1.ProjectRun{
			Files: []*plimsollv1.ProjectFile{{Path: "deps.tgz.b64", Content: content}},
			Steps: []string{"base64 -d deps.tgz.b64 | tar xz"},
		}}}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// A harness file inside an archive the call carries is found and refused like one
// shipped as itself, named by the part that holds the archive, never by the member.
func TestShipScanFindsAHarnessFileInAnArchive(t *testing.T) {
	set := withheldSetOf(t, withheld.ModeRefuse, nil, withheldFile(harnessSource, "harness/sim.py", ""))
	svc, fake, _ := scanService(set)
	_, err := projectWith(svc, authenticatedContext("agent-harness"), archiveFile(gzipped(t, tarred(t, "helpers/model.py", harnessSource))))
	if reason, marked := notDispatchedOf(err); connect.CodeOf(err) != connect.CodePermissionDenied || !marked ||
		reason != plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_PERMISSION || !strings.Contains(err.Error(), "harness/sim.py (files[0].content)") {
		t.Fatalf("got %v (marked %v, %v); want the refusal naming harness/sim.py in files[0].content", err, marked, reason)
	}
	if strings.Contains(err.Error(), "helpers/model.py") || fake.lastProj.Files != nil {
		t.Fatalf("the refusal names the member, or the provider saw the call: %v", err)
	}
}

// An archive past a bound leaves the scan incomplete. A set with a refuse-mode entry
// refuses the call, saying which part and which bound and nothing of the set; an
// audit-only set lets it run and states the scan incomplete to the operator alone.
func TestShipScanRefusesWhatItCouldNotRead(t *testing.T) {
	bomb := archiveFile(gzipped(t, make([]byte, withheld.MaxArchiveBytes+1)))
	set := withheldSetOf(t, withheld.ModeRefuse, nil,
		withheldFile(harnessSource, "harness/sim.py", ""), withheldValue(heldOutSeed, "seeds.txt:3", withheld.ModeAudit))
	svc, fake, logs := scanService(set)
	_, err := projectWith(svc, authenticatedContext("agent-harness"), bomb)
	reason, marked := notDispatchedOf(err)
	if connect.CodeOf(err) != connect.CodePermissionDenied || !marked || reason != plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_PERMISSION {
		t.Fatalf("got %v (marked %v, %v); want PermissionDenied, not dispatched, permission", err, marked, reason)
	}
	if !strings.Contains(err.Error(), "files[0].content: "+withheld.BoundArchiveBytes.Text()) ||
		strings.Contains(err.Error(), "harness/sim.py") || strings.Contains(err.Error(), "seeds.txt") || fake.lastProj.Files != nil {
		t.Fatalf("the refusal: %v", err)
	}
	line := logs.String()
	if !strings.Contains(line, `"msg":"withheld scan incomplete"`) || !strings.Contains(line, `"withheld_scan":"incomplete"`) ||
		!strings.Contains(line, `"withheld_incomplete":["files[0].content: archive_bytes"]`) || !strings.Contains(line, `"withheld_refused":true`) {
		t.Fatalf("the refusal's audit line: %s", line)
	}

	// Many parts past the bound: the refusal names the first eight, the audit line all.
	var files []*plimsollv1.ProjectFile
	for i := range 12 {
		files = append(files, &plimsollv1.ProjectFile{Path: fmt.Sprintf("d%d.b64", i), Content: bomb})
	}
	logs.Reset()
	_, err = svc.Run(authenticatedContext("agent-harness"), connect.NewRequest(&plimsollv1.RunRequest{Protocol: protocol.Number,
		Payload: &plimsollv1.RunRequest_Project{Project: &plimsollv1.ProjectRun{Files: files, Steps: []string{"true"}}}}))
	if msg := err.Error(); !strings.Contains(msg, "files[7].content") || strings.Contains(msg, "files[8].content") || !strings.Contains(msg, "and 4 more") {
		t.Fatalf("the refusal of twelve parts: %v", err)
	}
	if line := logs.String(); !strings.Contains(line, `"files[11].content: archive_bytes"`) {
		t.Fatalf("the audit line does not name every part: %s", line)
	}

	audit := withheldSetOf(t, withheld.ModeAudit, nil, withheldValue(heldOutSeed, "seeds.txt:3", ""))
	svc, fake, logs = scanService(audit)
	resp, err := projectWith(svc, authenticatedContext("agent-harness"), bomb)
	if err != nil || fake.lastProj.Files == nil {
		t.Fatalf("an audit-only set refused an incomplete scan: %v", err)
	}
	runs := runLines(t, logs)
	if len(runs) != 1 || runs[0].WithheldScan != withheldIncomplete || !reflect.DeepEqual(runs[0].WithheldIncomplete, []string{"files[0].content: archive_bytes"}) {
		t.Fatalf("the run's audit line: %+v", runs)
	}
	wire, err := protojson.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(wire), "withheld") || strings.Contains(string(wire), "incomplete") {
		t.Fatalf("the response states the scan: %s", wire)
	}
}

// encryptedSeeds is a zip whose members, harness/sim.py and seeds.txt (the held-out seed
// on its third line), are encrypted with the traditional PKWARE cipher: the fixture
// internal/withheld/archive_test.go describes as encryptedZip.
const encryptedSeeds = "UEsDBBQAAQAIAAAAAAD0klEZVwAAAFYAAAAOAAAAaGFybmVzcy9zaW0ucHnj3qUVUttClf71HaLLfmgwFfMjrYlYQKn/T5Ie9c7pUgczxjepqoyqnCXsyvro2NBInH6lgU9BV/XjM+i7DBIFrreqD9MWkrJbdxaLs/vsThmq8mCAn91QSwMEFAABAAgAAAAAAF1xg+QgAAAAFAAAAAkAAABzZWVkcy50eHTy7tQQqmElhcItSuhK2x321W06TsPw6MY2xiZvd1+7CFBLAQIUABQAAQAIAAAAAAD0klEZVwAAAFYAAAAOAAAAAAAAAAAAAAAAAAAAAABoYXJuZXNzL3NpbS5weVBLAQIUABQAAQAIAAAAAABdcYPkIAAAABQAAAAJAAAAAAAAAAAAAAAAAIMAAABzZWVkcy50eHRQSwUGAAAAAAIAAgBzAAAAygAAAAAA\n"

// An archive the scan recognizes and cannot read, here an encrypted zip holding the
// held-out seed, leaves the scan incomplete as a bound does: a set with a refuse-mode
// entry refuses the call, naming the part and why, since the seed could be inside; an
// audit-only set lets it run and states the scan incomplete to the operator alone.
func TestShipScanRefusesAnArchiveItCannotRead(t *testing.T) {
	refuse := withheldSetOf(t, withheld.ModeRefuse, nil, withheldValue(heldOutSeed, "seeds.txt:3", ""))
	svc, fake, logs := scanService(refuse)
	_, err := projectWith(svc, authenticatedContext("agent-harness"), encryptedSeeds)
	reason, marked := notDispatchedOf(err)
	if connect.CodeOf(err) != connect.CodePermissionDenied || !marked || reason != plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_PERMISSION {
		t.Fatalf("got %v (marked %v, %v); want PermissionDenied, not dispatched, permission", err, marked, reason)
	}
	if !strings.Contains(err.Error(), "files[0].content: "+withheld.BoundZipEncrypted.Text()) || strings.Contains(err.Error(), "seeds.txt") ||
		fake.lastProj.Files != nil {
		t.Fatalf("the refusal: %v", err)
	}
	if line := logs.String(); !strings.Contains(line, `"withheld_incomplete":["files[0].content: archive_zip_encrypted"]`) ||
		!strings.Contains(line, `"withheld_refused":true`) {
		t.Fatalf("the refusal's audit line: %s", line)
	}

	audit := withheldSetOf(t, withheld.ModeAudit, nil, withheldValue(heldOutSeed, "seeds.txt:3", ""))
	svc, fake, logs = scanService(audit)
	if _, err := projectWith(svc, authenticatedContext("agent-harness"), encryptedSeeds); err != nil || fake.lastProj.Files == nil {
		t.Fatalf("an audit-only set refused a call it could not read whole: %v", err)
	}
	runs := runLines(t, logs)
	if len(runs) != 1 || runs[0].WithheldScan != withheldIncomplete ||
		!reflect.DeepEqual(runs[0].WithheldIncomplete, []string{"files[0].content: archive_zip_encrypted"}) {
		t.Fatalf("the run's audit line: %+v", runs)
	}
}

// A call whose context has ended by the time its scan starts is refused as given up,
// not dispatched, whether the slot or the scan sees the end first.
func TestShipScanEndsWithTheCall(t *testing.T) {
	set := withheldSetOf(t, withheld.ModeRefuse, nil, withheldValue(heldOutSeed, "seeds.txt:3", ""))
	svc, fake, _ := scanService(set)
	for range 20 {
		ctx, cancel := context.WithCancel(authenticatedContext("agent-harness"))
		cancel()
		_, err := snippet(svc, ctx, "console.log(1)")
		if reason, marked := notDispatchedOf(err); !marked || reason != plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_CAPACITY || fake.lastReq.Code != "" {
			t.Fatalf("an ended call: %v (marked %v, %v)", err, marked, reason)
		}
	}
}
