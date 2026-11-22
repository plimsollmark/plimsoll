package rpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1/plimsollv1connect"
	"github.com/plimsollmark/plimsoll/internal/grants"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// syncBuffer is a log sink the server's goroutines can write while the test reads.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// refusalLines returns the refusal log's lines in what the buffer holds.
func refusalLines(t *testing.T, raw string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		if m["msg"] == "call refused before it ran" {
			out = append(out, m)
		}
	}
	return out
}

type principalTable map[string]Principal

func (p principalTable) VerifyToken(_ context.Context, token string) (Principal, bool, error) {
	pr, ok := p[token]
	return pr, ok, nil
}

// containerFake states the container tier, so a request for vm is refused at the floor,
// and counts the snippets it is given.
type containerFake struct {
	*fakeSandbox
	calls *atomic.Int64
}

func (containerFake) IsolationClass() sandbox.IsolationClass { return sandbox.IsolationContainer }

func (c containerFake) RunJavaScript(ctx context.Context, req sandbox.Request) (sandbox.Result, error) {
	c.calls.Add(1)
	return c.fakeSandbox.RunJavaScript(ctx, req)
}

const (
	tokenA       = "token-a-0123456789abcdef0123456789"
	tokenB       = "token-b-0123456789abcdef0123456789"
	tokenNoScope = "token-n-0123456789abcdef0123456789"
)

// refusalServer serves svc as plimsolld does: AuthenticateHTTP (told of refusals) in
// front of NewHandler with AuthInterceptor, the service's log captured, its clock settable.
func refusalServer(t *testing.T, sb sandbox.Sandbox) (*syncBuffer, func(time.Duration), string) {
	t.Helper()
	t.Setenv("HUE_TOKEN", "tok-xyz")
	path := filepath.Join(t.TempDir(), "grants.json")
	if err := os.WriteFile(path, []byte(`{"profiles":{"hue":{"base_url":"https://hue.internal","allow":["GET /v1/lights"],"allowed_callers":["mcp-a"],"token":{"type":"static","env":"HUE_TOKEN"}}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	reg, err := grants.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	svc := NewSandboxService(sb)
	svc.Grants = reg
	logs := &syncBuffer{}
	svc.Logger = slog.New(slog.NewJSONHandler(logs, nil))
	clock := time.Unix(2_000_000, 0)
	var mu sync.Mutex
	svc.refusals.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	advance := func(d time.Duration) { mu.Lock(); clock = clock.Add(d); mu.Unlock() }
	verifier := principalTable{
		tokenA:       {UserID: "mcp-a", Scopes: []string{ScopeCodeRun}},
		tokenB:       {UserID: "mcp-b", Scopes: []string{ScopeCodeRun}},
		tokenNoScope: {UserID: "mcp-n"},
	}
	_, h := NewHandler(svc, connect.WithInterceptors(AuthInterceptor(verifier)))
	srv := httptest.NewServer(AuthenticateHTTP(verifier, h, svc))
	t.Cleanup(srv.Close)
	return logs, advance, srv.URL
}

func runAs(t *testing.T, url, token string, req *connect.Request[plimsollv1.RunRequest]) error {
	t.Helper()
	req.Header().Set("Authorization", "Bearer "+token)
	_, err := plimsollv1connect.NewSandboxServiceClient(http.DefaultClient, url).Run(context.Background(), req)
	return err
}

// The reviewer's case (hunt-security-3): as caller mcp-b, four runs naming profiles it
// is not on (one of them real, three that do not exist) and one asking for vm from a
// provider stating container. All five are refused, as before; the log now holds one
// line naming the caller, the procedure, the code and the reason, and none of the
// profile names. The next refusal after the window writes the second line, counting
// the four folded into it.
func TestRefusalsGiveOneLinePerCallerAndNoProfileName(t *testing.T) {
	fake := containerFake{&fakeSandbox{jsResult: sandbox.Result{Sandbox: "fake"}}, &atomic.Int64{}}
	logs, advance, url := refusalServer(t, fake)
	profiles := []string{"hue", "admin", "billing", "prod-db"}
	for _, p := range profiles {
		if err := runAs(t, url, tokenB, withTrace(jsGrantReq("1", p), "join-1")); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Fatalf("profile %s: %v, want permission_denied", p, err)
		}
	}
	if err := runAs(t, url, tokenB, withFloor(jsReq("1"), "vm")); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("floor vm on a container provider: %v, want failed_precondition", err)
	}
	if n := fake.calls.Load(); n != 0 {
		t.Fatalf("the provider ran %d times", n)
	}
	raw := logs.String()
	lines := refusalLines(t, raw)
	if len(lines) != 1 {
		t.Fatalf("five refusals in one window gave %d lines, want 1:\n%s", len(lines), raw)
	}
	l := lines[0]
	if l["caller"] != "mcp-b" || l["procedure"] != plimsollv1connect.SandboxServiceRunProcedure ||
		l["code"] != "permission_denied" || l["reason"] != "permission" || l["refused"] != float64(1) || l["trace_id"] != "join-1" {
		t.Errorf("the line = %v", l)
	}
	for _, p := range profiles {
		if strings.Contains(raw, p) {
			t.Errorf("the log names the profile %q the caller asked for:\n%s", p, raw)
		}
	}

	advance(refusalLogEvery)
	if err := runAs(t, url, tokenB, withFloor(jsReq("1"), "vm")); err == nil {
		t.Fatal("the floor refusal ran")
	}
	lines = refusalLines(t, logs.String())
	if len(lines) != 2 {
		t.Fatalf("after the window: %d lines, want 2", len(lines))
	}
	if l := lines[1]; l["caller"] != "mcp-b" || l["refused"] != float64(5) || l["reason"] != "isolation" || l["code"] != "failed_precondition" {
		t.Errorf("the second line = %v, want mcp-b, 5 refused (4 folded and this one), isolation", l)
	}
}

// A scope refusal is answered before Connect (AuthenticateHTTP) and is noted there; a
// path that names no procedure is caller text, so the line says "unknown".
func TestScopeRefusalsAreNotedAndThePathIsNotEchoed(t *testing.T) {
	logs, _, url := refusalServer(t, &fakeSandbox{jsResult: sandbox.Result{Sandbox: "fake"}})
	if err := runAs(t, url, tokenNoScope, jsReq("1")); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("no scope: %v", err)
	}
	req, _ := http.NewRequest(http.MethodPost, url+"/plimsoll.v1.SandboxService/hue-billing-guess", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+tokenA)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	raw := logs.String()
	lines := refusalLines(t, raw)
	if len(lines) != 2 {
		t.Fatalf("%d lines, want 2:\n%s", len(lines), raw)
	}
	if l := lines[0]; l["caller"] != "mcp-n" || l["procedure"] != plimsollv1connect.SandboxServiceRunProcedure || l["reason"] != "permission" {
		t.Errorf("the scope line = %v", l)
	}
	if l := lines[1]; l["caller"] != "mcp-a" || l["procedure"] != "unknown" {
		t.Errorf("the unrouted path's line = %v", l)
	}
	if strings.Contains(raw, "hue-billing-guess") {
		t.Errorf("the log echoes the caller's path:\n%s", raw)
	}
}

// A refused credential has no caller, and authFailureLog counts it: no refusal line.
// A refusal whose request has a line of its own (here a run the provider refused after
// admission, on the run's "failed" line) gets no second one.
func TestRefusalsAlreadyLoggedAreNotLoggedTwice(t *testing.T) {
	fake := &fakeSandbox{jsErr: sandbox.NotDispatched(sandbox.RefusalCapacity, errors.New("provider full"))}
	logs, _, url := refusalServer(t, fake)
	if err := runAs(t, url, "not-a-token", jsReq("1")); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("bad token: %v", err)
	}
	if err := runAs(t, url, tokenA, jsReq("1")); err == nil {
		t.Fatal("the provider's refusal was not returned")
	}
	raw := logs.String()
	if n := len(refusalLines(t, raw)); n != 0 {
		t.Errorf("%d refusal lines, want 0:\n%s", n, raw)
	}
	if !strings.Contains(raw, "failed") {
		t.Errorf("the run's own failed line is missing:\n%s", raw)
	}
}

// Many distinct callers cannot grow the table past its bound: callers past it fold into
// one line without a caller, so one window carries at most refusalLogCallers+1 lines.
// Once the window has passed, the table is swept and owed counts are written.
func TestRefusalLogTableIsBounded(t *testing.T) {
	logs := &syncBuffer{}
	log := slog.New(slog.NewJSONHandler(logs, nil))
	now := time.Unix(3_000_000, 0)
	l := &refusalLog{now: func() time.Time { return now }}
	refusal := refuse(connect.CodePermissionDenied, sandbox.RefusalPermission, errors.New("grant_profile \"secret-name\" is not available"))
	const extra = 500
	for i := range refusalLogCallers + extra {
		l.note(log, fmt.Sprintf("caller-%d", i), plimsollv1connect.SandboxServiceRunProcedure, refusal, "")
	}
	if n := len(l.callers); n != refusalLogCallers {
		t.Fatalf("the table holds %d callers, want the bound %d", n, refusalLogCallers)
	}
	lines := refusalLines(t, logs.String())
	if len(lines) != refusalLogCallers+1 {
		t.Fatalf("%d lines, want %d (one per caller in the table, one for those past it)", len(lines), refusalLogCallers+1)
	}
	if over := lines[len(lines)-1]; over["callers_over_bound"] != true || over["caller"] != nil {
		t.Errorf("the line past the bound = %v", over)
	}
	if strings.Contains(logs.String(), "secret-name") {
		t.Error("the refusal's text reached the log")
	}
	// A second refusal of caller-0 in the window is folded; after the window, the sweep
	// writes it as owed, and the table empties of callers whose window passed.
	l.note(log, "caller-0", plimsollv1connect.SandboxServiceRunProcedure, refusal, "")
	now = now.Add(refusalLogEvery)
	l.note(log, "caller-new", plimsollv1connect.SandboxServiceRunProcedure, refusal, "")
	lines = refusalLines(t, logs.String())
	var owed0, owedOver bool
	for _, ln := range lines[refusalLogCallers+1:] {
		if ln["caller"] == "caller-0" && ln["refused"] == float64(1) {
			owed0 = true
		}
		if ln["callers_over_bound"] == true && ln["refused"] == float64(extra-1) {
			owedOver = true
		}
	}
	if !owed0 || !owedOver {
		t.Errorf("owed counts after the sweep: caller-0 %t, past the bound %t; lines %v", owed0, owedOver, lines[refusalLogCallers+1:])
	}
	if n := len(l.callers); n != 1 {
		t.Errorf("after the sweep the table holds %d callers, want 1", n)
	}
}

// A software rule the provider's software does not meet is refused before admission and
// noted like the others; the identities the caller named stay out of the log.
func TestSoftwareRuleRefusalIsNoted(t *testing.T) {
	fake := &describedFake{fakeSandbox: finishedFake("fake")}
	logs, _, url := refusalServer(t, fake)
	req := withTrace(jsReq("1"), "join-2")
	req.Msg.SoftwareRule = &plimsollv1.SoftwareRule{Mode: "exact", Identities: []string{"oci-manifest:linux/amd64@sha256:caller0named0this"}}
	if err := runAs(t, url, tokenA, req); err == nil {
		t.Fatal("a rule the provider cannot meet ran")
	}
	raw := logs.String()
	lines := refusalLines(t, raw)
	if len(lines) != 1 {
		t.Fatalf("%d lines, want 1:\n%s", len(lines), raw)
	}
	if l := lines[0]; l["caller"] != "mcp-a" || l["procedure"] != plimsollv1connect.SandboxServiceRunProcedure ||
		l["reason"] == "" || l["trace_id"] != "join-2" || l["refused"] != float64(1) {
		t.Errorf("the line = %v", l)
	}
	if strings.Contains(raw, "caller0named0this") {
		t.Errorf("the log carries the identity the caller named:\n%s", raw)
	}
}
