package rpc

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/internal/grants"
	"github.com/plimsollmark/plimsoll/sandbox"
)

func notDispatchedOf(err error) (plimsollv1.NotDispatchedReason, bool) {
	var ce *connect.Error
	if !errors.As(err, &ce) {
		return 0, false
	}
	for _, d := range ce.Details() {
		v, derr := d.Value()
		if derr != nil {
			continue
		}
		if nd, ok := v.(*plimsollv1.NotDispatched); ok {
			return nd.GetReason(), true
		}
	}
	return 0, false
}

func wantNotDispatched(t *testing.T, name string, err error, want plimsollv1.NotDispatchedReason) {
	t.Helper()
	got, ok := notDispatchedOf(err)
	if !ok || got != want {
		t.Errorf("%s: NotDispatched = %v, %v (err %v); want %v", name, got, ok, err, want)
	}
}

// Every refusal the handler raises before dispatch carries the detail with the
// reason a caller acts on, and none of them reached the provider.
func TestHandlerRefusalsCarryNotDispatched(t *testing.T) {
	t.Setenv("HUE_TOKEN", "tok-xyz")
	path := filepath.Join(t.TempDir(), "grants.json")
	if err := os.WriteFile(path, []byte(`{"profiles":{"hue":{"base_url":"https://hue.internal","allow":["GET /v1/lights"],"allowed_callers":["mcp-a"],"token":{"type":"static","env":"HUE_TOKEN"}}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	reg, err := grants.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeSandbox{jsResult: sandbox.Result{Sandbox: "fake"}}
	svc := NewSandboxService(fake)
	svc.Grants = reg
	ctx := authenticatedContext("mcp-b")

	const (
		request    = plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_REQUEST
		permission = plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_PERMISSION
		proto      = plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_PROTOCOL
		isolation  = plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_ISOLATION
	)
	for name, tc := range map[string]struct {
		req  *connect.Request[plimsollv1.RunRequest]
		want plimsollv1.NotDispatchedReason
	}{
		"protocol omitted":  {withProtocol(jsReq("1"), 0), proto},
		"protocol other":    {withProtocol(jsReq("1"), 999), proto},
		"unparseable floor": {withFloor(jsReq("1"), "fortress"), request},
		"no payload":        {envelopeReq(nil), request},
		"empty code":        {jsReq(""), request},
		// Same reason as "caller not on ACL": a different one would reveal which
		// profile names exist (TestGrantProfileRefusalDoesNotLeakExistence).
		"unknown profile":       {jsGrantReq("1", "nope"), permission},
		"profile name too long": {jsGrantReq("1", strings.Repeat("p", grants.MaxProfileNameBytes+1)), request},
		"caller not on ACL":     {jsGrantReq("1", "hue"), permission},
		"empty project":         {projectReq(&plimsollv1.ProjectRun{}), request},
		"empty module":          {moduleReq(&plimsollv1.ModuleRun{}), request},
	} {
		_, err := svc.Run(ctx, tc.req)
		wantNotDispatched(t, name, err, tc.want)
	}
	if fake.lastReq.Code != "" || fake.lastProj.Steps != nil || fake.lastMod.Model != "" {
		t.Fatal("a refused request reached the provider")
	}

	low := NewSandboxService(&isolationFake{isolation: sandbox.IsolationContainer})
	_, err = low.Run(ctx, withFloor(jsReq("1"), "vm"))
	wantNotDispatched(t, "floor above evidence", err, isolation)

	limited := NewSandboxService(&fakeSandbox{jsResult: sandbox.Result{Sandbox: "fake"}})
	limited.Limiter = NewCodeLimiter(0, 0, 1, 1)
	if _, err := limited.Run(ctx, jsReq("1")); err != nil {
		t.Fatalf("first run under the rate limit: %v", err)
	}
	_, err = limited.Run(ctx, jsReq("1"))
	wantNotDispatched(t, "rate limit", err, plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_CAPACITY)
}

// A provider's own pre-dispatch refusal crosses the handler with its reason; an
// error the provider did not mark carries no detail, even when its code matches a
// refusal (the module worker's exit 4 is InvalidArgument after the container ran).
func TestProviderErrorsKeepOrLackTheMark(t *testing.T) {
	_, err := NewSandboxService(sandbox.Disabled{}).Run(context.Background(), jsReq("1"))
	wantNotDispatched(t, "disabled provider", err, plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_UNSUPPORTED)

	for name, provErr := range map[string]error{
		"post-start refusal": fmt.Errorf("%w: worker refused the table", sandbox.ErrInvalidRequest),
		"infrastructure":     errors.New("docker: connection reset"),
	} {
		_, err := NewSandboxService(&fakeSandbox{jsErr: provErr}).Run(context.Background(), jsReq("1"))
		if err == nil {
			t.Fatalf("%s: no error", name)
		}
		if r, ok := notDispatchedOf(err); ok {
			t.Errorf("%s: carries NotDispatched %v; an unmarked provider error may have run", name, r)
		}
	}
}

// Authentication refusals carry the detail over the wire too.
func TestAuthRefusalsCarryNotDispatched(t *testing.T) {
	client := newAuthTestClient(t, fakeVerifier{token: "good", scopes: []string{"other"}})
	permission := plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_PERMISSION
	wantNotDispatched(t, "missing token", callRun(client, ""), permission)
	wantNotDispatched(t, "unknown token", callRun(client, "bad"), permission)
	wantNotDispatched(t, "missing scope", callRun(client, "good"), permission)
}

// The mechanism, not a list of sites: in this package a Connect error is built
// only by refuse (which marks it), by mapSandboxErr (which marks what the
// provider marked), or inside authenticatePrincipal (whose cancellation and
// verifier-outage errors are deliberately unmarked: no reason fits them, and
// unmarked is the safe reading). A new refusal site elsewhere must go through
// refuse or be added here with its reason for staying unmarked.
func TestConnectErrorsAreBuiltOnlyWhereTheMarkIsDecided(t *testing.T) {
	allowed := map[string]bool{"refuse": true, "mapSandboxErr": true, "authenticatePrincipal": true}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || allowed[fn.Name.Name] {
				continue
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "NewError" {
					if id, ok := sel.X.(*ast.Ident); ok && id.Name == "connect" {
						t.Errorf("%s: %s builds a Connect error without deciding the NotDispatched mark; use refuse", fset.Position(call.Pos()), fn.Name.Name)
					}
				}
				return true
			})
		}
	}
}

// An internal error reaches the caller as a generic message with an ID; its text,
// which can carry a vendor's response body or docker's stderr, stays in the log
// (v0.15.0 review, L10).
func TestInternalErrorTextStaysInTheLog(t *testing.T) {
	err := mapSandboxErr(errors.New("e2b create sandbox: HTTP 500: {\"apiKey\":\"e2b_secret\"} DOCKER_HOST=unix:///run/x.sock"))
	if connect.CodeOf(err) != connect.CodeInternal {
		t.Fatalf("code %v, want internal", connect.CodeOf(err))
	}
	msg := err.Error()
	if strings.Contains(msg, "e2b_secret") || strings.Contains(msg, "DOCKER_HOST") || !strings.Contains(msg, "internal error") {
		t.Fatalf("the caller sees %q", msg)
	}
	// Errors with their own code keep their text: it is the caller's own request.
	if err := mapSandboxErr(fmt.Errorf("%w: bad path", sandbox.ErrInvalidRequest)); !strings.Contains(err.Error(), "bad path") {
		t.Fatalf("an invalid request lost its reason: %v", err)
	}
}
