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
	"github.com/plimsollmark/plimsoll/internal/wireenum"
	"github.com/plimsollmark/plimsoll/sandbox"
)

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
	allowed := map[string]bool{"refuse": true, "refuseCapacity": true, "mapSandboxErr": true, "authenticatePrincipal": true}
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
		// Every declaration: a function's body, and a package-level var or const whose
		// value is a function literal (a table of payload kinds, say), which a scan
		// of function declarations alone would miss.
		for _, decl := range f.Decls {
			where := "a package-level declaration"
			if fn, ok := decl.(*ast.FuncDecl); ok {
				if allowed[fn.Name.Name] {
					continue
				}
				where = fn.Name.Name
			}
			ast.Inspect(decl, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "NewError" {
					if id, ok := sel.X.(*ast.Ident); ok && id.Name == "connect" {
						t.Errorf("%s: %s builds a Connect error without deciding the NotDispatched mark; use refuse", fset.Position(call.Pos()), where)
					}
				}
				return true
			})
		}
	}
}

// Every capacity refusal plimsoll builds states its limit, in this package and in every
// other of the module (finding release-115, widened by release-122): here through
// refuseCapacity, never refuse with sandbox.RefusalCapacity; elsewhere through
// sandbox.AtCapacity with a limit, or sandbox.RefuseDeadline when the call's own context
// ended first. RefusalCapacity is otherwise only compared, never handed to NotDispatched
// or kept in a variable that is, so a new path that refuses for capacity, its caller's
// deadline included, cannot leave its limit unstated for mapSandboxErr to guess.
func TestEveryCapacityRefusalStatesItsLimit(t *testing.T) {
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()
	files := 0
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".claude", "gen", "node_modules", "testdata", "third_party", "tmp", "private": // private is its own module
				return filepath.SkipDir
			}
			if path != root {
				if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
					return filepath.SkipDir // another module (clients/mcp, an example's)
				}
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		files++
		for _, bad := range capacityRefusalsWithoutALimit(f) {
			t.Errorf("%s: %s", fset.Position(bad.pos), bad.why)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files < 100 {
		t.Fatalf("read %d files: the walk missed the module", files)
	}
}

type unstatedLimit struct {
	pos token.Pos
	why string
}

// capacityRefusalsWithoutALimit is every place in f that builds a capacity refusal
// without stating its limit through the one function for it.
func capacityRefusalsWithoutALimit(f *ast.File) []unstatedLimit {
	var out []unstatedLimit
	name := func(e ast.Expr) string {
		switch e := e.(type) {
		case *ast.Ident:
			return e.Name
		case *ast.SelectorExpr:
			return e.Sel.Name
		}
		return ""
	}
	for _, decl := range f.Decls {
		inside := ""
		if fn, ok := decl.(*ast.FuncDecl); ok {
			inside = fn.Name.Name
		}
		var stack []ast.Node
		ast.Inspect(decl, func(n ast.Node) bool {
			if n == nil {
				stack = stack[:len(stack)-1]
				return true
			}
			var parent ast.Node
			if len(stack) > 0 {
				parent = stack[len(stack)-1]
			}
			stack = append(stack, n)
			if call, ok := n.(*ast.CallExpr); ok && len(call.Args) >= 2 {
				switch name(call.Fun) {
				case "refuse":
					if name(call.Args[1]) == "RefusalCapacity" {
						out = append(out, unstatedLimit{call.Pos(), "a capacity refusal built by refuse states no limit; use refuseCapacity"})
					}
				case "AtCapacity", "refuseCapacity":
					switch name(call.Args[0]) {
					case "CapacityUnstated":
						out = append(out, unstatedLimit{call.Pos(), "a capacity refusal with its limit unstated"})
					case "CapacityDeadline":
						if inside != "RefuseDeadline" {
							out = append(out, unstatedLimit{call.Pos(), "the deadline limit is set only by sandbox.RefuseDeadline"})
						}
					}
				}
			}
			var id *ast.Ident
			switch e := n.(type) {
			case *ast.SelectorExpr:
				id = e.Sel
			case *ast.Ident:
				if _, sel := parent.(*ast.SelectorExpr); !sel {
					id = e
				}
			}
			if id == nil || id.Name != "RefusalCapacity" {
				return true
			}
			switch p := parent.(type) {
			case *ast.BinaryExpr:
				if p.Op == token.EQL || p.Op == token.NEQ {
					return true
				}
			case *ast.CaseClause, *ast.ValueSpec:
				return true
			case *ast.KeyValueExpr:
				if p.Key == n {
					return true // a table indexed by refusal
				}
			case *ast.CompositeLit:
				return true // a table's positional entry
			}
			if inside == "AtCapacity" || inside == "refuseCapacity" {
				return true
			}
			out = append(out, unstatedLimit{n.Pos(), "a capacity refusal built without its limit; use sandbox.AtCapacity with the limit, or sandbox.RefuseDeadline when the call's own context ended first"})
			return true
		})
	}
	return out
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

// A capacity refusal whose provider stated no limit but which carries the call's own
// context error is the caller's deadline, never the provider's capacity (finding
// release-122): an out-of-tree provider marking a refusal capacity when its caller gave up
// is not told the provider was full.
func TestAnUnstatedCapacityRefusalForTheCallersDeadlineIsNotTheProviders(t *testing.T) {
	for _, cause := range []error{context.DeadlineExceeded, context.Canceled} {
		err := mapSandboxErr(sandbox.NotDispatched(sandbox.RefusalCapacity, fmt.Errorf("provider check: %w", cause)))
		if got := wireenum.CapacityLimitFromWire(wireLimit(err)); got != sandbox.CapacityDeadline {
			t.Errorf("%v: states limit %v, want deadline", cause, got)
		}
	}
	err := mapSandboxErr(sandbox.NotDispatched(sandbox.RefusalCapacity, errors.New("the provider's quota is spent")))
	if got := wireenum.CapacityLimitFromWire(wireLimit(err)); got != sandbox.CapacityProvider {
		t.Errorf("a provider's own refusal states %v, want provider", got)
	}
}
