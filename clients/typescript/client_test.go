// Package typescript holds no Go code but this test: it serves the real RPC
// handler and runs the TypeScript client's suites against it, so the client is
// proven against the daemon it talks to rather than against a recording of one.
package typescript

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1/plimsollv1connect"
	"github.com/plimsollmark/plimsoll/internal/rpc"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandboxtest"
)

// projectEcho runs nothing: it answers a project with the plan it received (the
// file paths, the steps, and the code in .plimsoll/cell.*), so the suite can check
// what a fresh executeCode call sends. It states both languages. A cell holding
// ECHO:NOSTEP is answered with no step report, as a run whose report was lost is.
type projectEcho struct{}

func (projectEcho) Name() string                           { return "project-echo" }
func (projectEcho) IsolationClass() sandbox.IsolationClass { return sandbox.IsolationContainer }
func (projectEcho) SupportsProjects() bool                 { return true }
func (projectEcho) Environments() sandbox.Environments {
	langs := []sandbox.Language{sandbox.LanguageJavaScript, sandbox.LanguagePython}
	return sandbox.Environments{Project: sandbox.PayloadEnvironment{Languages: langs}}
}
func (projectEcho) RunJavaScript(context.Context, sandbox.Request) (sandbox.Result, error) {
	return sandbox.Result{}, sandbox.NotDispatched(sandbox.RefusalUnsupported, sandbox.ErrUnsupported)
}
func (projectEcho) RunModule(context.Context, sandbox.ModuleRequest) (sandbox.ModuleResult, error) {
	return sandbox.ModuleResult{}, sandbox.NotDispatched(sandbox.RefusalUnsupported, sandbox.ErrUnsupported)
}
func (projectEcho) RunProject(_ context.Context, req sandbox.ProjectRequest) (sandbox.ProjectResult, error) {
	plan := struct {
		Files []string `json:"files"`
		Steps []string `json:"steps"`
		Cell  string   `json:"cell"`
	}{Steps: req.Steps}
	for _, f := range req.Files {
		plan.Files = append(plan.Files, f.Path)
		if f.Path == ".plimsoll/cell.py" || f.Path == ".plimsoll/cell.js" {
			plan.Cell = f.Content
		}
	}
	if strings.Contains(plan.Cell, "ECHO:NOSTEP") {
		return sandbox.ProjectResult{
			Sandbox: "project-echo", Isolation: sandbox.IsolationContainer, Outcome: sandbox.ProjectOutcomeProtocolError, Detail: "the runner's report was lost",
		}, nil
	}
	out, _ := json.Marshal(plan)
	return sandbox.ProjectResult{
		Sandbox: "project-echo", Isolation: sandbox.IsolationContainer, Outcome: sandbox.ProjectOutcomeCompleted,
		Steps: []sandbox.StepResult{{Command: req.Steps[0], Stdout: string(out)}},
	}, nil
}

func serve(t *testing.T, svc *rpc.SandboxService, extra func(*http.ServeMux)) string {
	t.Helper()
	svc.Logger = slog.New(slog.DiscardHandler)
	mux := http.NewServeMux()
	path, h := plimsollv1connect.NewSandboxServiceHandler(svc, connect.WithInterceptors(rpc.AuthInterceptor(nil)))
	mux.Handle(path, h)
	if extra != nil {
		extra(mux)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

// TestTypeScript serves three daemons, the wasm provider for single runs, the
// in-memory session provider for sessions and cells (whose POST /test/end-sessions
// ends every open session as a lifetime would), and projectEcho for the project a
// fresh executeCode call sends, and runs three suites against them:
// the client's own, which needs nothing but node; the add-ons', which need the
// client's dev dependencies (npm install in clients/typescript); and the
// Trigger.dev example's, which needs the example's (npm install in
// examples/trigger-chat). A suite whose dependencies are absent is skipped unless
// PLIMSOLL_REQUIRE_CLIENTS=1, which makes missing prerequisites fail.
// Files run one at a time because the end-sessions endpoint reaches every session.
func TestTypeScript(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		clientSkipOrFail(t, "node is not installed")
	}
	if out, err := exec.Command(node, "-e", "process.exit(process.features.typescript ? 0 : 1)").CombinedOutput(); err != nil {
		clientSkipOrFail(t, "this node cannot run TypeScript directly (needs >= 22.18): %v %s", err, out)
	}

	wasmURL := serve(t, rpc.NewSandboxService(sandboxtest.Wasm()), nil)
	sessions := &sandboxtest.Sessions{}
	svc := rpc.NewSandboxService(sessions)
	svc.Sessions = rpc.SessionConfig{MaxSessions: 16, Lifetime: time.Minute, IdleTimeout: time.Minute}
	sessionsURL := serve(t, svc, func(mux *http.ServeMux) {
		mux.HandleFunc("POST /test/end-sessions", func(http.ResponseWriter, *http.Request) {
			for _, s := range sessions.Opened() {
				s.End(sandbox.SessionExpired)
			}
		})
	})
	echoURL := serve(t, rpc.NewSandboxService(projectEcho{}), nil)
	breaking := rpc.NewSandboxService(&breakingSessions{Sessions: &sandboxtest.Sessions{}})
	breaking.Sessions = rpc.SessionConfig{MaxSessions: 16, Lifetime: time.Minute, IdleTimeout: time.Minute}
	breakingURL := serve(t, breaking, nil)
	ownerCapped := rpc.NewSandboxService(&sandboxtest.Sessions{})
	ownerCapped.Sessions = rpc.SessionConfig{MaxSessions: 16, MaxPerOwner: 1, Lifetime: time.Minute, IdleTimeout: time.Minute}
	ownerCapURL := serve(t, ownerCapped, nil)
	liarMux := http.NewServeMux()
	liarPath, liarHandler := plimsollv1connect.NewSandboxServiceHandler(unansweredLiar{})
	liarMux.Handle(liarPath, liarHandler)
	liarSrv := httptest.NewServer(liarMux)
	t.Cleanup(liarSrv.Close)
	env := append(os.Environ(), "PLIMSOLL_WASM_URL="+wasmURL, "PLIMSOLL_SESSIONS_URL="+sessionsURL, "PLIMSOLL_URL="+sessionsURL,
		"PLIMSOLL_ECHO_URL="+echoURL, "PLIMSOLL_BREAKING_URL="+breakingURL, "PLIMSOLL_LIAR_URL="+liarSrv.URL, "PLIMSOLL_OWNER_CAP_URL="+ownerCapURL)

	suites := []struct{ name, dir, glob, needs string }{
		{"client", ".", "test/*.test.ts", ""},
		{"addons", ".", "test/addons/*.test.ts", "node_modules/@mastra/core"},
		{"trigger-example", "../../examples/trigger-chat", "src/trigger/*.test.ts", "node_modules/@trigger.dev/sdk"},
	}
	for _, s := range suites {
		t.Run(s.name, func(t *testing.T) {
			if s.needs != "" {
				if _, err := os.Stat(filepath.Join(s.dir, s.needs)); err != nil {
					clientSkipOrFail(t, "run npm install in %s first", s.dir)
				}
			}
			files, err := filepath.Glob(filepath.Join(s.dir, s.glob))
			if err != nil || len(files) == 0 {
				t.Fatalf("no tests match %s: %v", s.glob, err)
			}
			for i := range files {
				files[i], _ = filepath.Rel(s.dir, files[i])
			}
			cmd := exec.Command(node, append([]string{"--test", "--test-concurrency=1", "--test-reporter=spec"}, files...)...)
			cmd.Dir = s.dir
			cmd.Env = env
			out, err := cmd.CombinedOutput()
			t.Logf("%s", out)
			if err != nil {
				t.Fatalf("node --test: %v", err)
			}
		})
	}
}

func clientSkipOrFail(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv("PLIMSOLL_REQUIRE_CLIENTS") == "1" {
		t.Fatalf(format, args...)
	}
	t.Skipf(format, args...)
}

// The package ships its own copy of the license, because a published package carries
// nothing from outside its directory; it must stay the repository's license.
func TestLicenseMatchesRepository(t *testing.T) {
	own, err := os.ReadFile("LICENSE")
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.ReadFile(filepath.Join("..", "..", "LICENSE"))
	if err != nil {
		t.Fatal(err)
	}
	if string(own) != string(root) {
		t.Fatal("LICENSE differs from the repository's LICENSE; copy it again")
	}
}

// Both client packages carry the version of the plimsoll release they ship in, so a
// reader can tell which daemon release a package was built and tested with: the npm
// package, its lockfile, the Python distribution and the version the Python client
// sends.
func TestClientVersionsAgree(t *testing.T) {
	var pkg, lock struct {
		Version string `json:"version"`
	}
	for _, f := range []struct {
		path string
		into any
	}{{"package.json", &pkg}, {"package-lock.json", &lock}} {
		b, err := os.ReadFile(f.path)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, f.into); err != nil {
			t.Fatalf("%s: %v", f.path, err)
		}
	}
	python := func(path, pattern string) string {
		b, err := os.ReadFile(filepath.Join("..", "python", path))
		if err != nil {
			t.Fatal(err)
		}
		m := regexp.MustCompile(`(?m)` + pattern).FindSubmatch(b)
		if m == nil {
			t.Fatalf("%s: no version", path)
		}
		return string(m[1])
	}
	versions := map[string]string{
		"package.json":                           pkg.Version,
		"package-lock.json":                      lock.Version,
		"python/pyproject.toml":                  python("pyproject.toml", `^version = "([^"]+)"$`),
		"python/src/plimsoll_client/_version.py": python(filepath.Join("src", "plimsoll_client", "_version.py"), `^__version__ = "([^"]+)"$`),
	}
	for _, v := range versions {
		if v != pkg.Version || v == "" {
			t.Fatalf("client versions disagree: %v", versions)
		}
	}
}

// breakingSessions opens fake sessions whose second snippet call runs and then
// returns an unmarked error, as an exec stream that broke after the code ran does:
// the daemon sends that call's record with the error.
type breakingSessions struct{ *sandboxtest.Sessions }

func (p *breakingSessions) OpenSession(ctx context.Context, opts sandbox.SessionOptions) (sandbox.Session, error) {
	s, err := p.Sessions.OpenSession(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &breakingSession{Session: s}, nil
}

type breakingSession struct {
	sandbox.Session
	n int
}

func (s *breakingSession) RunJavaScript(ctx context.Context, req sandbox.Request) (sandbox.Result, error) {
	res, err := s.Session.RunJavaScript(ctx, req)
	if s.n++; s.n == 2 {
		return res, errors.New("the exec stream broke after the code ran")
	}
	return res, err
}

// RunCell breaks the same way: the session's second call, of either kind.
func (s *breakingSession) RunCell(ctx context.Context, req sandbox.CellRequest) (sandbox.CellResult, error) {
	res, err := s.Session.RunCell(ctx, req)
	if s.n++; s.n == 2 {
		return res, errors.New("the relay was lost after the code ran")
	}
	return res, err
}

// unansweredLiar opens a session as provider "liar" at container, and answers every
// call with the record of a call that may have run, stating evidence the session did
// not state at open: "weaker" names the tier process, anything else another provider.
type unansweredLiar struct {
	plimsollv1connect.UnimplementedSandboxServiceHandler
}

const liarSessionID = "00112233445566778899aabbccddeeff"

func (unansweredLiar) OpenSession(context.Context, *connect.Request[plimsollv1.OpenSessionRequest]) (*connect.Response[plimsollv1.OpenSessionResponse], error) {
	return connect.NewResponse(&plimsollv1.OpenSessionResponse{SessionId: liarSessionID, Session: record.SessionFingerprint(liarSessionID),
		Sandbox: "liar", Isolation: "container", ExpiresUnixMs: time.Now().Add(time.Minute).UnixMilli()}), nil
}

func (unansweredLiar) SessionRun(_ context.Context, req *connect.Request[plimsollv1.SessionRunRequest]) (*connect.Response[plimsollv1.SessionRunResponse], error) {
	provider, isolation := "liar", "container"
	if req.Msg.GetJavascript().GetCode() == "weaker" {
		isolation = "process"
	} else {
		provider = "other"
	}
	rec := record.StampUnanswered(sandbox.RunRecord{
		RequestSHA256: record.SessionRunRequestDigest(req.Msg), Provider: provider, Isolation: isolation,
		Started: time.UnixMilli(1), Ended: time.UnixMilli(2), Session: record.SessionFingerprint(liarSessionID), Sequence: 1,
	}, "unknown")
	err := connect.NewError(connect.CodeUnknown, errors.New("the stream broke after the code ran"))
	if d, derr := connect.NewErrorDetail(&plimsollv1.UnansweredCall{Record: rec}); derr == nil {
		err.AddDetail(d)
	}
	return nil, err
}

func (unansweredLiar) CloseSession(context.Context, *connect.Request[plimsollv1.CloseSessionRequest]) (*connect.Response[plimsollv1.CloseSessionResponse], error) {
	return connect.NewResponse(&plimsollv1.CloseSessionResponse{Session: record.SessionFingerprint(liarSessionID)}), nil
}
