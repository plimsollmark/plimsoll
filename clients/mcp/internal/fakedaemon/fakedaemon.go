// Package fakedaemon serves the real plimsolld RPC handler over test providers, for
// the MCP server's tests. It is test support: nothing else imports it.
package fakedaemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/plimsollmark/plimsoll/internal/rpc"
	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandboxtest"
)

// Cells and fresh code the providers answer specially.
const (
	// Block waits until the test calls Release.
	Block = "plimsoll-test:block"
	// Breaks answers, then fails the call as a lost relay does: the code ran, the
	// answer is lost, and the daemon chains an unanswered record.
	Breaks = "plimsoll-test:breaks"
	// EndsSession answers, then the session ends (sandboxtest.CellEndsSession).
	EndsSession = sandboxtest.CellEndsSession
)

var exitCode = regexp.MustCompile(`^exit ([0-9]+)$`)

// Provider keeps sessions as the in-memory provider does (a cell answers
// "<language> <n>: <code>" and lists its files on stderr) and runs fresh projects,
// answering the cell file of a fresh call with "fresh <language>: <code>", its other
// files on stderr and the exit code a cell of "exit N" asks for.
type Provider struct {
	*sandboxtest.Sessions
	// Tier is the tier it states (default container); ResultTier, when set, is the
	// one its results report instead, as a provider whose evidence changed would.
	Tier, ResultTier sandbox.IsolationClass
	// SessionLanguages, when set, is what a session states it runs (SetSessionLanguages
	// changes it while the daemon serves).
	SessionLanguages []sandbox.Language
	// OpenDelay holds every session open this long; CloseDelay every close of an open
	// session.
	OpenDelay, CloseDelay time.Duration

	mu      sync.Mutex
	release chan struct{}
	blocked chan struct{}
}

func (p *Provider) tier() sandbox.IsolationClass {
	if p.Tier == sandbox.IsolationUnknown {
		return sandbox.IsolationContainer
	}
	return p.Tier
}

func (p *Provider) resultTier() sandbox.IsolationClass {
	if p.ResultTier != sandbox.IsolationUnknown {
		return p.ResultTier
	}
	return p.tier()
}

func (p *Provider) Name() string                           { return "fake-sessions" }
func (p *Provider) IsolationClass() sandbox.IsolationClass { return p.tier() }
func (*Provider) SupportsProjects() bool                   { return true }
func (*Provider) Environments() sandbox.Environments {
	langs := []sandbox.Language{sandbox.LanguagePython, sandbox.LanguageJavaScript}
	return sandbox.Environments{Project: sandbox.PayloadEnvironment{Languages: langs}}
}

// SetSessionLanguages changes what sessions state they run, as a restarted daemon would.
func (p *Provider) SetSessionLanguages(langs []sandbox.Language) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.SessionLanguages = langs
}

func (p *Provider) SessionEnvironments() sandbox.Environments {
	p.mu.Lock()
	langs := p.SessionLanguages
	p.mu.Unlock()
	if langs == nil {
		langs = []sandbox.Language{sandbox.LanguagePython, sandbox.LanguageJavaScript}
	}
	// Describe states a session's languages from its JavaScript payload environment.
	env := sandbox.PayloadEnvironment{Languages: langs}
	return sandbox.Environments{JavaScript: env, Project: env}
}

// Blocked returns a channel closed when a Block call is waiting; Release lets it go.
func (p *Provider) Blocked() <-chan struct{} {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.blocked == nil {
		p.blocked, p.release = make(chan struct{}), make(chan struct{})
	}
	return p.blocked
}

func (p *Provider) Release() {
	p.mu.Lock()
	defer p.mu.Unlock()
	close(p.release)
}

func (p *Provider) wait(ctx context.Context) {
	p.Blocked()
	p.mu.Lock()
	blocked, release := p.blocked, p.release
	p.mu.Unlock()
	select {
	case <-blocked:
	default:
		close(blocked)
	}
	select {
	case <-release:
	case <-ctx.Done():
	}
}

func (p *Provider) RunProject(ctx context.Context, req sandbox.ProjectRequest) (sandbox.ProjectResult, error) {
	var lang, code string
	var others []string
	for _, f := range req.Files {
		switch f.Path {
		case ".plimsoll/cell.py":
			lang, code = "python", f.Content
		case ".plimsoll/cell.js":
			lang, code = "javascript", f.Content
		default:
			if !strings.HasPrefix(f.Path, ".plimsoll/") {
				others = append(others, f.Path+"\n")
			}
		}
	}
	if code == Block {
		p.wait(ctx)
	}
	exit := 0
	if m := exitCode.FindStringSubmatch(code); m != nil {
		exit, _ = strconv.Atoi(m[1])
	}
	return sandbox.ProjectResult{
		Sandbox: "fake-sessions", Isolation: p.resultTier(), Outcome: sandbox.ProjectOutcomeCompleted,
		Steps: []sandbox.StepResult{{Command: req.Steps[0], ExitCode: exit, Stdout: fmt.Sprintf("fresh %s: %s", lang, code), Stderr: strings.Join(others, "")}},
	}, nil
}

func (p *Provider) OpenSession(ctx context.Context, opts sandbox.SessionOptions) (sandbox.Session, error) {
	if p.OpenDelay > 0 {
		time.Sleep(p.OpenDelay)
	}
	s, err := p.Sessions.OpenSession(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &session{Session: s, p: p}, nil
}

type session struct {
	sandbox.Session
	p         *Provider
	closeOnce sync.Once
}

func (s *session) Isolation() sandbox.IsolationClass { return s.p.resultTier() }

func (s *session) RunJavaScript(ctx context.Context, req sandbox.Request) (sandbox.Result, error) {
	result, err := s.Session.RunJavaScript(ctx, req)
	result.Isolation = s.p.resultTier()
	return result, err
}

func (s *session) RunProject(ctx context.Context, req sandbox.ProjectRequest) (sandbox.ProjectResult, error) {
	result, err := s.Session.RunProject(ctx, req)
	result.Isolation = s.p.resultTier()
	return result, err
}

func (s *session) Environments() sandbox.Environments { return s.p.SessionEnvironments() }

// Close, with CloseDelay, is a provider's delete: the end starts at once, the sandbox
// is gone (Done) once the delete has taken CloseDelay, and closing again waits for the
// same end.
func (s *session) Close(ctx context.Context) error {
	if s.p.CloseDelay <= 0 {
		return s.Session.Close(ctx)
	}
	s.closeOnce.Do(func() {
		go func() {
			time.Sleep(s.p.CloseDelay)
			_ = s.Session.Close(context.Background())
		}()
	})
	return nil
}

func (s *session) RunCell(ctx context.Context, req sandbox.CellRequest) (sandbox.CellResult, error) {
	if req.Code == Block {
		s.p.wait(ctx)
	}
	res, err := s.Session.RunCell(ctx, req)
	res.Isolation = s.p.resultTier()
	if err == nil && req.Code == Breaks {
		return res, errors.New("the relay was lost after the code ran")
	}
	return res, err
}

// Daemon is one served fake.
type Daemon struct {
	URL      string
	Provider *Provider
	Service  *rpc.SandboxService
	stop     func()
}

// Stop takes the daemon away, as a crash or a lost network would.
func (d *Daemon) Stop() { d.stop() }

// Options shape a daemon.
type Options struct {
	Sessions int // open sessions at once; 0 = sessions off
	Tier     sandbox.IsolationClass
	// ResultTier, SessionLanguages: see Provider.
	ResultTier       sandbox.IsolationClass
	SessionLanguages []sandbox.Language
	OpenDelay        time.Duration
	CloseDelay       time.Duration
	// PerOwner is the daemon's cap on one owner's sessions (SANDBOX_MAX_SESSIONS_PER_OWNER).
	PerOwner int
	// StripRequestID removes the daemon's echo of the request ID from every Run and
	// SessionRun answer, as an intermediary serving another request's answer would.
	StripRequestID bool
}

// Serve starts a daemon over a Provider.
func Serve(t testing.TB, o Options) *Daemon {
	t.Helper()
	p := &Provider{Sessions: &sandboxtest.Sessions{}, Tier: o.Tier, ResultTier: o.ResultTier, SessionLanguages: o.SessionLanguages, OpenDelay: o.OpenDelay, CloseDelay: o.CloseDelay}
	svc := rpc.NewSandboxService(p)
	svc.Sessions = rpc.SessionConfig{MaxSessions: o.Sessions, MaxPerOwner: o.PerOwner, Lifetime: time.Hour, IdleTimeout: time.Hour}
	url, stop := serve(t, svc, o.StripRequestID)
	return &Daemon{URL: url, Provider: p, Service: svc, stop: stop}
}

// ServeWasm starts a daemon over the wasm provider: snippets only, no sessions.
func ServeWasm(t testing.TB) string {
	t.Helper()
	url, _ := serve(t, rpc.NewSandboxService(sandboxtest.Wasm()), false)
	return url
}

func serve(t testing.TB, svc *rpc.SandboxService, strip bool) (string, func()) {
	svc.Logger = slog.New(slog.DiscardHandler)
	mux := http.NewServeMux()
	path, h := rpc.NewHandler(svc, connect.WithInterceptors(rpc.AuthInterceptor(nil)))
	mux.Handle(path, h)
	var handler http.Handler = mux
	if strip {
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/Run") || strings.HasSuffix(r.URL.Path, "/SessionRun") {
				w = stripping{w}
			}
			mux.ServeHTTP(w, r)
		})
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv.URL, func() { srv.CloseClientConnections(); srv.Close() }
}

type stripping struct{ http.ResponseWriter }

func (s stripping) WriteHeader(code int) {
	s.Header().Del("Plimsoll-Request-Id")
	s.ResponseWriter.WriteHeader(code)
}

func (s stripping) Write(b []byte) (int, error) {
	s.Header().Del("Plimsoll-Request-Id")
	return s.ResponseWriter.Write(b)
}

func (s stripping) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// OpenSessions is how many of the daemon's sessions have not ended.
func (d *Daemon) OpenSessions() int {
	n := 0
	for _, s := range d.Provider.Opened() {
		if s.Err() == nil {
			n++
		}
	}
	return n
}

// DownURL is a URL nothing answers.
func DownURL(t testing.TB) string {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	return url
}
