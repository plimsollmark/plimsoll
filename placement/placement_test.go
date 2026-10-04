package placement

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/plimsollmark/plimsoll/client"
	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1/plimsollv1connect"
	"github.com/plimsollmark/plimsoll/internal/rpc"
	"github.com/plimsollmark/plimsoll/protocol"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandboxtest"
)

// stub is a daemon that answers Describe as configured and Run as scripted, and
// records what reached it.
type stub struct {
	plimsollv1connect.UnimplementedSandboxServiceHandler
	name        string
	describe    *plimsollv1.DescribeResponse
	answer      func(*plimsollv1.RunRequest) (*plimsollv1.RunResponse, error)
	openErr     error
	runs        int
	lastToken   string
	floors      []string // minimum_isolation of every Run and OpenSession that reached it
	ranIn       string   // the environment its records state, when not what Describe says
	ranSoftware string   // selected software, when different from Describe
	// describeHook, when set, answers Describe instead of describe, and may block.
	describeHook func() *plimsollv1.DescribeResponse
}

func (s *stub) Describe(context.Context, *connect.Request[plimsollv1.DescribeRequest]) (*connect.Response[plimsollv1.DescribeResponse], error) {
	if s.describeHook != nil {
		return connect.NewResponse(s.describeHook()), nil
	}
	return connect.NewResponse(s.describe), nil
}

func (s *stub) Run(_ context.Context, req *connect.Request[plimsollv1.RunRequest]) (*connect.Response[plimsollv1.RunResponse], error) {
	s.runs++
	s.lastToken = req.Header().Get("Authorization")
	s.floors = append(s.floors, req.Msg.GetMinimumIsolation())
	resp, err := s.answer(req.Msg)
	if err != nil {
		return nil, err
	}
	// A daemon states the identities its Describe states for the payload's kind, unless
	// the test scripts another: ranIn for the environment, ranSoftware for the software,
	// each on its own.
	described := s.describe.GetJavascriptEnvironment()
	switch req.Msg.GetPayload().(type) {
	case *plimsollv1.RunRequest_Project:
		described = s.describe.GetProjectEnvironment()
	case *plimsollv1.RunRequest_Module:
		described = s.describe.GetModuleEnvironment()
	}
	env, software := s.ranIn, s.ranSoftware
	if env == "" {
		env = described.GetIdentity()
	}
	if software == "" {
		software = described.GetSoftwareIdentity()
	}
	resp.Environment, resp.SoftwareIdentity = env, software
	rule := sandbox.SoftwareRule{Mode: sandbox.SoftwareMode(req.Msg.GetSoftwareRule().GetMode()), Identities: req.Msg.GetSoftwareRule().GetIdentities()}
	resp.Record = record.Stamp(sandbox.RunRecord{RequestSHA256: record.RunRequestDigest(req.Msg), SoftwareRuleID: rule.ID()}, resp)
	return connect.NewResponse(resp), nil
}

func (s *stub) OpenSession(_ context.Context, req *connect.Request[plimsollv1.OpenSessionRequest]) (*connect.Response[plimsollv1.OpenSessionResponse], error) {
	s.floors = append(s.floors, req.Msg.GetMinimumIsolation())
	if s.openErr != nil {
		return nil, s.openErr
	}
	id := strings.Repeat("a", 32)
	return connect.NewResponse(&plimsollv1.OpenSessionResponse{
		SessionId: id, Session: record.SessionFingerprint(id), Sandbox: s.describe.GetSandbox(),
		Isolation: s.describe.GetIsolation(), ExpiresUnixMs: time.Now().Add(time.Minute).UnixMilli(),
	}), nil
}

func describeAs(provider, isolation string, opts ...func(*plimsollv1.DescribeResponse)) *plimsollv1.DescribeResponse {
	d := &plimsollv1.DescribeResponse{
		Sandbox: provider, Isolation: isolation, Protocol: protocol.Number,
		SupportsProject: true, SupportsJavascriptGrants: true, SupportsProjectGrants: true,
		JavascriptEnvironment: &plimsollv1.PayloadEnvironment{Identity: provider + "-image:1"},
		ProjectEnvironment:    &plimsollv1.PayloadEnvironment{Identity: provider + "-image:1"},
	}
	for _, o := range opts {
		o(d)
	}
	return d
}

func ok(stdout string) func(*plimsollv1.RunRequest) (*plimsollv1.RunResponse, error) {
	return func(m *plimsollv1.RunRequest) (*plimsollv1.RunResponse, error) {
		resp := &plimsollv1.RunResponse{Sandbox: "stub", Isolation: "vm"}
		switch m.GetPayload().(type) {
		case *plimsollv1.RunRequest_Project:
			resp.Result = &plimsollv1.RunResponse_Project{Project: &plimsollv1.ProjectResult{Outcome: plimsollv1.ProjectOutcome_PROJECT_OUTCOME_COMPLETED}}
		case *plimsollv1.RunRequest_Module:
			resp.Result = &plimsollv1.RunResponse_Module{Module: &plimsollv1.ModuleResult{Outcome: plimsollv1.ProjectOutcome_PROJECT_OUTCOME_COMPLETED}}
		default:
			resp.Result = &plimsollv1.RunResponse_Javascript{Javascript: &plimsollv1.JavaScriptResult{Stdout: []byte(stdout)}}
		}
		return resp, nil
	}
}

func TestSoftwareRuleSelectsApprovedImageAndTravelsWithRequest(t *testing.T) {
	a := "oci-manifest:linux/amd64@sha256:" + strings.Repeat("a", 64)
	b := "oci-manifest:linux/amd64@sha256:" + strings.Repeat("b", 64)
	first := &stub{name: "first", describe: describeAs("fake", "vm", func(d *plimsollv1.DescribeResponse) {
		d.JavascriptEnvironment.SoftwareIdentity = a
	}), answer: ok("first")}
	second := &stub{name: "second", describe: describeAs("fake", "vm", func(d *plimsollv1.DescribeResponse) {
		d.JavascriptEnvironment.SoftwareIdentity = b
	}), answer: ok("second")}
	p := pool(t, first, second)
	req := Requirement{Software: sandbox.SoftwareRule{Mode: sandbox.SoftwareExact, Identities: []string{b}}}
	result, choice, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"}, req)
	if err != nil || choice.Backend != "second" || first.runs != 0 || second.runs != 1 ||
		result.Record.SoftwareIdentity != b || result.Record.SoftwareRuleID != "exact:"+b {
		t.Fatalf("choice %+v, result %+v, err %v", choice, result, err)
	}
	approved := Requirement{Software: sandbox.SoftwareRule{Mode: sandbox.SoftwareApproved, Identities: []string{a, b}}}
	_, choice, err = p.RunJavaScript(context.Background(), sandbox.Request{Code: "2"}, approved)
	if err != nil || choice.Backend != "first" || first.runs != 1 {
		t.Fatalf("approved choice %+v, error %v", choice, err)
	}
}

// refuse answers with a refusal carrying the not-dispatched mark.
func refuse(reason plimsollv1.NotDispatchedReason) func(*plimsollv1.RunRequest) (*plimsollv1.RunResponse, error) {
	return func(*plimsollv1.RunRequest) (*plimsollv1.RunResponse, error) {
		code := connect.CodeResourceExhausted
		if reason == plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_PERMISSION {
			code = connect.CodePermissionDenied
		}
		ce := connect.NewError(code, errors.New("refused by the stub"))
		if d, err := connect.NewErrorDetail(&plimsollv1.NotDispatched{Reason: reason}); err == nil {
			ce.AddDetail(d)
		}
		return nil, ce
	}
}

// failUnmarked answers with an error that does not say whether anything ran.
func failUnmarked(*plimsollv1.RunRequest) (*plimsollv1.RunResponse, error) {
	return nil, connect.NewError(connect.CodeInternal, errors.New("the daemon fell over mid-run"))
}

func serve(t *testing.T, s *stub) Backend {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(plimsollv1connect.NewSandboxServiceHandler(s))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c, err := client.New(srv.URL, client.WithToken("token-"+s.name))
	if err != nil {
		t.Fatal(err)
	}
	return Backend{Name: s.name, Client: c}
}

func pool(t *testing.T, stubs ...*stub) *Pool {
	t.Helper()
	var backends []Backend
	for _, s := range stubs {
		backends = append(backends, serve(t, s))
	}
	p, err := New(backends, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestFilterKeepsOnlyBackendsThatCanTakeTheRequest(t *testing.T) {
	container := &stub{name: "container", describe: describeAs("docker", "container"), answer: ok("container ran\n")}
	vm := &stub{name: "vm", describe: describeAs("e2b", "vm"), answer: ok("vm ran\n")}
	p := pool(t, container, vm)
	ctx := context.Background()

	// A vm floor skips the container backend entirely: it is never sent the request.
	res, choice, err := p.RunJavaScript(ctx, sandbox.Request{Code: "1", MinimumIsolation: sandbox.IsolationVM},
		Requirement{MinimumIsolation: sandbox.IsolationVM})
	if err != nil || choice.Backend != "vm" || res.Stdout != "vm ran\n" {
		t.Fatalf("result %+v choice %+v err %v", res, choice, err)
	}
	if container.runs != 0 {
		t.Fatalf("the container backend was sent %d requests despite the floor", container.runs)
	}
	// A named provider wins over order.
	_, choice, err = p.RunJavaScript(ctx, sandbox.Request{Code: "1"}, Requirement{Provider: "e2b"})
	if err != nil || choice.Backend != "vm" {
		t.Fatalf("choice %+v err %v", choice, err)
	}
	// A named backend that cannot take the request is an error, not a fallback.
	_, _, err = p.RunJavaScript(ctx, sandbox.Request{Code: "1"},
		Requirement{Backend: "container", MinimumIsolation: sandbox.IsolationVM})
	// Two runs so far, both on vm; the refused request added none.
	if !errors.Is(err, ErrNoBackend) || vm.runs != 2 {
		t.Fatalf("err %v, vm runs %d", err, vm.runs)
	}
	if _, marked := sandbox.NotDispatchedReason(err); !marked {
		t.Fatal("the router's own refusal is not marked as not dispatched")
	}
}

func TestFilterReadsSupportAndEnvironment(t *testing.T) {
	noProject := &stub{name: "wasm", describe: describeAs("wasm", "process", func(d *plimsollv1.DescribeResponse) {
		d.SupportsProject, d.SupportsProjectGrants = false, false
	}), answer: ok("")}
	full := &stub{name: "docker", describe: describeAs("docker", "container", func(d *plimsollv1.DescribeResponse) {
		d.SupportsModule = true
		d.ModuleEnvironment = &plimsollv1.PayloadEnvironment{Identity: "docker-image:1"}
	}), answer: ok("")}
	p := pool(t, noProject, full)
	ctx := context.Background()

	if _, choice, err := p.RunProject(ctx, sandbox.ProjectRequest{Steps: []string{"true"}}, Requirement{}); err != nil || choice.Backend != "docker" {
		t.Fatalf("project: choice %+v err %v", choice, err)
	}
	if _, choice, err := p.RunModule(ctx, sandbox.ModuleRequest{Model: "m", Rows: [][]float64{{1}}, EndTime: 1, Step: 0.5}, Requirement{}); err != nil || choice.Backend != "docker" {
		t.Fatalf("module: choice %+v err %v", choice, err)
	}
	// A module run cannot carry a grant, whatever a backend says.
	if _, _, err := p.RunModule(ctx, sandbox.ModuleRequest{Model: "m", Rows: [][]float64{{1}}, EndTime: 1, Step: 0.5},
		Requirement{GrantProfile: true}); !errors.Is(err, ErrNoBackend) {
		t.Fatalf("a module run with a grant: %v", err)
	}
	// A snippet grant is fine on the wasm backend, which states snippet grants.
	if _, choice, err := p.RunJavaScript(ctx, sandbox.Request{Code: "1"}, Requirement{GrantProfile: true}); err != nil || choice.Backend != "wasm" {
		t.Fatalf("snippet grant: choice %+v err %v", choice, err)
	}
	// An environment that no backend states keeps none: an empty identity claims nothing.
	if _, _, err := p.RunJavaScript(ctx, sandbox.Request{Code: "1"}, Requirement{Environment: "other-image:9"}); !errors.Is(err, ErrNoBackend) {
		t.Fatalf("an environment nobody states: %v", err)
	}
	if _, choice, err := p.RunJavaScript(ctx, sandbox.Request{Code: "1"}, Requirement{Environment: "docker-image:1"}); err != nil || choice.Backend != "docker" {
		t.Fatalf("a named environment: choice %+v err %v", choice, err)
	}
}

func TestRetriesOnlyRefusalsThatRanNothing(t *testing.T) {
	for name, tc := range map[string]struct {
		first    func(*plimsollv1.RunRequest) (*plimsollv1.RunResponse, error)
		wantRuns int
		wantOn   string
	}{
		"capacity":    {refuse(plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_CAPACITY), 1, "second"},
		"unsupported": {refuse(plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_UNSUPPORTED), 1, "second"},
		"isolation":   {refuse(plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_ISOLATION), 1, "second"},
		"environment": {refuse(plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_ENVIRONMENT), 1, "second"},
		"permission":  {refuse(plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_PERMISSION), 0, "first"},
		"request":     {refuse(plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_REQUEST), 0, "first"},
		"unmarked":    {failUnmarked, 0, "first"},
	} {
		t.Run(name, func(t *testing.T) {
			first := &stub{name: "first", describe: describeAs("docker", "vm"), answer: tc.first}
			second := &stub{name: "second", describe: describeAs("e2b", "vm"), answer: ok("second ran\n")}
			p := pool(t, first, second)
			res, choice, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"}, Requirement{})
			if second.runs != tc.wantRuns {
				t.Fatalf("the second backend ran %d times, want %d (err %v)", second.runs, tc.wantRuns, err)
			}
			if choice.Backend != tc.wantOn {
				t.Fatalf("ran on %q, want %q", choice.Backend, tc.wantOn)
			}
			if tc.wantRuns == 1 {
				if err != nil || res.Stdout != "second ran\n" || len(choice.Retried) != 1 || choice.Retried[0].Backend != "first" {
					t.Fatalf("res %+v choice %+v err %v", res, choice, err)
				}
			} else if err == nil {
				t.Fatal("a refusal that may have run, or that every backend would give, was retried or swallowed")
			}
		})
	}
}

// The last backend's refusal is the caller's error, with the ones before it named.
func TestEveryBackendRefusing(t *testing.T) {
	a := &stub{name: "a", describe: describeAs("docker", "vm"), answer: refuse(plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_CAPACITY)}
	b := &stub{name: "b", describe: describeAs("e2b", "vm"), answer: refuse(plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_CAPACITY)}
	p := pool(t, a, b)
	_, choice, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"}, Requirement{})
	if !errors.Is(err, sandbox.ErrAtCapacity) || choice.Backend != "b" || len(choice.Retried) != 1 {
		t.Fatalf("choice %+v err %v", choice, err)
	}
	if _, marked := sandbox.NotDispatchedReason(err); !marked {
		t.Fatal("the last refusal lost its mark")
	}
}

// Each backend gets the caller's own credential for that backend, never one shared
// bearer: a profile's allowed_callers and a minted token's subject depend on it.
func TestEachBackendKeepsItsOwnCredential(t *testing.T) {
	a := &stub{name: "a", describe: describeAs("docker", "vm"), answer: refuse(plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_CAPACITY)}
	b := &stub{name: "b", describe: describeAs("e2b", "vm"), answer: ok("ran\n")}
	p := pool(t, a, b)
	if _, _, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"}, Requirement{}); err != nil {
		t.Fatal(err)
	}
	if a.lastToken != "Bearer token-a" || b.lastToken != "Bearer token-b" {
		t.Fatalf("tokens: a %q, b %q", a.lastToken, b.lastToken)
	}
}

func TestPreferRanksTheSurvivors(t *testing.T) {
	cheap := &stub{name: "cheap", describe: describeAs("docker", "container"), answer: ok("cheap\n")}
	strong := &stub{name: "strong", describe: describeAs("e2b", "vm"), answer: ok("strong\n")}
	p := pool(t, cheap, strong)
	res, choice, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"}, Requirement{
		Prefer: func(x, y client.Info) int { return int(y.Isolation) - int(x.Isolation) }, // strongest first
	})
	if err != nil || choice.Backend != "strong" || res.Stdout != "strong\n" {
		t.Fatalf("choice %+v res %+v err %v", choice, res, err)
	}
}

// A session lives on one daemon, so the choice is made once and the client returned
// is that daemon's.
func TestOpenSessionPlacesOnce(t *testing.T) {
	noSessions := &stub{name: "plain", describe: describeAs("docker", "container"), answer: ok("")}
	withSessions := &stub{name: "sessions", describe: describeAs("openshell", "container", func(d *plimsollv1.DescribeResponse) {
		d.SupportsSessions = true
		d.SessionLifetimeMs = 60000
	}), answer: ok("")}
	p := pool(t, noSessions, withSessions)
	s, choice, err := p.OpenSession(context.Background(), client.SessionOptions{}, Requirement{})
	if err != nil || choice.Backend != "sessions" || s == nil {
		t.Fatalf("choice %+v err %v", choice, err)
	}
	only := pool(t, noSessions)
	if _, _, err := only.OpenSession(context.Background(), client.SessionOptions{}, Requirement{}); !errors.Is(err, ErrNoBackend) {
		t.Fatalf("a pool with no session backend: %v", err)
	}
}

// The floor a request was placed with travels with it. A backend described as a VM
// that answers from a container (its tier dropped after the cached Describe) must not
// hand back that answer as a success, and the daemon must have been told the floor,
// so a real one would have refused before dispatch.
func TestThePlacementFloorRidesOnTheRequest(t *testing.T) {
	downgraded := func(m *plimsollv1.RunRequest) (*plimsollv1.RunResponse, error) {
		resp, err := ok("")(m)
		resp.Isolation = "container"
		return resp, err
	}
	s := &stub{name: "was-vm", describe: describeAs("e2b", "vm", func(d *plimsollv1.DescribeResponse) {
		d.SupportsModule = true
		d.ModuleEnvironment = &plimsollv1.PayloadEnvironment{Identity: "e2b-sim:1"}
		d.SupportsSessions = true
		d.SessionLifetimeMs = 60000
	}), answer: downgraded}
	p := pool(t, s)
	ctx := context.Background()
	vm := Requirement{MinimumIsolation: sandbox.IsolationVM}
	_, _, jsErr := p.RunJavaScript(ctx, sandbox.Request{Code: "1"}, vm)
	_, _, projErr := p.RunProject(ctx, sandbox.ProjectRequest{Steps: []string{"true"}}, vm)
	_, _, modErr := p.RunModule(ctx, sandbox.ModuleRequest{Model: "m", Rows: [][]float64{{1}}, EndTime: 1, Step: 0.5}, vm)
	for name, err := range map[string]error{"javascript": jsErr, "project": projErr, "module": modErr} {
		if !errors.Is(err, sandbox.ErrIsolationEvidenceMismatch) {
			t.Errorf("%s: a container answer to a VM placement: %v", name, err)
		}
	}
	if _, _, err := p.OpenSession(ctx, client.SessionOptions{}, vm); err != nil {
		t.Fatalf("open: %v", err)
	}
	if want := []string{"vm", "vm", "vm", "vm"}; !slices.Equal(s.floors, want) {
		t.Fatalf("floors on the wire %q, want %q", s.floors, want)
	}

	// The stronger of the two floors wins, whichever side states it.
	s.floors, s.answer = nil, ok("")
	if _, _, err := p.RunJavaScript(ctx, sandbox.Request{Code: "1", MinimumIsolation: sandbox.IsolationVM},
		Requirement{MinimumIsolation: sandbox.IsolationContainer}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(s.floors, []string{"vm"}) {
		t.Fatalf("floors on the wire %q, want the request's stronger vm", s.floors)
	}

	// An invalid floor is refused before anything is sent, not outvoted by a valid one.
	s.floors = nil
	_, _, err := p.RunJavaScript(ctx, sandbox.Request{Code: "1", MinimumIsolation: sandbox.IsolationNone}, vm)
	if reason, marked := sandbox.NotDispatchedReason(err); !errors.Is(err, sandbox.ErrInvalidRequest) || !marked || reason != sandbox.RefusalRequest || len(s.floors) != 0 {
		t.Fatalf("an invalid request floor: err %v (reason %v, marked %v), %d sent", err, reason, marked, len(s.floors))
	}
}

// A backend that was down is used once it answers again: descriptions are refreshed,
// not fixed at startup.
func TestADescriptionIsRefreshed(t *testing.T) {
	down := &stub{name: "down", describe: describeAs("docker", "vm"), answer: ok("back\n")}
	backend := serve(t, down)
	p, err := New([]Backend{backend}, 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	// It now reports a weaker tier; the next request past the TTL sees that.
	down.describe = describeAs("docker", "container")
	time.Sleep(20 * time.Millisecond)
	if _, _, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"}, Requirement{MinimumIsolation: sandbox.IsolationVM}); !errors.Is(err, ErrNoBackend) {
		t.Fatalf("a stale description was used: %v", err)
	}
}

// A slow Refresh that finishes after an on-demand Describe does not put its older
// answer back (review F12): the pool keeps the answer asked for last.
func TestASlowRefreshKeepsTheNewerDescription(t *testing.T) {
	asked, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	st := &stub{name: "b", answer: ok("1\n")}
	st.describeHook = func() *plimsollv1.DescribeResponse {
		if calls.Add(1) == 1 { // Refresh's: asked first, answers last, with the older tier
			close(asked)
			<-release
			return describeAs("docker", "container")
		}
		return describeAs("docker", "vm")
	}
	backend := serve(t, st)
	p, err := New([]Backend{backend}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	refreshed := make(chan error, 1)
	go func() { refreshed <- p.Refresh(context.Background()) }()
	<-asked
	info, err := p.Describe(context.Background(), backend.Name)
	if err != nil || info.Isolation != sandbox.IsolationVM {
		t.Fatalf("the on-demand description: %+v, %v", info, err)
	}
	close(release)
	if err := <-refreshed; err != nil {
		t.Fatal(err)
	}
	if info, err := p.Describe(context.Background(), backend.Name); err != nil || info.Isolation != sandbox.IsolationVM {
		t.Fatalf("after the slow refresh: %+v, %v; want the newer vm description kept", info, err)
	}
}

func TestNewChecksItsBackends(t *testing.T) {
	c, err := client.New("http://127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	for name, backends := range map[string][]Backend{
		"none":       {},
		"no name":    {{Client: c}},
		"no client":  {{Name: "a"}},
		"duplicated": {{Name: "a", Client: c}, {Name: "a", Client: c}},
	} {
		if _, err := New(backends, 0); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// A real daemon behind the router, not a stub: the wasm provider, with the router
// choosing it by tier and the run's evidence checked by the client as usual.
func TestAgainstARealDaemon(t *testing.T) {
	mux := http.NewServeMux()
	path, h := plimsollv1connect.NewSandboxServiceHandler(rpc.NewSandboxService(sandboxtest.Wasm()),
		connect.WithInterceptors(rpc.AuthInterceptor(nil)))
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c, err := client.New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	p, err := New([]Backend{{Name: "local", Client: c}}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	res, choice, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: `console.log(6*7)`},
		Requirement{MinimumIsolation: sandbox.IsolationProcess})
	if err != nil || choice.Backend != "local" || !strings.Contains(res.Stdout, "42") {
		t.Fatalf("res %+v choice %+v err %v", res, choice, err)
	}
	if res.Record == nil {
		t.Fatal("the run record did not come back through the router")
	}
	// A floor the only backend cannot meet is refused here, without a request.
	if _, _, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"},
		Requirement{MinimumIsolation: sandbox.IsolationVM}); !errors.Is(err, ErrNoBackend) {
		t.Fatalf("a vm floor on a process-tier daemon: %v", err)
	}
}

// TestEnvironmentRequirementIsCheckedAgainstTheRun: a backend whose Describe answer
// (cached for a minute) named the required environment but whose run record states
// another must not be reported as a success, and must not be retried elsewhere,
// because the run happened (external review of v0.10.0, finding 7, 2026-09-28).
func TestEnvironmentRequirementIsCheckedAgainstTheRun(t *testing.T) {
	moved := &stub{name: "moved", describe: describeAs("docker", "kernel"), answer: ok("x"), ranIn: "docker-image:2"}
	spare := &stub{name: "spare", describe: describeAs("docker", "kernel"), answer: ok("x")}
	p := pool(t, moved, spare)
	ctx := context.Background()
	req := Requirement{Environment: "docker-image:1"}
	_, choice, err := p.RunJavaScript(ctx, sandbox.Request{Code: "1"}, req)
	if !errors.Is(err, ErrEnvironmentMismatch) {
		t.Fatalf("a run whose record states docker-image:2 under a docker-image:1 requirement: %v", err)
	}
	if _, marked := sandbox.NotDispatchedReason(err); marked || spare.runs != 0 || choice.Backend != "moved" {
		t.Fatalf("the mismatch was treated as not dispatched (marked %v, spare ran %d, choice %+v)", marked, spare.runs, choice)
	}
	if _, _, err := p.RunProject(ctx, sandbox.ProjectRequest{Files: []sandbox.File{{Path: "a.js", Content: "1"}}, Steps: []string{"node a.js"}}, Requirement{Environment: "docker-image:1", Backend: "moved"}); !errors.Is(err, ErrEnvironmentMismatch) {
		t.Fatalf("a project run: %v", err)
	}
	if _, _, err := p.RunJavaScript(ctx, sandbox.Request{Code: "1"}, Requirement{Environment: "docker-image:1", Backend: "spare"}); err != nil {
		t.Fatalf("a run whose record states the required environment: %v", err)
	}
}

func withSoftware(id string) func(*plimsollv1.DescribeResponse) {
	return func(d *plimsollv1.DescribeResponse) {
		d.JavascriptEnvironment.SoftwareIdentity = id
		d.ProjectEnvironment.SoftwareIdentity = id
	}
}

// TestSoftwareRequirementIsCheckedAgainstTheRun is the software analogue of
// TestEnvironmentRequirementIsCheckedAgainstTheRun: a backend whose Describe named an
// approved identity but whose run reports another is not a success, and is not retried
// elsewhere, because the run happened.
func TestSoftwareRequirementIsCheckedAgainstTheRun(t *testing.T) {
	const idA = "oci-manifest:linux/amd64@sha256:1111111111111111111111111111111111111111111111111111111111111111"
	const idB = "oci-manifest:linux/amd64@sha256:2222222222222222222222222222222222222222222222222222222222222222"
	moved := &stub{name: "moved", describe: describeAs("docker", "kernel", withSoftware(idA)),
		answer: ok("x"), ranSoftware: idB}
	spare := &stub{name: "spare", describe: describeAs("docker", "kernel", withSoftware(idA)), answer: ok("x")}
	p := pool(t, moved, spare)
	ctx := context.Background()
	rule := sandbox.SoftwareRule{Mode: sandbox.SoftwareExact, Identities: []string{idA}}

	_, choice, err := p.RunJavaScript(ctx, sandbox.Request{Code: "1"}, Requirement{Software: rule})
	if err == nil {
		t.Fatal("a run reporting an identity outside the rule was reported as a success")
	}
	if _, marked := sandbox.NotDispatchedReason(err); marked {
		t.Fatalf("the mismatch was marked not dispatched, though the run happened: %v", err)
	}
	if spare.runs != 0 {
		t.Fatalf("the request was retried elsewhere after it had already run (spare ran %d)", spare.runs)
	}
	if choice.Backend != "moved" {
		t.Fatalf("choice = %+v, want the backend that ran it", choice)
	}
	if _, _, err := p.RunJavaScript(ctx, sandbox.Request{Code: "1"},
		Requirement{Software: rule, Backend: "spare"}); err != nil {
		t.Fatalf("a run reporting the required identity: %v", err)
	}
}

type failingRecorder struct{}

func (failingRecorder) Record(*plimsollv1.RunRequest, *plimsollv1.RunResponse) error {
	return errors.New("disk full")
}

// A recorder that fails must not hide that the run went to another environment:
// the error carries both ErrEnvironmentMismatch and client.ErrNotRecorded.
func TestEnvironmentIsCheckedWhenTheRecorderFails(t *testing.T) {
	moved := &stub{name: "moved", describe: describeAs("docker", "kernel"), answer: ok("x"), ranIn: "docker-image:2"}
	b := serve(t, moved)
	mux := http.NewServeMux()
	mux.Handle(plimsollv1connect.NewSandboxServiceHandler(moved))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c, err := client.New(srv.URL, client.WithToken("token-moved"), client.WithRecorder(failingRecorder{}))
	if err != nil {
		t.Fatal(err)
	}
	b.Client = c
	p, err := New([]Backend{b}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"}, Requirement{Environment: "docker-image:1"})
	if !errors.Is(err, ErrEnvironmentMismatch) || !errors.Is(err, client.ErrNotRecorded) {
		t.Fatalf("err = %v, want ErrEnvironmentMismatch joined with client.ErrNotRecorded", err)
	}
}

// A session is filtered on where sessions run, which Describe states, not on where a
// single snippet runs: on docker a session runs in the project image, so a requirement
// naming that image places it, and one naming the snippet image does not (v0.15.0
// review, L19).
func TestSessionsAreFilteredOnTheSessionEnvironment(t *testing.T) {
	project := "oci-manifest:linux/amd64@sha256:" + strings.Repeat("b", 64)
	docker := &stub{name: "docker", describe: describeAs("docker", "kernel", func(d *plimsollv1.DescribeResponse) {
		d.SupportsSessions = true
		d.JavascriptEnvironment = &plimsollv1.PayloadEnvironment{Identity: "docker-image:snippet"}
		d.SessionEnvironment = &plimsollv1.PayloadEnvironment{Identity: "docker-image:project", SoftwareIdentity: project}
	}), answer: ok("")}
	p := pool(t, docker)
	ctx := context.Background()
	if _, choice, err := p.OpenSession(ctx, client.SessionOptions{}, Requirement{Environment: "docker-image:project"}); err != nil || choice.Backend != "docker" {
		t.Fatalf("a requirement naming the session's environment: choice %+v, err %v", choice, err)
	}
	if _, _, err := p.OpenSession(ctx, client.SessionOptions{}, Requirement{Environment: "docker-image:snippet"}); !errors.Is(err, ErrNoBackend) {
		t.Fatalf("a requirement naming the snippet environment placed a session: %v", err)
	}
	rule := sandbox.SoftwareRule{Mode: sandbox.SoftwareExact, Identities: []string{project}}
	if _, _, err := p.OpenSession(ctx, client.SessionOptions{}, Requirement{Software: rule}); errors.Is(err, ErrNoBackend) {
		t.Fatalf("a software rule naming the project image excluded the backend: %v", err)
	}
}
