package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1/plimsollv1connect"
	"github.com/plimsollmark/plimsoll/protocol"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// floorTestProvider is SANDBOX_PROVIDER=floor-test, registered only in a child daemon
// whose environment sets PLIMSOLLD_FLOOR_TEST_PROVIDER=1 (TestMain). It proves kernel
// isolation at startup and finds container isolation on every dispatch, as agentsandbox
// does when its runtime class is replaced under a running daemon: each dispatch checks the
// request's floor against what it found, and records that as its evidence from then on.
const floorTestProvider = "floor-test"

type staleTierSandbox struct {
	mu     sync.Mutex
	stated sandbox.IsolationClass
}

func (*staleTierSandbox) Name() string { return floorTestProvider }
func (s *staleTierSandbox) IsolationClass() sandbox.IsolationClass {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stated
}

func (s *staleTierSandbox) dispatch(floor sandbox.IsolationClass) error {
	s.mu.Lock()
	s.stated = sandbox.IsolationContainer
	s.mu.Unlock()
	return sandbox.CheckMinimumIsolation(sandbox.IsolationContainer, floor)
}

func (s *staleTierSandbox) RunJavaScript(_ context.Context, req sandbox.Request) (sandbox.Result, error) {
	if err := s.dispatch(req.MinimumIsolation); err != nil {
		return sandbox.Result{}, err
	}
	return sandbox.Result{Stdout: "ran at container", Sandbox: floorTestProvider, Isolation: sandbox.IsolationContainer}, nil
}

func (s *staleTierSandbox) RunProject(_ context.Context, req sandbox.ProjectRequest) (sandbox.ProjectResult, error) {
	if err := s.dispatch(req.MinimumIsolation); err != nil {
		return sandbox.ProjectResult{}, err
	}
	return sandbox.ProjectResult{Sandbox: floorTestProvider, Isolation: sandbox.IsolationContainer, Outcome: sandbox.ProjectOutcomeCompleted}, nil
}

func (*staleTierSandbox) RunModule(context.Context, sandbox.ModuleRequest) (sandbox.ModuleResult, error) {
	return sandbox.ModuleResult{}, sandbox.NotDispatched(sandbox.RefusalUnsupported, sandbox.ErrUnsupported)
}

func (*staleTierSandbox) SupportsProjects() bool { return true }

func registerFloorTestProvider() {
	providers[floorTestProvider] = providerDescriptor{
		build: func(getenv func(string) string) (sandbox.Provider, error) {
			res, err := sandbox.ResourcesFromEnv(getenv)
			return sandbox.Provider{Sandbox: &staleTierSandbox{stated: sandbox.IsolationKernel}, Resources: res}, err
		},
		usage:            "\n  SANDBOX_PROVIDER=floor-test a provider the floor test registers in its child daemon\n",
		hardenedEnvelope: []string{"SANDBOX_MEMORY_MB"},
		hardened:         func(func(string) string, func(string, ...any), func(error)) {},
	}
}

// isolationFloor is hardened mode's startup rule held on every run: the level the policy
// accepts at startup is the floor, and a daemon not in hardened mode holds none.
func TestIsolationFloorIsHardenedModesRule(t *testing.T) {
	if got := isolationFloor(false, sandbox.IsolationUnknown); got != sandbox.IsolationUnknown {
		t.Fatalf("not hardened: floor %s, want none", got)
	}
	if got := isolationFloor(true, sandbox.IsolationUnknown); got != sandbox.IsolationKernel {
		t.Fatalf("hardened: floor %s, want kernel", got)
	}
	f := hardenedDockerFacts()
	for tier, ok := range map[sandbox.IsolationClass]bool{
		sandbox.IsolationVM: true, sandbox.IsolationKernel: true, sandbox.IsolationContainer: false,
		sandbox.IsolationProcess: false, sandbox.IsolationNone: false, sandbox.IsolationUnknown: false,
	} {
		f.Isolation = tier
		err := enforceHardenedPolicy(getenvFrom(hardenedEnv()), f)
		if (err == nil) != ok || ok != tier.Meets(isolationFloor(true, sandbox.IsolationUnknown)) {
			t.Errorf("tier %s: policy %v, meets the floor %t; want both to say %t", tier, err, tier.Meets(isolationFloor(true, sandbox.IsolationUnknown)), ok)
		}
	}
}

// The operator's SANDBOX_MIN_ISOLATION is a floor on every run too, not only a startup
// check, and the stronger of it and hardened mode's floor wins.
func TestIsolationFloorHoldsTheOperatorsMinimum(t *testing.T) {
	for _, c := range []struct {
		hardened   bool
		configured sandbox.IsolationClass
		want       sandbox.IsolationClass
	}{
		{false, sandbox.IsolationContainer, sandbox.IsolationContainer},
		{false, sandbox.IsolationVM, sandbox.IsolationVM},
		{true, sandbox.IsolationContainer, sandbox.IsolationKernel},
		{true, sandbox.IsolationVM, sandbox.IsolationVM},
	} {
		if got := isolationFloor(c.hardened, c.configured); got != c.want {
			t.Errorf("hardened %t, SANDBOX_MIN_ISOLATION %s: floor %s, want %s", c.hardened, c.configured, got, c.want)
		}
	}
}

// /readyz says not ready while the provider's tier is below the daemon's floor: every run
// would be refused, so a load balancer should stop sending them. With no floor, the tier
// does not decide readiness, as before.
func TestReadyzHoldsTheFloor(t *testing.T) {
	weak := &staleTierSandbox{stated: sandbox.IsolationContainer}
	for floor, want := range map[sandbox.IsolationClass]int{
		sandbox.IsolationUnknown: http.StatusOK, sandbox.IsolationContainer: http.StatusOK, sandbox.IsolationKernel: http.StatusServiceUnavailable,
	} {
		rec := httptest.NewRecorder()
		readyzHandler(weak, floor)(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		if rec.Code != want {
			t.Errorf("floor %s over a container tier: %d %q, want %d", floor, rec.Code, rec.Body.String(), want)
		}
	}
}

// The real main(), hardened, over a provider whose boundary falls from kernel to container
// after startup: a caller that sets no minimum is refused, not dispatched, for the isolation
// reason, on a snippet and on a project, and /readyz says not ready once the provider's
// evidence shows the drop. The same daemon not in hardened mode runs the snippet at
// container and stays ready, as before. Without the floor main() sets, the hardened daemon
// ran the snippet ("ran at container").
func TestHardenedDaemonHoldsItsFloorOnEveryRun(t *testing.T) {
	const token = "floor-0123456789abcdef0123456789abcdef"
	sum := sha256.Sum256([]byte(token))
	clients, err := json.Marshal(map[string]any{"clients": []map[string]any{
		{"id": "caller", "token_sha256": hex.EncodeToString(sum[:]), "scopes": []string{"code:run"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	clientsPath := filepath.Join(t.TempDir(), "clients.json")
	if err := os.WriteFile(clientsPath, clients, 0o600); err != nil {
		t.Fatal(err)
	}
	base := []string{"PLIMSOLLD_FLOOR_TEST_PROVIDER=1", "SANDBOX_PROVIDER=" + floorTestProvider, "SANDBOX_MEMORY_MB=256",
		"PLIMSOLL_ADDR=127.0.0.1:0", "PLIMSOLL_METRICS_ADDR=off", "PLIMSOLL_CLIENTS_FILE=" + clientsPath}
	run := func(d *daemon, payload *plimsollv1.RunRequest) (*plimsollv1.RunResponse, error) {
		payload.Protocol = protocol.Number
		req := connect.NewRequest(payload)
		req.Header().Set("Authorization", "Bearer "+token)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		resp, err := plimsollv1connect.NewSandboxServiceClient(http.DefaultClient, "http://"+d.addr).Run(ctx, req)
		if err != nil {
			return nil, err
		}
		return resp.Msg, nil
	}
	snippet := &plimsollv1.RunRequest{Payload: &plimsollv1.RunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: "1"}}}
	project := &plimsollv1.RunRequest{Payload: &plimsollv1.RunRequest_Project{Project: &plimsollv1.ProjectRun{
		Files: []*plimsollv1.ProjectFile{{Path: "a.js", Content: "1"}}, Steps: []string{"node a.js"}}}}
	isolationRefusal := func(err error) bool {
		var ce *connect.Error
		if !errors.As(err, &ce) || ce.Code() != connect.CodeFailedPrecondition {
			return false
		}
		for _, detail := range ce.Details() {
			if v, derr := detail.Value(); derr == nil {
				if nd, ok := v.(*plimsollv1.NotDispatched); ok {
					return nd.GetReason() == plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_ISOLATION
				}
			}
		}
		return false
	}
	ready := func(d *daemon) int {
		resp, err := http.Get("http://" + d.addr + "/readyz")
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	hard := startDaemon(t, append([]string{"PLIMSOLL_HARDENED=1"}, base...), 30*time.Second)
	if !strings.Contains(hard.logText(), "hardened mode: production policy verified and enforced") {
		t.Fatalf("the daemon did not start hardened:\n%s", hard.logText())
	}
	if code := ready(hard); code != http.StatusOK {
		t.Fatalf("readyz before the drop: %d", code)
	}
	for name, payload := range map[string]*plimsollv1.RunRequest{"snippet": snippet, "project": project} {
		resp, err := run(hard, payload)
		if !isolationRefusal(err) {
			t.Fatalf("hardened %s with no caller minimum: %v (stdout %q); want an isolation refusal, not dispatched",
				name, err, resp.GetJavascript().GetStdout())
		}
	}
	if code := ready(hard); code != http.StatusServiceUnavailable {
		t.Fatalf("readyz after the drop: %d; want not ready", code)
	}
	hard.stop(t, 30*time.Second)

	// Not hardened, with the operator's SANDBOX_MIN_ISOLATION=kernel: startup passes (the
	// provider proves kernel), and the minimum then holds every run as hardened mode's does.
	floored := startDaemon(t, append([]string{"SANDBOX_MIN_ISOLATION=kernel"}, base...), 30*time.Second)
	if resp, err := run(floored, snippet); !isolationRefusal(err) {
		t.Fatalf("SANDBOX_MIN_ISOLATION=kernel, a snippet with no caller minimum: %v (stdout %q); want an isolation refusal, not dispatched",
			err, resp.GetJavascript().GetStdout())
	}
	if code := ready(floored); code != http.StatusServiceUnavailable {
		t.Fatalf("SANDBOX_MIN_ISOLATION=kernel, readyz after the drop: %d; want not ready", code)
	}
	floored.stop(t, 30*time.Second)

	plain := startDaemon(t, base, 30*time.Second)
	resp, err := run(plain, snippet)
	if err != nil || string(resp.GetJavascript().GetStdout()) != "ran at container" {
		t.Fatalf("not hardened: %v, %q; want the run dispatched at container, as before", err, resp.GetJavascript().GetStdout())
	}
	if code := ready(plain); code != http.StatusOK {
		t.Fatalf("not hardened, readyz after the drop: %d; want ready, as before", code)
	}
	plain.stop(t, 30*time.Second)
}
