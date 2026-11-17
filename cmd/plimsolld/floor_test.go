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
	"github.com/plimsollmark/plimsoll/sandbox/agentsandbox"
	"github.com/plimsollmark/plimsoll/sandbox/openshell"
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

// The startup-order test's two providers, registered beside floor-test. Each writes a line
// to the file PLIMSOLLD_STARTUP_RECORD names when one of its startup checks runs
// ("preflight", then "smoke"), so the test sees from outside the child daemon whether they
// ran. floor-test-config reports container from its configuration, as the wslc per-run
// mode does by default; floor-test-checks reports container until its Preflight proves
// kernel, as docker under runsc does, and its descriptor says so (tierFromChecks).
const (
	floorTestConfigProvider = "floor-test-config"
	floorTestChecksProvider = "floor-test-checks"
)

type startupRecorder struct {
	staleTierSandbox
	name, record string
	proves       sandbox.IsolationClass // the tier Preflight sets; unknown leaves the configured one
}

func (r *startupRecorder) Name() string { return r.name }

func (r *startupRecorder) note(step string) error {
	f, err := os.OpenFile(r.record, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(step + "\n")
	return err
}

func (r *startupRecorder) Preflight(context.Context) error {
	if r.proves != sandbox.IsolationUnknown {
		r.mu.Lock()
		r.stated = r.proves
		r.mu.Unlock()
	}
	return r.note("preflight")
}

func (r *startupRecorder) SmokeTest(context.Context) error { return r.note("smoke") }

func registerFloorTestProviders() {
	register := func(build func(getenv func(string) string) sandbox.Sandbox, name string, fromChecks func(sandbox.Sandbox) bool) {
		providers[name] = providerDescriptor{
			build: func(getenv func(string) string) (sandbox.Provider, error) {
				res, err := sandbox.ResourcesFromEnv(getenv)
				return sandbox.Provider{Sandbox: build(getenv), Resources: res}, err
			},
			usage:            "\n  SANDBOX_PROVIDER=" + name + " a provider the floor tests register in their child daemon\n",
			hardenedEnvelope: []string{"SANDBOX_MEMORY_MB"},
			hardened:         func(func(string) string, func(string, ...any), func(error)) {},
			tierFromChecks:   fromChecks,
		}
	}
	register(func(func(string) string) sandbox.Sandbox {
		return &staleTierSandbox{stated: sandbox.IsolationKernel}
	}, floorTestProvider, nil)
	register(func(getenv func(string) string) sandbox.Sandbox {
		return &startupRecorder{staleTierSandbox: staleTierSandbox{stated: sandbox.IsolationContainer},
			name: floorTestConfigProvider, record: getenv("PLIMSOLLD_STARTUP_RECORD")}
	}, floorTestConfigProvider, nil)
	register(func(getenv func(string) string) sandbox.Sandbox {
		return &startupRecorder{staleTierSandbox: staleTierSandbox{stated: sandbox.IsolationContainer},
			name: floorTestChecksProvider, record: getenv("PLIMSOLLD_STARTUP_RECORD"), proves: sandbox.IsolationKernel}
	}, floorTestChecksProvider, func(sandbox.Sandbox) bool { return true })
}

// The real main(): SANDBOX_MIN_ISOLATION above a tier the configuration fixes ends startup
// before the provider's Preflight or smoke test runs (finding wslc-29: the wslc per-run
// mode's smoke test boots two Hyper-V VMs), with the same error and exit status as before.
// A provider whose checks establish its tier is held to the floor after them instead: it
// starts when they prove enough, and is refused, after them, when they do not. With the
// check after the smoke test only, as before, the first case found both checks run.
func TestOperatorFloorRefusesBeforeStartupChecks(t *testing.T) {
	base := []string{"PLIMSOLLD_FLOOR_TEST_PROVIDER=1", "SANDBOX_MEMORY_MB=256", "PLIMSOLL_TOKEN=" + strings.Repeat("t", 32),
		"PLIMSOLL_ADDR=127.0.0.1:0", "PLIMSOLL_METRICS_ADDR=off"}
	env := func(record, provider, floor string) []string {
		return append([]string{"PLIMSOLLD_STARTUP_RECORD=" + record, "SANDBOX_PROVIDER=" + provider, "SANDBOX_MIN_ISOLATION=" + floor}, base...)
	}
	ran := func(record string) string {
		b, err := os.ReadFile(record)
		if errors.Is(err, os.ErrNotExist) {
			return ""
		}
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(strings.Fields(string(b)), ",")
	}
	const refused = "provider does not meet the required isolation tier"
	for _, c := range []struct {
		provider, floor string
		started         bool
		checks          string // the startup checks that ran, in order
	}{
		{floorTestConfigProvider, "vm", false, ""},
		{floorTestConfigProvider, "kernel", false, ""},
		{floorTestConfigProvider, "container", true, "preflight,smoke"},
		{floorTestChecksProvider, "kernel", true, "preflight,smoke"},
		{floorTestChecksProvider, "vm", false, "preflight,smoke"},
	} {
		t.Run(c.provider+"/"+c.floor, func(t *testing.T) {
			record := filepath.Join(t.TempDir(), "record")
			if c.started {
				d := startDaemon(t, env(record, c.provider, c.floor), 30*time.Second)
				d.stop(t, 30*time.Second)
				// readyz is never polled here, so the checks ran once, at startup.
				if got := ran(record); got != c.checks {
					t.Fatalf("startup checks %q, want %q; log:\n%s", got, c.checks, d.logText())
				}
				return
			}
			code, log := exitDaemon(t, env(record, c.provider, c.floor), 30*time.Second)
			if code != 1 || !strings.Contains(log, refused) || !strings.Contains(log, "below SANDBOX_MIN_ISOLATION="+c.floor) {
				t.Fatalf("exit %d, want 1 with %q; log:\n%s", code, refused, log)
			}
			if got := ran(record); got != c.checks {
				t.Fatalf("startup checks %q before the floor refused the provider, want %q; log:\n%s", got, c.checks, log)
			}
		})
	}
}

// Which providers' tiers are known from configuration alone, as built from their settings:
// docker under runc and the wslc per-run mode are, docker under runsc is not (Preflight
// proves kernel), and the two providers whose first check reads the tier say so.
func TestTierKnownBeforeChecks(t *testing.T) {
	for _, c := range []struct {
		env   map[string]string
		known bool
	}{
		{map[string]string{"SANDBOX_PROVIDER": "docker"}, true},
		{map[string]string{"SANDBOX_PROVIDER": "docker", "SANDBOX_DOCKER_RUNTIME": "runsc"}, false},
		{map[string]string{"SANDBOX_PROVIDER": "wslc", "SANDBOX_WSLC_IMAGE": "plimsoll/sandbox:latest"}, true},
		{map[string]string{"SANDBOX_PROVIDER": "wslc", "SANDBOX_WSLC_IMAGE": "plimsoll/sandbox:latest", "SANDBOX_WSLC_ACCEPT_VM_TIER": "1"}, true},
		{map[string]string{"SANDBOX_PROVIDER": "wasm"}, true},
		{map[string]string{}, true}, // disabled
	} {
		p, err := buildProvider(getenvFrom(c.env))
		if err != nil {
			t.Fatalf("%v: %v", c.env, err)
		}
		if got := tierKnownBeforeChecks(p.Sandbox); got != c.known {
			t.Errorf("%v: tier known before the checks %t, want %t", c.env, got, c.known)
		}
	}
	for _, name := range []string{agentsandbox.Name, openshell.Name} {
		if f := providers[name].tierFromChecks; f == nil || !f(nil) {
			t.Errorf("%s: its tier is unknown until its first check, but its descriptor does not say the checks establish it", name)
		}
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
