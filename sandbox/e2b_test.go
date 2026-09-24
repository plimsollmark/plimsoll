package sandbox

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"mime"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestE2BCreateDeniesAllEgress verifies every ungranted E2B VM is created secured
// and with deny-all egress.
func TestE2BCreateDeniesAllEgress(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"sandboxID":"sb-1","envdAccessToken":"envd-tok","trafficAccessToken":"traffic-tok"}`))
	}))
	defer srv.Close()
	e := &E2B{APIKey: "k", APIBase: srv.URL}

	vm, err := e.create(context.Background(), 30*time.Second)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if vm.accessToken != "envd-tok" {
		t.Errorf("accessToken = %q, want envd-tok", vm.accessToken)
	}
	if vm.trafficAccessToken != "traffic-tok" {
		t.Errorf("trafficAccessToken = %q, want traffic-tok", vm.trafficAccessToken)
	}
	var body map[string]any
	if err := json.Unmarshal(gotBody, &body); err != nil {
		t.Fatalf("parse create body: %v", err)
	}
	if secure, _ := body["secure"].(bool); !secure {
		t.Errorf("create body must request secured access (secure=true): %s", gotBody)
	}
	net, ok := body["network"].(map[string]any)
	if !ok {
		t.Fatalf("run missing network config in create body: %s", gotBody)
	}
	if deny, _ := net["denyOut"].([]any); len(deny) != 1 || deny[0] != "0.0.0.0/0" {
		t.Errorf("denyOut = %v, want [0.0.0.0/0]", net["denyOut"])
	}
	if _, hasAllow := net["allowOut"]; hasAllow {
		t.Errorf("run must not allow any outbound host: %s", gotBody)
	}
	if allowPublic, ok := net["allowPublicTraffic"].(bool); !ok || allowPublic {
		t.Errorf("allowPublicTraffic = %v, want false", net["allowPublicTraffic"])
	}
	if _, hasEnvs := body["envVars"]; hasEnvs {
		t.Errorf("untrusted VM must not receive host-API environment variables: %s", gotBody)
	}
}

func TestE2BCreateGrantUsesAllowlistAndBetaHeaderTransform(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"sandboxID":"sb-guard","envdAccessToken":"envd","trafficAccessToken":"traffic"}`))
	}))
	defer srv.Close()
	e := &E2B{APIKey: "k", APIBase: srv.URL}
	cfg := &e2bGuardConfig{
		Endpoint: &guardEndpoint{URL: "https://guard.example/v1/e2b/guard", Host: "guard.example", Path: "/v1/e2b/guard"},
		Token:    "crg_test-token",
	}
	if _, err := e.create(context.Background(), 30*time.Second, cfg); err != nil {
		t.Fatalf("create: %v", err)
	}
	var body struct {
		Network struct {
			DenyOut  []string `json:"denyOut"`
			AllowOut []string `json:"allowOut"`
			Rules    map[string][]struct {
				Transform struct {
					Headers map[string]string `json:"headers"`
				} `json:"transform"`
			} `json:"rules"`
		} `json:"network"`
	}
	if err := json.Unmarshal(gotBody, &body); err != nil {
		t.Fatalf("parse create body: %v", err)
	}
	if len(body.Network.DenyOut) != 1 || body.Network.DenyOut[0] != "0.0.0.0/0" {
		t.Fatalf("denyOut = %v, want deny-all", body.Network.DenyOut)
	}
	if len(body.Network.AllowOut) != 1 || body.Network.AllowOut[0] != "guard.example" {
		t.Fatalf("allowOut = %v, want only guard.example", body.Network.AllowOut)
	}
	rules := body.Network.Rules["guard.example"]
	if len(rules) != 1 || rules[0].Transform.Headers[EgressGuardHeader] != "crg_test-token" {
		t.Fatalf("rules = %+v, want one injected guard header", body.Network.Rules)
	}
}

func TestE2BGuardKeepsCustomerCredentialInBroker(t *testing.T) {
	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer upstream.Close()
	e := &E2B{APIKey: "k", GuardURL: "https://guard.example/v1/e2b/guard"}
	grant := &HostAPIGrant{BaseURL: upstream.URL, Allow: []HostRoute{{Method: "GET", Path: "/v1/items"}}, Minter: StaticToken("customer-secret")}
	cfg, cleanup, err := e.openGuard(context.Background(), grant, time.Minute)
	if err != nil {
		t.Fatalf("open guard: %v", err)
	}
	defer cleanup()
	if strings.Contains(hostGuardSDKModule(grant, cfg.Endpoint.URL, ""), "customer-secret") || strings.Contains(hostGuardSDKModule(grant, cfg.Endpoint.URL, ""), cfg.Token) {
		t.Fatal("E2B guest module contains a customer or guard credential")
	}
	resp := e.EgressGuardCall(context.Background(), cfg.Token, http.MethodGet, "/v1/items", nil)
	if resp.Status != http.StatusOK || string(resp.Body) != `{"ok":true}` {
		t.Fatalf("guard response = %+v, want upstream response", resp)
	}
	if gotAuth != "Bearer customer-secret" {
		t.Fatalf("upstream Authorization = %q, want broker-injected customer credential", gotAuth)
	}
	cleanup()
	if resp := e.EgressGuardCall(context.Background(), cfg.Token, http.MethodGet, "/v1/items", nil); resp.Status != http.StatusUnauthorized {
		t.Fatalf("expired guard status = %d, want 401", resp.Status)
	}
}

func TestParseE2BGuardURL(t *testing.T) {
	got, err := parseE2BGuardURL("https://Guard.Example")
	if err != nil || got.URL != "https://Guard.Example/v1/e2b/guard" || got.Host != "guard.example" {
		t.Fatalf("parsed guard = %+v, err=%v", got, err)
	}
	for _, raw := range []string{
		"http://guard.example/v1/e2b/guard",
		"https://localhost/v1/e2b/guard",
		"https://guard.example:8443/v1/e2b/guard",
		"https://guard.example/v1/e2b/guard?x=1",
		"https://guard.example/v1/../guard",
	} {
		if _, err := parseE2BGuardURL(raw); err == nil {
			t.Errorf("parseE2BGuardURL(%q) unexpectedly succeeded", raw)
		}
	}
}

func TestE2BRunProcessPropagatesDeadlineToEnvd(t *testing.T) {
	var timeoutHeader string
	var envdToken, trafficToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timeoutHeader = r.Header.Get("Connect-Timeout-Ms")
		envdToken = r.Header.Get("X-Access-Token")
		trafficToken = r.Header.Get("e2b-traffic-access-token")
		w.Header().Set("Content-Type", "application/connect+json")
		_, _ = w.Write(frame(0, []byte(`{"event":{"end":{"exitCode":0,"exited":true}}}`)))
		_, _ = w.Write(frame(0x2, []byte(`{}`)))
	}))
	defer srv.Close()
	e := &E2B{APIKey: "k", EnvdHost: func(string) string { return srv.URL }}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := e.runProcess(ctx, e2bVM{id: "sb", accessToken: "tok", trafficAccessToken: "traffic"}, "true", nil, ""); err != nil {
		t.Fatal(err)
	}
	ms, err := strconv.Atoi(timeoutHeader)
	if err != nil || ms < 1 || ms > 2000 {
		t.Fatalf("Connect-Timeout-Ms = %q, want 1..2000", timeoutHeader)
	}
	if envdToken != "tok" || trafficToken != "traffic" {
		t.Fatalf("envd auth headers = (%q, %q), want (tok, traffic)", envdToken, trafficToken)
	}
}

func TestE2BReadFileDistinguishesMissingFromInfrastructureFailure(t *testing.T) {
	status := http.StatusNotFound
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte("failure"))
	}))
	defer srv.Close()
	e := &E2B{EnvdHost: func(string) string { return srv.URL }}
	if _, found, err := e.readFile(context.Background(), e2bVM{id: "sb", accessToken: "tok"}, "/x"); err != nil || found {
		t.Fatalf("404: found=%v err=%v, want missing without error", found, err)
	}
	status = http.StatusInternalServerError
	if _, _, err := e.readFile(context.Background(), e2bVM{id: "sb", accessToken: "tok"}, "/x"); err == nil {
		t.Fatal("500 was silently treated as a missing artifact")
	}
}

func TestE2BUsesEarlierCallerDeadlineForVM(t *testing.T) {
	var createTimeout float64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/sandboxes" && r.Method == http.MethodPost:
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			createTimeout, _ = body["timeout"].(float64)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"sandboxID":"sb-1","envdAccessToken":"access","trafficAccessToken":"traffic"}`))
		case r.URL.Path == "/process.Process/Start":
			_, _ = w.Write(frame(0, []byte(`{"event":{"end":{"exitCode":0,"exited":true}}}`)))
			_, _ = w.Write(frame(0x2, []byte(`{}`)))
		case r.URL.Path == "/files" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusOK)
		case strings.HasPrefix(r.URL.Path, "/sandboxes/") && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "unexpected", http.StatusNotFound)
		}
	}))
	defer srv.Close()
	e := &E2B{APIKey: "k", APIBase: srv.URL, EnvdHost: func(string) string { return srv.URL }}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := e.RunJavaScript(ctx, Request{Code: "1", Timeout: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if createTimeout > 11 {
		t.Fatalf("VM timeout = %.0fs, want caller budget + 10s backstop", createTimeout)
	}
}

func TestE2BRejectsHostAPIGrantsWithoutGuardBeforeCreatingVM(t *testing.T) {
	created := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		created = true
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	e := &E2B{APIKey: "k", APIBase: srv.URL}
	grant := &HostAPIGrant{BaseURL: "https://host.internal"}
	if _, err := e.RunJavaScript(context.Background(), Request{Code: "1", Grant: grant}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("RunJavaScript err = %v, want ErrUnsupported", err)
	}
	if _, err := e.RunProject(context.Background(), ProjectRequest{Steps: []string{"true"}, Grant: grant}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("RunProject err = %v, want ErrUnsupported", err)
	}
	if created {
		t.Fatal("E2B created a VM for a rejected host-API grant")
	}
}

// TestE2BCreateFailsClosedWithoutEnvdToken verifies that a secure-mode create whose
// response carries no envd access token is treated as an error (and the sandbox is
// killed), never as a usable VM with an unauthenticated data plane.
func TestE2BCreateFailsClosedWithoutEnvdToken(t *testing.T) {
	killed := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			killed <- r.URL.Path
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"sandboxID":"sb-2"}`))
	}))
	defer srv.Close()
	e := &E2B{APIKey: "k", APIBase: srv.URL}

	if _, err := e.create(context.Background(), 30*time.Second); err == nil {
		t.Fatal("create without envdAccessToken must fail closed")
	}
	select {
	case path := <-killed:
		if path != "/sandboxes/sb-2" {
			t.Errorf("killed %q, want /sandboxes/sb-2", path)
		}
	case <-time.After(5 * time.Second):
		t.Error("token-less sandbox was not killed")
	}
}

func TestE2BCreateFailsClosedWithoutTrafficToken(t *testing.T) {
	killed := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			killed <- r.URL.Path
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"sandboxID":"sb-traffic","envdAccessToken":"envd"}`))
	}))
	defer srv.Close()
	e := &E2B{APIKey: "k", APIBase: srv.URL}

	if _, err := e.create(context.Background(), 30*time.Second); err == nil || !strings.Contains(err.Error(), "traffic access token") {
		t.Fatalf("err = %v, want a missing traffic-token failure", err)
	}
	select {
	case path := <-killed:
		if path != "/sandboxes/sb-traffic" {
			t.Errorf("killed %q, want /sandboxes/sb-traffic", path)
		}
	case <-time.After(5 * time.Second):
		t.Error("traffic-token-less sandbox was not killed")
	}
}

// TestE2BCreateNoSilentLeakOnUnparseableResponse verifies that a 2xx create whose
// body has no parseable sandbox ID fails with a clear error (and does not pretend a
// VM was created). There is nothing to reap because no ID was recovered — the point
// is that the failure is explicit, not a usable-looking zero VM.
func TestE2BCreateNoSilentLeakOnUnparseableResponse(t *testing.T) {
	var deletes int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deletes++
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`this is not json`))
	}))
	defer srv.Close()
	e := &E2B{APIKey: "k", APIBase: srv.URL}
	vm, err := e.create(context.Background(), 30*time.Second)
	if err == nil || !strings.Contains(err.Error(), "sandbox ID") {
		t.Fatalf("err = %v, want an explicit no-sandbox-ID error", err)
	}
	if vm.id != "" {
		t.Errorf("returned a non-empty vm on failure: %+v", vm)
	}
	if deletes != 0 {
		t.Errorf("attempted %d deletes for an unidentifiable sandbox; nothing to reap", deletes)
	}
}

// TestE2BStreamTransferBudget verifies the whole-stream transfer cap fires: a process
// that keeps emitting in-bound frames past maxStreamTransferBytes is aborted rather
// than read forever (a flood-DoS guard beyond the per-frame and per-output caps).
func TestE2BStreamTransferBudget(t *testing.T) {
	pr, pw := io.Pipe()
	go func() {
		// One big-but-legal frame just under the total budget, then another that
		// tips it over — the reader must reject before consuming without bound.
		big := make([]byte, maxConnectFrameBytes)
		for i := 0; i < (maxStreamTransferBytes/maxConnectFrameBytes)+2; i++ {
			if _, err := pw.Write(frame(0, big)); err != nil {
				return
			}
		}
		_ = pw.Close()
	}()
	err := readConnectStream(pr, func([]byte) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "transfer budget") {
		t.Fatalf("err = %v, want a transfer-budget rejection", err)
	}
}

// TestE2BVerifyResourcesFailsClosed verifies configured resource values are hard
// maximums, not minimum floors that accidentally authorize a larger hostile VM.
func TestE2BVerifyResourcesFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sandboxes/sb" || r.Header.Get("X-API-Key") != "k" {
			http.Error(w, "unexpected", http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"memoryMB":512,"cpuCount":2,"diskSizeMB":1024}`))
	}))
	defer srv.Close()

	e := &E2B{APIKey: "k", APIBase: srv.URL, MaxMemoryMB: 256}
	err := e.verifyResources(context.Background(), e2bVM{id: "sb"})
	if err == nil || !strings.Contains(err.Error(), "exceeds memory cap") {
		t.Fatalf("err = %v, want an over-cap failure", err)
	}

	// Every reported dimension at or below its maximum succeeds.
	e.MaxMemoryMB, e.MaxVCPU, e.MaxDiskMB = 512, 2, 1024
	if err := e.verifyResources(context.Background(), e2bVM{id: "sb"}); err != nil {
		t.Fatalf("resource caps met but verify failed: %v", err)
	}

	// No cap configured -> skipped entirely (no API call needed).
	e.MaxMemoryMB, e.MaxVCPU, e.MaxDiskMB = 0, 0, 0
	e.APIBase = "http://127.0.0.1:1"
	if err := e.verifyResources(context.Background(), e2bVM{id: "sb"}); err != nil {
		t.Fatalf("unconfigured verify should be a no-op, got %v", err)
	}
}

func TestE2BVerifyResourcesDistinguishesZeroFromMissingDisk(t *testing.T) {
	response := `{"memoryMB":512,"cpuCount":2,"diskSizeMB":0}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(response))
	}))
	defer srv.Close()

	e := &E2B{APIKey: "k", APIBase: srv.URL, MaxDiskMB: 1024}
	if err := e.verifyResources(context.Background(), e2bVM{id: "sb"}); err != nil {
		t.Fatalf("present zero-MiB disk allocation is within cap: %v", err)
	}
	response = `{"memoryMB":512,"cpuCount":2}`
	if err := e.verifyResources(context.Background(), e2bVM{id: "sb"}); err == nil || !strings.Contains(err.Error(), "omitted diskSizeMB") {
		t.Fatalf("missing diskSizeMB err = %v, want fail-closed presence error", err)
	}
}

func TestE2BRejectsUnsupportedResourceConfiguration(t *testing.T) {
	for _, e := range []*E2B{
		{MaxVCPU: 0.5},
		{PidsLimit: 64},
		{MaxVCPU: math.NaN()},
	} {
		if err := e.validateResourceConfig(); err == nil {
			t.Errorf("validateResourceConfig(%+v) succeeded, want rejection", e)
		}
	}
}

// e2bSmokeCalls records what the fake control-plane/envd server observed during a
// SmokeTest, so tests can assert the smoke exercised the real run mechanics.
type e2bSmokeCalls struct {
	stagedPaths []string
	procCmd     string
	procCwd     string
	procEnvs    map[string]string
	deleted     bool
}

// e2bSmokeFake serves the minimal control-plane + envd surface SmokeTest touches,
// scripting the probe's stdout report and exit code.
func e2bSmokeFake(t *testing.T, report string, exitCode int) (*httptest.Server, *e2bSmokeCalls) {
	t.Helper()
	calls := &e2bSmokeCalls{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/sandboxes" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"sandboxID":"sb-smoke","envdAccessToken":"envd","trafficAccessToken":"traffic"}`))
		case strings.HasPrefix(r.URL.Path, "/sandboxes/") && r.Method == http.MethodDelete:
			calls.deleted = true
			w.WriteHeader(http.StatusOK)
		case r.URL.Path == "/files" && r.Method == http.MethodPost:
			mr, err := r.MultipartReader()
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			for {
				part, err := mr.NextPart()
				if err != nil {
					break
				}
				// Part.FileName() strips directories; envd routes by the RAW filename
				// param, so read it from the header like the real server does.
				_, params, _ := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
				calls.stagedPaths = append(calls.stagedPaths, params["filename"])
			}
			w.WriteHeader(http.StatusOK)
		case r.URL.Path == "/process.Process/Start":
			raw, _ := io.ReadAll(r.Body)
			var start struct {
				Process struct {
					Cmd  string            `json:"cmd"`
					Cwd  string            `json:"cwd"`
					Envs map[string]string `json:"envs"`
				} `json:"process"`
			}
			if len(raw) > 5 {
				_ = json.Unmarshal(raw[5:], &start) // strip the connect envelope header
			}
			calls.procCmd, calls.procCwd, calls.procEnvs = start.Process.Cmd, start.Process.Cwd, start.Process.Envs
			w.Header().Set("Content-Type", "application/connect+json")
			stdout := base64.StdEncoding.EncodeToString([]byte(report))
			_, _ = w.Write(frame(0, []byte(`{"event":{"data":{"stdout":"`+stdout+`"}}}`)))
			_, _ = w.Write(frame(0, []byte(`{"event":{"end":{"exitCode":`+strconv.Itoa(exitCode)+`,"exited":true}}}`)))
			_, _ = w.Write(frame(0x2, []byte(`{}`)))
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, calls
}

// TestE2BSmokeTestVerifiesTemplateEndToEnd proves the startup smoke drives the
// exact project-run mechanics: multi-file staging into the project dir, a probe
// launched via `sh <script>` with the project cwd, and teardown afterwards.
func TestE2BSmokeTestVerifiesTemplateEndToEnd(t *testing.T) {
	srv, calls := e2bSmokeFake(t, `{"node":"v22.0.0","cwd":"/home/user/project","egressOpen":[]}`, 0)
	e := &E2B{APIKey: "k", APIBase: srv.URL, EnvdHost: func(string) string { return srv.URL }}
	if err := e.SmokeTest(context.Background()); err != nil {
		t.Fatalf("SmokeTest: %v", err)
	}
	wantStaged := []string{"/home/user/project/plimsoll-smoke.cjs", "/tmp/plimsoll-smoke-step.sh"}
	for _, want := range wantStaged {
		found := false
		for _, got := range calls.stagedPaths {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Errorf("smoke did not stage %q (staged: %v)", want, calls.stagedPaths)
		}
	}
	if calls.procCmd != "sh" || calls.procCwd != "/home/user/project" {
		t.Errorf("probe ran as (%q, cwd %q), want the project-step path (sh, /home/user/project)", calls.procCmd, calls.procCwd)
	}
	if !calls.deleted {
		t.Error("smoke did not tear down its throwaway sandbox")
	}
}

// TestE2BSmokeTestFailsClosed verifies each behavioral check actually gates
// startup: open egress, a missing toolchain (exit 127), an unparseable report,
// and a dishonored working directory must all be errors, and the throwaway
// sandbox must be reaped even on failure.
func TestE2BSmokeTestFailsClosed(t *testing.T) {
	cases := []struct {
		name     string
		report   string
		exitCode int
		wantErr  string
	}{
		{"egress open", `{"node":"v22.0.0","cwd":"/home/user/project","egressOpen":["https://1.1.1.1"]}`, 0, "egress is OPEN"},
		{"missing toolchain", ``, 127, "exited 127"},
		{"garbage report", `not json`, 0, "unparseable probe report"},
		{"wrong cwd", `{"node":"v22.0.0","cwd":"/","egressOpen":[]}`, 0, "project dir"},
		{"no node version", `{"node":"","cwd":"/home/user/project","egressOpen":[]}`, 0, "no node version"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, calls := e2bSmokeFake(t, tc.report, tc.exitCode)
			e := &E2B{APIKey: "k", APIBase: srv.URL, EnvdHost: func(string) string { return srv.URL }}
			err := e.SmokeTest(context.Background())
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
			if !calls.deleted {
				t.Error("failed smoke leaked its throwaway sandbox")
			}
		})
	}
}

// TestE2BGuardedRunTrustsProxyCA verifies that a guarded E2B run points Node at
// the guest OS trust store (NODE_EXTRA_CA_CERTS) so brokered guard calls verify
// the E2B proxy CA rather than failing with UNABLE_TO_VERIFY_LEAF_SIGNATURE, while
// an ungranted run (no guard, no proxy TLS) does not. Regression guard for the E2B
// live-proof blocker resolved via the guest OS trust store.
func TestE2BGuardedRunTrustsProxyCA(t *testing.T) {
	newE2B := func(srv *httptest.Server) *E2B {
		return &E2B{
			APIKey:         "k",
			APIBase:        srv.URL,
			GuardURL:       "https://guard.example/v1/e2b/guard",
			EnvdHost:       func(string) string { return srv.URL },
			DefaultTimeout: 30 * time.Second,
			MaxTimeout:     30 * time.Second,
		}
	}
	grant := &HostAPIGrant{
		BaseURL: "https://api.example",
		Allow:   []HostRoute{{Method: http.MethodGet, Path: "/v1/items"}},
		Minter:  StaticToken("customer-secret"),
	}

	t.Run("snippet with grant sets the CA bundle", func(t *testing.T) {
		srv, calls := e2bSmokeFake(t, "", 0)
		if _, err := newE2B(srv).RunJavaScript(context.Background(), Request{Code: "1", Grant: grant}); err != nil {
			t.Fatalf("RunJavaScript: %v", err)
		}
		if got := calls.procEnvs["NODE_EXTRA_CA_CERTS"]; got != e2bGuestCABundle {
			t.Fatalf("NODE_EXTRA_CA_CERTS = %q, want %q", got, e2bGuestCABundle)
		}
	})

	t.Run("snippet without grant leaves the CA bundle unset", func(t *testing.T) {
		srv, calls := e2bSmokeFake(t, "", 0)
		if _, err := newE2B(srv).RunJavaScript(context.Background(), Request{Code: "1"}); err != nil {
			t.Fatalf("RunJavaScript: %v", err)
		}
		if got, ok := calls.procEnvs["NODE_EXTRA_CA_CERTS"]; ok {
			t.Fatalf("ungranted run set NODE_EXTRA_CA_CERTS = %q, want unset", got)
		}
	})

	t.Run("project step with grant sets CA bundle alongside NODE_OPTIONS", func(t *testing.T) {
		srv, calls := e2bSmokeFake(t, "", 0)
		_, err := newE2B(srv).RunProject(context.Background(), ProjectRequest{
			Files: []File{{Path: "index.mjs", Content: "1"}},
			Steps: []string{"node index.mjs"},
			Grant: grant,
		})
		if err != nil {
			t.Fatalf("RunProject: %v", err)
		}
		if got := calls.procEnvs["NODE_EXTRA_CA_CERTS"]; got != e2bGuestCABundle {
			t.Fatalf("NODE_EXTRA_CA_CERTS = %q, want %q", got, e2bGuestCABundle)
		}
		if got := calls.procEnvs["NODE_OPTIONS"]; got != "--import /tmp/plimsoll-e2b-host.mjs" {
			t.Fatalf("NODE_OPTIONS = %q, want the host-SDK preload", got)
		}
	})
}

// TestHostNetPreambleBakesAllowlist verifies the Docker-side injected client
// carries a defense-in-depth gate in addition to the authoritative host broker.
func TestHostNetPreambleBakesAllowlist(t *testing.T) {
	grant := &HostAPIGrant{
		BaseURL: "https://hue.internal",
		Allow:   []HostRoute{{http.MethodGet, "/v1/lights"}, {http.MethodPut, "/v1/lights/*/on"}},
	}
	out := withHostSDK("console.log(1)", grant)
	for _, want := range []string{`"m":"GET"`, `"p":"/v1/lights"`, `"p":"/v1/lights/*/on"`, "__allowed", "not permitted by sandbox capability"} {
		if !strings.Contains(out, want) {
			t.Errorf("injected client missing %q", want)
		}
	}
	// An empty allowlist bakes to "[]" (reaches nothing), never an unset placeholder.
	empty := withHostSDK("x", &HostAPIGrant{BaseURL: "https://h.internal"})
	if !strings.Contains(empty, "const __allow = [];") {
		t.Errorf("empty allow should bake to []: %s", empty)
	}
	if strings.Contains(out, "__ALLOW_JSON__") || strings.Contains(empty, "__ALLOW_JSON__") {
		t.Error("placeholder __ALLOW_JSON__ was not substituted")
	}
}
