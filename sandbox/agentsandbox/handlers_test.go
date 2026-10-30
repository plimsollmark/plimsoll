package agentsandbox

import (
	"context"
	"encoding/pem"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/plimsollmark/plimsoll/sandbox"
)

const declaredHandler = "runsc-receipt"

func declare(names ...string) func(*Config) {
	return func(c *Config) { c.RunscHandlers = names }
}

// A malformed declaration is refused by New, which contacts nothing, so no API call is
// made: an empty entry, a name that is not a DNS label, a name given twice, and every
// name the built-in table maps (runsc itself, and runc and the Kata handlers, which must
// never be read as gVisor).
func TestDeclaredHandlersAreCheckedBeforeAnyAPICall(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusTeapot)
	}))
	t.Cleanup(srv.Close)
	ca := caFileOf(t, srv)
	cases := []struct {
		names []string
		want  string
	}{
		{[]string{""}, "an empty entry"},
		{[]string{declaredHandler, ""}, "an empty entry"},
		{[]string{"Runsc-Receipt"}, "not a DNS label"},
		{[]string{"runsc_receipt"}, "not a DNS label"},
		{[]string{"runsc.receipt"}, "not a DNS label"},
		{[]string{"-runsc"}, "not a DNS label"},
		{[]string{"runsc-"}, "not a DNS label"},
		{[]string{"runsc receipt"}, "not a DNS label"},
		{[]string{strings.Repeat("a", 64)}, "not a DNS label"},
		{[]string{declaredHandler, declaredHandler}, "named twice"},
	}
	for name, tier := range handlerTiers {
		cases = append(cases, struct {
			names []string
			want  string
		}{[]string{declaredHandler, name}, "already knows (the " + tier.String() + " tier)"})
	}
	for _, c := range cases {
		cfg := Config{APIServer: srv.URL, CAFile: ca, TokenFile: "token", Namespace: "default", WarmPool: "pool",
			RuntimeClass: "gvisor", Image: fakeImage, SandboxdToken: fakeToken, RunscHandlers: c.names}
		if _, err := New(cfg); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("RunscHandlers %q: %v; want %q", c.names, err, c.want)
		}
	}
	if n := calls.Load(); n != 0 {
		t.Fatalf("%d API calls while refusing declarations", n)
	}
	if _, err := New(Config{APIServer: srv.URL, CAFile: ca, TokenFile: "token", Namespace: "default", WarmPool: "pool",
		RuntimeClass: "gvisor", Image: fakeImage, SandboxdToken: fakeToken, RunscHandlers: []string{declaredHandler, strings.Repeat("a", 63)}}); err != nil {
		t.Fatalf("a valid declaration: %v", err)
	}
}

// The variable is a comma list: unset or blank declares nothing, entries are trimmed, and
// an empty entry or any refusal above stops the build, naming the variable.
func TestDeclaredHandlersFromEnv(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	ca := caFileOf(t, srv)
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "sandboxd.token")
	if err := os.WriteFile(tokenFile, []byte(fakeToken), 0o600); err != nil {
		t.Fatal(err)
	}
	env := func(list string) func(string) string {
		m := map[string]string{
			"SANDBOX_AGENTSANDBOX_API_SERVER": "https://127.0.0.1:6443", "SANDBOX_AGENTSANDBOX_CA_FILE": ca, "SANDBOX_AGENTSANDBOX_TOKEN_FILE": "token",
			"SANDBOX_AGENTSANDBOX_NAMESPACE": "default", "SANDBOX_AGENTSANDBOX_WARM_POOL": "pool", "SANDBOX_AGENTSANDBOX_RUNTIME_CLASS": "gvisor",
			"SANDBOX_AGENTSANDBOX_IMAGE": fakeImage, "SANDBOX_AGENTSANDBOX_SANDBOXD_TOKEN_FILE": tokenFile,
			"SANDBOX_AGENTSANDBOX_RUNSC_HANDLERS": list,
		}
		return func(k string) string { return m[k] }
	}
	for list, want := range map[string][]string{
		"":                                   nil,
		"  ":                                 nil,
		declaredHandler:                      {declaredHandler},
		" runsc-receipt , runsc-debug ":      {declaredHandler, "runsc-debug"},
		"runsc-receipt,runsc-debug,runsc-x9": {declaredHandler, "runsc-debug", "runsc-x9"},
	} {
		built, err := FromEnv(env(list))
		if err != nil {
			t.Fatalf("%q: %v", list, err)
		}
		p := built.Sandbox.(*Provider)
		if got := p.cfg.RunscHandlers; !equalNames(got, want) {
			t.Fatalf("%q: declared %q, want %q", list, got, want)
		}
		for _, name := range want {
			if p.handlers[name] != sandbox.IsolationKernel {
				t.Fatalf("%q: %s claims %s, want kernel", list, name, p.handlers[name])
			}
		}
	}
	for list, want := range map[string]string{
		"runsc-receipt,":               "an empty entry",
		"runsc-receipt,,x":             "an empty entry",
		",runsc-receipt":               "an empty entry",
		"runsc-receipt,runc":           "already knows (the container tier)",
		"runsc":                        "already knows (the kernel tier)",
		"kata-clh,runsc-receipt":       "already knows (the vm tier)",
		"RUNSC":                        "not a DNS label",
		"runsc-receipt, runsc-receipt": "named twice",
	} {
		_, err := FromEnv(env(list))
		if err == nil || !strings.Contains(err.Error(), "SANDBOX_AGENTSANDBOX_RUNSC_HANDLERS") || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v; want a refusal naming the variable and %q", list, err, want)
		}
	}
}

// caFileOf writes srv's certificate as a CA file, which New reads.
func caFileOf(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func equalNames(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// A declared handler is the kernel tier: Preflight reports it, the smoke test passes on
// gVisor's answers, and a snippet and a project run at kernel. Without the declaration
// the same class is refused as an untested handler.
func TestADeclaredHandlerIsTheKernelTier(t *testing.T) {
	p, api, sd := testProviderWith(t, declare(declaredHandler))
	api.handler = declaredHandler
	if err := p.Preflight(context.Background()); err != nil || p.IsolationClass() != sandbox.IsolationKernel {
		t.Fatalf("declared: %v, %s", err, p.IsolationClass())
	}
	fakeSmoke(t, p, sd, nil)
	if err := p.SmokeTest(context.Background()); err != nil {
		t.Fatalf("smoke on a declared gVisor handler: %v", err)
	}
	drained(t, p)
	if res, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1", MinimumIsolation: sandbox.IsolationKernel}); err != nil || res.Isolation != sandbox.IsolationKernel {
		t.Fatalf("a snippet: %+v, %v", res, err)
	}
	res, err := p.RunProject(context.Background(), sandbox.ProjectRequest{Files: []sandbox.File{{Path: "a.js", Content: "1"}}, Steps: []string{"node a.js"}, MinimumIsolation: sandbox.IsolationKernel})
	if err != nil || res.Isolation != sandbox.IsolationKernel || res.Outcome != sandbox.ProjectOutcomeCompleted {
		t.Fatalf("a project: %+v, %v", res, err)
	}
	drained(t, p)

	undeclared, api2, _ := testProvider(t)
	api2.handler = declaredHandler
	if err := undeclared.Preflight(context.Background()); err == nil || !strings.Contains(err.Error(), "has not tested") || undeclared.IsolationClass() != sandbox.IsolationUnknown {
		t.Fatalf("undeclared: %v, %s", err, undeclared.IsolationClass())
	}
}

// A declared handler whose pod shows another kernel is refused before any of the run's
// code, for a snippet and a project, as runsc is: the host's kernel (the handler mapped to
// runc), no readable kernel log, and a Kata VM's Linux boot line.
func TestADeclaredHandlerOnAnotherKernelIsRefused(t *testing.T) {
	for _, c := range []struct{ name, answer string }{
		{"the host's kernel", "kernel [    0.000000] Linux version 6.6.87.2\nboot " + fakeBoot + "\nSeccomp:\t2\n"},
		{"no kernel log, as under runc", "kernel \nboot " + fakeBoot + "\nSeccomp:\t2\n"},
		{"a Kata VM", "kernel " + kataBoot + "\nboot " + fakeBoot + "\nSeccomp:\t0\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			p, api, sd := testProviderWith(t, declare(declaredHandler))
			api.handler = declaredHandler
			sd.tierAnswer = c.answer
			_, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"})
			if refusal(err) != sandbox.RefusalEnvironment || !strings.Contains(err.Error(), "not gVisor's") || len(sd.starts) != 0 {
				t.Fatalf("a snippet: %v; %d starts", err, len(sd.starts))
			}
			_, err = p.RunProject(context.Background(), sandbox.ProjectRequest{Files: []sandbox.File{{Path: "a.js", Content: "1"}}, Steps: []string{"node a.js"}})
			if refusal(err) != sandbox.RefusalEnvironment || !strings.Contains(err.Error(), "not gVisor's") || len(sd.starts) != 0 {
				t.Fatalf("a project: %v; %d starts", err, len(sd.starts))
			}
			drained(t, p)
		})
	}
}

// Startup fails when a declared handler's pods are not gVisor: the smoke test claims pods
// through the run path, and each is held to gVisor's boot line, so nothing is proven.
func TestStartupFailsOnADeclaredHandlerThatIsNotGVisor(t *testing.T) {
	p, api, sd := testProviderWith(t, declare(declaredHandler))
	api.handler = declaredHandler
	fakeSmoke(t, p, sd, func(r *boundaryReport) { r.Dmesg = "[    0.000000] Linux version 6.6.87.2" })
	sd.tierAnswer = "kernel [    0.000000] Linux version 6.6.87.2\nboot " + fakeBoot + "\nSeccomp:\t2\n"
	if err := p.SmokeTest(context.Background()); err == nil || !strings.Contains(err.Error(), "not gVisor's") {
		t.Fatalf("smoke on a declared handler that runs another kernel: %v", err)
	}
	drained(t, p)
	p.mu.Lock()
	proven := p.proven
	p.mu.Unlock()
	if proven != "" || len(sd.starts) != 0 {
		t.Fatalf("proven %q, %d commands sent; want nothing proven and nothing sent", proven, len(sd.starts))
	}
}

// After a smoke test on a declared handler, a substitution is refused before code: a node
// that remaps the handler to another runtime (its pods' kernel is no longer gVisor's), and
// a runtime class replaced with one whose handler is runc.
func TestADeclaredHandlerSubstitutedAfterStartupIsRefused(t *testing.T) {
	p, api, sd := testProviderWith(t, declare(declaredHandler))
	api.handler = declaredHandler
	runtimeDefault(api)
	fakeSmoke(t, p, sd, nil)
	if err := p.SmokeTest(context.Background()); err != nil {
		t.Fatal(err)
	}
	drained(t, p)
	sd.mu.Lock()
	before := len(sd.starts)
	gvisor := sd.tierAnswer
	sd.tierAnswer = "kernel \nboot " + fakeBoot + "\nSeccomp:\t2\n"
	sd.mu.Unlock()
	for name, run := range map[string]func() error{
		"snippet": func() error {
			_, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"})
			return err
		},
		"project": func() error {
			_, err := p.RunProject(context.Background(), sandbox.ProjectRequest{Files: []sandbox.File{{Path: "a.js", Content: "1"}}, Steps: []string{"node a.js"}})
			return err
		},
	} {
		if err := run(); refusal(err) != sandbox.RefusalEnvironment || !strings.Contains(err.Error(), "not gVisor's") {
			t.Fatalf("a %s on a remapped node: %v", name, err)
		}
	}
	drained(t, p)
	sd.mu.Lock()
	sd.tierAnswer = gvisor
	after := len(sd.starts)
	sd.mu.Unlock()
	if after != before {
		t.Fatalf("%d commands sent to pods on a remapped node", after-before)
	}
	api.mu.Lock()
	api.classUID, api.handler = "replacement-uid", "runc"
	api.mu.Unlock()
	if _, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"}); refusal(err) != sandbox.RefusalEnvironment || !strings.Contains(err.Error(), "runtime class gvisor changed") {
		t.Fatalf("a run on a class replaced with runc: %v", err)
	}
	drained(t, p)
}

// Declarations are each provider's own: one provider's declared handler is unknown to
// another built without it, the package's table is untouched, and editing the slice a
// provider was built from changes nothing.
func TestProvidersDoNotShareDeclaredHandlers(t *testing.T) {
	builtIn := maps.Clone(handlerTiers)
	names := []string{declaredHandler}
	a, apiA, _ := testProviderWith(t, declare(names...))
	b, apiB, _ := testProvider(t)
	apiA.handler, apiB.handler = declaredHandler, declaredHandler
	names[0] = "edited-after-new"
	if err := a.Preflight(context.Background()); err != nil || a.IsolationClass() != sandbox.IsolationKernel {
		t.Fatalf("the declaring provider: %v, %s", err, a.IsolationClass())
	}
	if err := b.Preflight(context.Background()); err == nil || !strings.Contains(err.Error(), "has not tested") {
		t.Fatalf("the other provider accepted a handler it never declared: %v", err)
	}
	if _, ok := a.handlers["edited-after-new"]; ok || a.cfg.RunscHandlers[0] != declaredHandler {
		t.Fatalf("an edit to the caller's slice reached the provider: %q", a.cfg.RunscHandlers)
	}
	if !maps.Equal(handlerTiers, builtIn) {
		t.Fatalf("the package's table changed: %v", handlerTiers)
	}
}
