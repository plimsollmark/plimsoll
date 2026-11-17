package wslc

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// The per-run mode reports container unless the operator sets SANDBOX_WSLC_ACCEPT_VM_TIER=1
// (finding wslc-23: before, it reported vm and every vm floor admitted it, while Microsoft
// states that WSL is not a security sandbox for running untrusted code). Every floor, a
// request's, the daemon's and a router's, compares against IsolationClass, so these tests
// pin that one value and the refusal it gives.

// microsoftStatement is the sentence every wslc qualification carries.
const microsoftStatement = "Microsoft states that WSL is not a security sandbox for running untrusted code"

func TestPerRunTierIsContainerUnlessAccepted(t *testing.T) {
	for _, c := range []struct {
		name   string
		cfg    Config
		tier   sandbox.IsolationClass
		phrase string
	}{
		{"per-run by default", Config{}, sandbox.IsolationContainer, PerRunQualification},
		{"per-run named", Config{Mode: ModePerRun}, sandbox.IsolationContainer, PerRunQualification},
		{"per-run accepted", Config{Mode: ModePerRun, AcceptVMTier: true}, sandbox.IsolationVM, PerRunAcceptedQualification},
		{"shared", Config{Mode: ModeShared}, sandbox.IsolationContainer, SharedQualification},
	} {
		c.cfg.Image = "plimsoll/sandbox:latest"
		p, err := New(c.cfg)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if p.IsolationClass() != c.tier || p.Qualification() != c.phrase {
			t.Errorf("%s: tier %s, qualification %q; want %s, %q", c.name, p.IsolationClass(), p.Qualification(), c.tier, c.phrase)
		}
	}
}

// isolationRefusal fails unless err is a refusal that ran nothing, for the isolation
// reason, wrapping ErrInsufficientIsolation.
func isolationRefusal(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, sandbox.ErrInsufficientIsolation) {
		t.Fatalf("%s: %v, want ErrInsufficientIsolation", what, err)
	}
	var nd *sandbox.NotDispatchedError
	if !errors.As(err, &nd) || nd.Reason != sandbox.RefusalIsolation {
		t.Fatalf("%s: %v is not marked not dispatched for the isolation reason", what, err)
	}
}

// floorRequests are a snippet and a project, each with the floor given.
func floorRequests(floor sandbox.IsolationClass) (sandbox.Request, sandbox.ProjectRequest) {
	return sandbox.Request{Code: "1", MinimumIsolation: floor},
		sandbox.ProjectRequest{Files: []sandbox.File{{Path: "a.js", Content: "1"}}, Steps: []string{"node a.js"}, MinimumIsolation: floor}
}

// refusedWithNothingStarted runs a snippet and a project with the floor on p and requires
// each to be refused for the isolation reason, naming the setting, with no call made to the
// stand-in at all: no session, no holder, no template copy, no container.
func refusedWithNothingStarted(t *testing.T, p *Provider, f *fake, floor sandbox.IsolationClass) {
	t.Helper()
	snippet, project := floorRequests(floor)
	res, err := p.RunJavaScript(context.Background(), snippet)
	isolationRefusal(t, "snippet at "+floor.String(), err)
	if res.Isolation != sandbox.IsolationContainer {
		t.Fatalf("a refused snippet states tier %s", res.Isolation)
	}
	pr, err := p.RunProject(context.Background(), project)
	isolationRefusal(t, "project at "+floor.String(), err)
	if pr.Isolation != sandbox.IsolationContainer {
		t.Fatalf("a refused project states tier %s", pr.Isolation)
	}
	if !strings.Contains(err.Error(), "SANDBOX_WSLC_ACCEPT_VM_TIER=1") {
		t.Fatalf("the refusal does not name the setting: %v", err)
	}
	p.drain()
	if calls := f.calls(); len(calls) != 0 {
		t.Fatalf("a refused run reached the stand-in %d times, first %s %v", len(calls), calls[0].Prog, calls[0].Argv)
	}
	if st := f.state(); len(st.Sessions) != 0 {
		t.Fatalf("a refused run left sessions: %v", st.Sessions)
	}
}

func TestVMFloorRefusedBeforeAnyContainer(t *testing.T) {
	p, f := readyPerRun(t, nil)
	refusedWithNothingStarted(t, p, f, sandbox.IsolationVM)
}

func TestKernelFloorRefusedBeforeAnyContainer(t *testing.T) {
	t.Run("gVisor off", func(t *testing.T) {
		p, f := readyPerRun(t, nil)
		refusedWithNothingStarted(t, p, f, sandbox.IsolationKernel)
	})
	t.Run("gVisor on", func(t *testing.T) {
		// gVisor inside the VM does not raise the tier: nothing has audited a kernel claim
		// for this provider.
		p, f, _ := readyGVisor(t, nil)
		if p.IsolationClass() != sandbox.IsolationContainer {
			t.Fatalf("gVisor on: tier %s", p.IsolationClass())
		}
		refusedWithNothingStarted(t, p, f, sandbox.IsolationKernel)
		refusedWithNothingStarted(t, p, f, sandbox.IsolationVM)
	})
	t.Run("gVisor on, accepted", func(t *testing.T) {
		// With the setting the tier is vm, gVisor or not, and the sentence is the accepted
		// one with gVisor's added.
		p, _, _ := readyGVisor(t, nil, func(c *Config) { c.AcceptVMTier = true })
		if p.IsolationClass() != sandbox.IsolationVM || p.Qualification() != PerRunAcceptedQualification+" "+GVisorQualification {
			t.Fatalf("gVisor on, accepted: tier %s, qualification %q", p.IsolationClass(), p.Qualification())
		}
		res, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1", MinimumIsolation: sandbox.IsolationKernel})
		if err != nil || res.Isolation != sandbox.IsolationVM || res.Policy != PolicyGVisor {
			t.Fatalf("a kernel floor on the accepted gVisor provider: %+v %v", res, err)
		}
	})
}

// A container floor still runs on the per-run mode's default: the change refuses only
// floors above what the mode now reports.
func TestContainerFloorRunsOnTheDefaultPerRunMode(t *testing.T) {
	p, _ := readyPerRun(t, nil)
	snippet, project := floorRequests(sandbox.IsolationContainer)
	res, err := p.RunJavaScript(context.Background(), snippet)
	if err != nil || res.Isolation != sandbox.IsolationContainer || res.ExitCode != 0 {
		t.Fatalf("snippet: %+v %v", res, err)
	}
	pr, err := p.RunProject(context.Background(), project)
	if err != nil || pr.Isolation != sandbox.IsolationContainer || pr.Outcome != sandbox.ProjectOutcomeCompleted {
		t.Fatalf("project: %+v %v", pr, err)
	}
}

func TestAcceptedVMTierAdmitsVMFloor(t *testing.T) {
	accept := func(c *Config) { c.AcceptVMTier = true }
	p, f := readyPerRun(t, nil, accept)
	if p.IsolationClass() != sandbox.IsolationVM {
		t.Fatalf("accepted: tier %s", p.IsolationClass())
	}
	for _, floor := range []sandbox.IsolationClass{sandbox.IsolationVM, sandbox.IsolationKernel} {
		snippet, project := floorRequests(floor)
		res, err := p.RunJavaScript(context.Background(), snippet)
		if err != nil || res.Isolation != sandbox.IsolationVM || res.ExitCode != 0 {
			t.Fatalf("snippet at %s: %+v %v", floor, res, err)
		}
		pr, err := p.RunProject(context.Background(), project)
		if err != nil || pr.Isolation != sandbox.IsolationVM || pr.Outcome != sandbox.ProjectOutcomeCompleted {
			t.Fatalf("project at %s: %+v %v", floor, pr, err)
		}
	}
	p.drain()
	if n := len(f.runs()); n != 4 {
		t.Fatalf("four admitted runs started %d containers", n)
	}
	ev, ok := p.Evidence()
	if !ok || !ev.VMTierAccepted {
		t.Fatalf("the evidence does not record the setting: %+v", ev)
	}
	q, _ := readyPerRun(t, nil)
	if ev, _ := q.Evidence(); ev.VMTierAccepted {
		t.Fatal("the evidence records the setting on a default provider")
	}
}

func TestAcceptVMTierVariable(t *testing.T) {
	env := func(kv ...string) func(string) string {
		m := map[string]string{"SANDBOX_WSLC_IMAGE": "plimsoll/sandbox:latest"}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return func(k string) string { return m[k] }
	}
	for _, c := range []struct {
		name string
		env  func(string) string
		tier sandbox.IsolationClass
	}{
		{"unset", env(), sandbox.IsolationContainer},
		{"0", env("SANDBOX_WSLC_ACCEPT_VM_TIER", "0"), sandbox.IsolationContainer},
		{"1", env("SANDBOX_WSLC_ACCEPT_VM_TIER", "1"), sandbox.IsolationVM},
		{"1 with per-run named", env("SANDBOX_WSLC_ACCEPT_VM_TIER", "1", "SANDBOX_WSLC_MODE", "per-run"), sandbox.IsolationVM},
	} {
		prov, err := FromEnv(c.env)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := prov.Sandbox.IsolationClass(); got != c.tier {
			t.Errorf("%s: tier %s, want %s", c.name, got, c.tier)
		}
	}
	for name, c := range map[string]struct {
		env  func(string) string
		want string
	}{
		"not a boolean": {env("SANDBOX_WSLC_ACCEPT_VM_TIER", "yes"), "SANDBOX_WSLC_ACCEPT_VM_TIER must be one of"},
	} {
		if _, err := FromEnv(c.env); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error naming %q", name, err, c.want)
		}
	}
	// The shared mode refuses the variable whatever its value: it means nothing there, so an
	// operator who set it, even to 0 or false, expected something it does not do (finding
	// wslc-32). Before, only a value read as true was refused.
	for _, v := range []string{"0", "false", "1", "true", "FALSE", " 0 ", "yes"} {
		_, err := FromEnv(env("SANDBOX_WSLC_ACCEPT_VM_TIER", v, "SANDBOX_WSLC_MODE", "shared"))
		if err == nil || !strings.Contains(err.Error(), "SANDBOX_WSLC_ACCEPT_VM_TIER applies to SANDBOX_WSLC_MODE=per-run only") {
			t.Errorf("shared mode with SANDBOX_WSLC_ACCEPT_VM_TIER=%q: %v, want the per-run-only refusal", v, err)
		}
	}
	// Unset (or only spaces, which every boolean setting reads as unset) builds the shared mode.
	for _, v := range []string{"", "  "} {
		prov, err := FromEnv(env("SANDBOX_WSLC_ACCEPT_VM_TIER", v, "SANDBOX_WSLC_MODE", "shared"))
		if err != nil || prov.Sandbox.IsolationClass() != sandbox.IsolationContainer {
			t.Errorf("shared mode with SANDBOX_WSLC_ACCEPT_VM_TIER=%q: %v, %v; want the shared mode at container", v, prov.Sandbox, err)
		}
	}
	// A caller of New is refused the same way.
	if _, err := New(Config{Mode: ModeShared, Image: "plimsoll/sandbox:latest", AcceptVMTier: true}); err == nil ||
		!strings.Contains(err.Error(), "per-run only") {
		t.Errorf("New with the shared mode and AcceptVMTier: %v, want the per-run-only refusal", err)
	}
}

func TestQualificationNamesTheSetting(t *testing.T) {
	for name, q := range map[string]string{"container": PerRunQualification, "vm": PerRunAcceptedQualification} {
		if !strings.Contains(q, microsoftStatement) || !strings.Contains(q, perRunFacts) {
			t.Errorf("%s: %q lacks Microsoft's statement or the mode's facts", name, q)
		}
		if !strings.Contains(q, "SANDBOX_WSLC_ACCEPT_VM_TIER=1") {
			t.Errorf("%s: %q does not name the setting", name, q)
		}
	}
	if !strings.HasPrefix(PerRunQualification, "Reported as container: ") || !strings.HasSuffix(PerRunQualification, "this mode then reports vm.") {
		t.Errorf("the default sentence does not say what it reports and how to change it: %q", PerRunQualification)
	}
	if !strings.HasSuffix(PerRunAcceptedQualification, "The operator of this daemon set SANDBOX_WSLC_ACCEPT_VM_TIER=1.") {
		t.Errorf("the accepted sentence does not say the operator set it: %q", PerRunAcceptedQualification)
	}
	if !strings.Contains(SharedQualification, microsoftStatement) {
		t.Errorf("the shared sentence lacks Microsoft's statement: %q", SharedQualification)
	}
}
