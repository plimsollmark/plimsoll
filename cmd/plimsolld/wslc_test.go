package main

import (
	"context"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/internal/rpc"
	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandbox/wslc"
)

// Every variable the wslc provider reads is one both of plimsolld's guards cover: -h names
// it, and a misspelling of it is named at startup. The reads are recorded from FromEnv
// itself, so a name built at run time is caught as well as a literal one.
func TestWSLCVariablesAreUnderTheDaemonsGuards(t *testing.T) {
	var read []string
	_, _ = wslc.FromEnv(func(k string) string {
		read = append(read, k)
		if k == "SANDBOX_WSLC_IMAGE" {
			return "plimsoll/sandbox:latest"
		}
		return ""
	})
	own := 0
	for _, name := range read {
		if !strings.HasPrefix(name, "SANDBOX_") && !strings.HasPrefix(name, "PLIMSOLL_") {
			t.Errorf("wslc reads %s, which neither the -h drift test nor the unknown-variable warning sees", name)
			continue
		}
		if strings.HasPrefix(name, "SANDBOX_WSLC_") {
			own++
		}
		if got := unknownVariables([]string{name + "=x"}, helpText()); len(got) != 0 {
			t.Errorf("wslc reads %s but -h does not name it", name)
		}
		if got := unknownVariables([]string{name + "X=x"}, helpText()); !slices.Equal(got, []string{name + "X"}) {
			t.Errorf("a misspelled %sX is not named at startup (got %v)", name, got)
		}
	}
	if own < 3 {
		t.Fatalf("FromEnv recorded only %v; the guard checked too little of the provider's own", read)
	}
}

// Hardened mode refuses wslc whatever else is in order, in both modes: the shared mode's
// tier is container, and the per-run mode's vm tier, which the generic tier check would
// pass, is refused by the descriptor in its own words (whether hardened mode may ever
// accept it waits on the project owner).
func TestHardenedModeRefusesWSLC(t *testing.T) {
	for _, tc := range []struct {
		mode string
		tier sandbox.IsolationClass
	}{{"shared", sandbox.IsolationContainer}, {"per-run", sandbox.IsolationVM}} {
		f := hardenedDockerFacts()
		f.Provider, f.Isolation = wslc.Name, tc.tier
		env := hardenedEnv()
		delete(env, "SANDBOX_PIDS")
		env["SANDBOX_WSLC_MODE"] = tc.mode
		if tc.mode == "per-run" {
			// gVisor inside each VM does not lift the refusal until an independent audit
			// has looked at it.
			env["SANDBOX_WSLC_GVISOR"] = "1"
			env["SANDBOX_WSLC_RUNSC_PATH"] = "/usr/local/bin/runsc"
			env["SANDBOX_WSLC_RUNSC_SHA512"] = strings.Repeat("a", 128)
		}
		err := enforceHardenedPolicy(getenvFrom(env), f)
		if err == nil || !strings.Contains(err.Error(), "hardened mode does not serve wslc in either mode") {
			t.Fatalf("hardened mode with wslc %s (tier %s): %v", tc.mode, tc.tier, err)
		}
	}
}

// Each mode's tier is stated with its own qualification on the startup log: the per-run
// mode's vm with the per-run sentence, the shared mode's container with the shared one, and
// both carry Microsoft's statement. A tier logged with no sentence, or with the other
// mode's, fails.
func TestWSLCStartupLogQualifiesTheTier(t *testing.T) {
	for _, mode := range []string{"shared", "per-run", ""} {
		env := map[string]string{"SANDBOX_PROVIDER": "wslc", "SANDBOX_WSLC_IMAGE": "plimsoll/sandbox:latest", "SANDBOX_WSLC_MODE": mode}
		p, err := buildProvider(getenvFrom(env))
		if err != nil {
			t.Fatal(err)
		}
		args := providers[wslc.Name].resourceLog(p.Sandbox, p.Resources)
		got := map[string]any{}
		for i := 0; i+1 < len(args); i += 2 {
			got[args[i].(string)] = args[i+1]
		}
		q := got["isolation_qualification"]
		switch {
		case mode != "shared" && (p.Sandbox.IsolationClass() != sandbox.IsolationVM || q != wslc.PerRunQualification):
			t.Fatalf("per-run: tier %s, qualification %v", p.Sandbox.IsolationClass(), q)
		case mode == "shared" && (p.Sandbox.IsolationClass() != sandbox.IsolationContainer || q != wslc.SharedQualification):
			t.Fatalf("shared: tier %s, qualification %v", p.Sandbox.IsolationClass(), q)
		}
		if s, _ := q.(string); !strings.Contains(s, "Microsoft states that WSL is not a security sandbox for running untrusted code") {
			t.Fatalf("mode %q: the qualification lacks Microsoft's statement: %v", mode, q)
		}
	}
}

// plimsolld builds wslc only when SANDBOX_PROVIDER names it, and the build fails closed on
// a configuration the provider cannot honor.
func TestWSLCIsBuiltOnlyWhenNamed(t *testing.T) {
	env := map[string]string{"SANDBOX_PROVIDER": "wslc", "SANDBOX_PIDS": "64", "SANDBOX_WSLC_IMAGE": "plimsoll/sandbox:latest", "SANDBOX_WSLC_MODE": "shared"}
	if _, err := buildProvider(getenvFrom(env)); err == nil || !strings.Contains(err.Error(), "SANDBOX_PIDS") {
		t.Fatalf("SANDBOX_PIDS with wslc: %v", err)
	}
	delete(env, "SANDBOX_PIDS")
	p, err := buildProvider(getenvFrom(env))
	if err != nil || p.Sandbox.Name() != wslc.Name || p.Sandbox.IsolationClass() != sandbox.IsolationContainer {
		t.Fatalf("buildProvider(wslc) = %v, %v", p.Sandbox, err)
	}
	if _, ok := p.Sandbox.(sandbox.SessionProvider); ok {
		t.Fatal("wslc states sessions, which this provider does not build")
	}
	delete(env, "SANDBOX_PROVIDER")
	if p, err := buildProvider(getenvFrom(env)); err != nil || p.Sandbox.Name() == wslc.Name {
		t.Fatalf("with SANDBOX_PROVIDER unset the daemon built %v (%v)", p.Sandbox, err)
	}
}

// With gVisor on, the startup log states the runtime, and the tier's qualification carries
// gVisor's own position: an added wall inside the VM, with the VM wall's qualification
// unchanged. The tier stays vm. Off, the log says runc and the qualification is the
// per-run mode's alone.
func TestWSLCStartupLogStatesTheRuntime(t *testing.T) {
	for _, gvisor := range []bool{false, true} {
		env := map[string]string{"SANDBOX_PROVIDER": "wslc", "SANDBOX_WSLC_IMAGE": "plimsoll/sandbox:latest", "SANDBOX_WSLC_MODE": "per-run"}
		if gvisor {
			env["SANDBOX_WSLC_GVISOR"] = "1"
			env["SANDBOX_WSLC_RUNSC_PATH"] = "/usr/local/bin/runsc"
			env["SANDBOX_WSLC_RUNSC_SHA512"] = strings.Repeat("a", 128)
		}
		p, err := buildProvider(getenvFrom(env))
		if err != nil {
			t.Fatal(err)
		}
		if p.Sandbox.IsolationClass() != sandbox.IsolationVM {
			t.Fatalf("gvisor=%v: tier %s", gvisor, p.Sandbox.IsolationClass())
		}
		args := providers[wslc.Name].resourceLog(p.Sandbox, p.Resources)
		got := map[string]any{}
		for i := 0; i+1 < len(args); i += 2 {
			got[args[i].(string)] = args[i+1]
		}
		runtime, _ := got["wslc_runtime"].(string)
		q, _ := got["isolation_qualification"].(string)
		switch {
		case gvisor && (!strings.HasPrefix(runtime, "runsc (gVisor, systrap)") || q != wslc.PerRunQualification+" "+wslc.GVisorQualification):
			t.Fatalf("gVisor on: runtime %q, qualification %q", runtime, q)
		case !gvisor && (runtime != "runc" || q != wslc.PerRunQualification):
			t.Fatalf("gVisor off: runtime %q, qualification %q", runtime, q)
		}
	}
	// The shared mode refuses the setting, at build.
	env := map[string]string{"SANDBOX_PROVIDER": "wslc", "SANDBOX_WSLC_IMAGE": "plimsoll/sandbox:latest", "SANDBOX_WSLC_MODE": "shared", "SANDBOX_WSLC_GVISOR": "1",
		"SANDBOX_WSLC_RUNSC_PATH": "/usr/local/bin/runsc", "SANDBOX_WSLC_RUNSC_SHA512": strings.Repeat("a", 128)}
	if _, err := buildProvider(getenvFrom(env)); err == nil || !strings.Contains(err.Error(), "per-run only") {
		t.Fatalf("gVisor in the shared mode: %v", err)
	}
}

// The qualification reaches a caller that asks the daemon what it is: Describe, served by
// the RPC layer over the real provider, carries Microsoft's sentence in the per-run mode
// (the default), the shared mode's own sentence in the shared mode, and with gVisor on ends with gVisor's own
// sentence. The tier is unchanged either way.
func TestWSLCDescribeStatesTheQualification(t *testing.T) {
	base := map[string]string{"SANDBOX_PROVIDER": "wslc", "SANDBOX_WSLC_IMAGE": "plimsoll/sandbox:latest"}
	gvisor := map[string]string{"SANDBOX_WSLC_GVISOR": "1", "SANDBOX_WSLC_RUNSC_PATH": "/usr/local/bin/runsc", "SANDBOX_WSLC_RUNSC_SHA512": strings.Repeat("a", 128)}
	for _, tc := range []struct {
		name  string
		extra map[string]string
		tier  string
		want  func(q string) bool
	}{
		{"default (per-run)", nil, "vm", func(q string) bool { return q == wslc.PerRunQualification }},
		{"per-run", map[string]string{"SANDBOX_WSLC_MODE": "per-run"}, "vm", func(q string) bool { return q == wslc.PerRunQualification }},
		{"shared", map[string]string{"SANDBOX_WSLC_MODE": "shared"}, "container", func(q string) bool { return q == wslc.SharedQualification }},
		{"per-run with gVisor", gvisor, "vm", func(q string) bool {
			return strings.HasPrefix(q, wslc.PerRunQualification) && strings.HasSuffix(q, wslc.GVisorQualification)
		}},
	} {
		env := map[string]string{}
		for _, m := range []map[string]string{base, tc.extra} {
			for k, v := range m {
				env[k] = v
			}
		}
		p, err := buildProvider(getenvFrom(env))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		resp, err := rpc.NewSandboxService(p.Sandbox).Describe(context.Background(), connect.NewRequest(&plimsollv1.DescribeRequest{}))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if q := resp.Msg.GetIsolationQualification(); !tc.want(q) || resp.Msg.GetIsolation() != tc.tier {
			t.Errorf("%s: Describe states tier %q with qualification %q", tc.name, resp.Msg.GetIsolation(), q)
		}
	}
}
