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
// tier is container, as is the per-run mode's by default, and the per-run mode's vm tier
// with SANDBOX_WSLC_ACCEPT_VM_TIER=1, which the generic tier check would pass, is refused
// by the descriptor in its own words (whether hardened mode may ever accept it waits on the
// project owner).
func TestHardenedModeRefusesWSLC(t *testing.T) {
	for _, tc := range []struct {
		mode   string
		accept bool
		tier   sandbox.IsolationClass
	}{{"shared", false, sandbox.IsolationContainer}, {"per-run", false, sandbox.IsolationContainer}, {"per-run", true, sandbox.IsolationVM}} {
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
		if tc.accept {
			env["SANDBOX_WSLC_ACCEPT_VM_TIER"] = "1"
		}
		err := enforceHardenedPolicy(getenvFrom(env), f)
		if err == nil || !strings.Contains(err.Error(), "hardened mode does not serve wslc in either mode") {
			t.Fatalf("hardened mode with wslc %s (tier %s): %v", tc.mode, tc.tier, err)
		}
	}
}

// Each mode's tier is stated with its own qualification on the startup log: the per-run
// mode's container with the per-run sentence, its vm (with SANDBOX_WSLC_ACCEPT_VM_TIER=1)
// with the accepted one, the shared mode's container with the shared one, and all carry
// Microsoft's statement. A tier logged with no sentence, or with another's, fails.
func TestWSLCStartupLogQualifiesTheTier(t *testing.T) {
	for _, tc := range []struct {
		mode, accept string
		tier         sandbox.IsolationClass
		sentence     string
	}{
		{"shared", "", sandbox.IsolationContainer, wslc.SharedQualification},
		{"per-run", "", sandbox.IsolationContainer, wslc.PerRunQualification},
		{"", "", sandbox.IsolationContainer, wslc.PerRunQualification},
		{"per-run", "1", sandbox.IsolationVM, wslc.PerRunAcceptedQualification},
		{"", "1", sandbox.IsolationVM, wslc.PerRunAcceptedQualification},
	} {
		mode := tc.mode
		env := map[string]string{"SANDBOX_PROVIDER": "wslc", "SANDBOX_WSLC_IMAGE": "plimsoll/sandbox:latest", "SANDBOX_WSLC_MODE": mode, "SANDBOX_WSLC_ACCEPT_VM_TIER": tc.accept}
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
		if p.Sandbox.IsolationClass() != tc.tier || q != tc.sentence {
			t.Fatalf("mode %q, accept %q: tier %s, qualification %v", mode, tc.accept, p.Sandbox.IsolationClass(), q)
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
// unchanged. The tier stays container (gVisor does not raise it). Off, the log says runc
// and the qualification is the per-run mode's alone.
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
		if p.Sandbox.IsolationClass() != sandbox.IsolationContainer {
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
// the RPC layer over the real provider, carries the per-run sentence with the container tier
// in the per-run mode (the default), the accepted sentence with the vm tier once the
// operator sets SANDBOX_WSLC_ACCEPT_VM_TIER=1, the shared mode's own sentence in the shared
// mode, and with gVisor on ends with gVisor's own sentence. gVisor does not change the tier.
func TestWSLCDescribeStatesTheQualification(t *testing.T) {
	base := map[string]string{"SANDBOX_PROVIDER": "wslc", "SANDBOX_WSLC_IMAGE": "plimsoll/sandbox:latest"}
	gvisor := map[string]string{"SANDBOX_WSLC_GVISOR": "1", "SANDBOX_WSLC_RUNSC_PATH": "/usr/local/bin/runsc", "SANDBOX_WSLC_RUNSC_SHA512": strings.Repeat("a", 128)}
	accept := map[string]string{"SANDBOX_WSLC_ACCEPT_VM_TIER": "1"}
	merged := func(ms ...map[string]string) map[string]string {
		out := map[string]string{}
		for _, m := range ms {
			for k, v := range m {
				out[k] = v
			}
		}
		return out
	}
	for _, tc := range []struct {
		name  string
		extra map[string]string
		tier  string
		want  func(q string) bool
	}{
		{"default (per-run)", nil, "container", func(q string) bool { return q == wslc.PerRunQualification }},
		{"per-run", map[string]string{"SANDBOX_WSLC_MODE": "per-run"}, "container", func(q string) bool { return q == wslc.PerRunQualification }},
		{"per-run accepted", accept, "vm", func(q string) bool { return q == wslc.PerRunAcceptedQualification }},
		{"shared", map[string]string{"SANDBOX_WSLC_MODE": "shared"}, "container", func(q string) bool { return q == wslc.SharedQualification }},
		{"per-run with gVisor", gvisor, "container", func(q string) bool {
			return q == wslc.PerRunQualification+" "+wslc.GVisorQualification
		}},
		{"per-run with gVisor, accepted", merged(gvisor, accept), "vm", func(q string) bool {
			return q == wslc.PerRunAcceptedQualification+" "+wslc.GVisorQualification
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

// A daemon whose operator requires vm (or kernel) of the wslc per-run mode refuses to start
// until the operator accepts Microsoft's statement: the startup check returns an error
// naming the provider, the tier it reports and the floor, with the sentence that names the
// setting. With the setting, vm and kernel are met; container is met either way.
func TestWSLCDaemonFloorVMRefusesToStartWithoutAcceptance(t *testing.T) {
	build := func(extra map[string]string) sandbox.Sandbox {
		t.Helper()
		env := map[string]string{"SANDBOX_PROVIDER": "wslc", "SANDBOX_WSLC_IMAGE": "plimsoll/sandbox:latest"}
		for k, v := range extra {
			env[k] = v
		}
		p, err := buildProvider(getenvFrom(env))
		if err != nil {
			t.Fatal(err)
		}
		return p.Sandbox
	}
	floor := func(raw string) sandbox.IsolationClass {
		t.Helper()
		want, required, err := minimumIsolationWith(getenvFrom(map[string]string{"SANDBOX_MIN_ISOLATION": raw}))
		if err != nil || !required {
			t.Fatalf("SANDBOX_MIN_ISOLATION=%s: %v, required %v", raw, err, required)
		}
		return want
	}
	def := build(nil)
	for _, raw := range []string{"vm", "kernel"} {
		err := operatorMinimumError(def, floor(raw), true)
		if err == nil {
			t.Fatalf("SANDBOX_MIN_ISOLATION=%s on the default per-run mode: no error", raw)
		}
		for _, want := range []string{`"wslc"`, "reports isolation container", "SANDBOX_MIN_ISOLATION=" + raw, "SANDBOX_WSLC_ACCEPT_VM_TIER=1"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("SANDBOX_MIN_ISOLATION=%s: %v does not name %q", raw, err, want)
			}
		}
	}
	if err := operatorMinimumError(def, floor("container"), true); err != nil {
		t.Fatalf("a container floor on the default per-run mode: %v", err)
	}
	if err := operatorMinimumError(def, sandbox.IsolationUnknown, false); err != nil {
		t.Fatalf("no floor: %v", err)
	}
	accepted := build(map[string]string{"SANDBOX_WSLC_ACCEPT_VM_TIER": "1"})
	for _, raw := range []string{"vm", "kernel", "container"} {
		if err := operatorMinimumError(accepted, floor(raw), true); err != nil {
			t.Fatalf("SANDBOX_MIN_ISOLATION=%s with the setting: %v", raw, err)
		}
	}
}

// -h states the values SANDBOX_WSLC_ACCEPT_VM_TIER takes exactly as the provider reads them
// (sandbox.BoolFromEnv): unset, 0 or false is off and the per-run mode reports container;
// 1 or true is on and it reports vm; letter case and surrounding spaces are ignored; any
// other value refuses startup (finding wslc-31: -h named only unset, 0 and 1).
func TestWSLCAcceptVMTierHelpListsTheValuesTheCodeAccepts(t *testing.T) {
	help := strings.Join(strings.Fields(wslcUsage), " ")
	start := strings.Index(help, "SANDBOX_WSLC_ACCEPT_VM_TIER per-run only")
	end := strings.Index(help, "SANDBOX_WSLC_MAX_SESSIONS")
	if start < 0 || end < start {
		t.Fatalf("no SANDBOX_WSLC_ACCEPT_VM_TIER section in -h")
	}
	section := help[start:end]
	for _, claim := range []string{"Off (unset, 0 or false)", "On (1 or true)",
		"Letter case and spaces around the value are ignored; any other value refuses startup",
		"In the shared mode any value refuses startup, 0 included"} {
		if !strings.Contains(section, claim) {
			t.Errorf("-h does not say %q: %s", claim, section)
		}
	}
	for value, tier := range map[string]sandbox.IsolationClass{
		"": sandbox.IsolationContainer, "0": sandbox.IsolationContainer, "false": sandbox.IsolationContainer,
		"FALSE": sandbox.IsolationContainer, " 0 ": sandbox.IsolationContainer,
		"1": sandbox.IsolationVM, "true": sandbox.IsolationVM, "True": sandbox.IsolationVM, " 1 ": sandbox.IsolationVM,
		"yes": sandbox.IsolationUnknown, "on": sandbox.IsolationUnknown, "t": sandbox.IsolationUnknown, "2": sandbox.IsolationUnknown,
	} {
		p, err := buildProvider(getenvFrom(map[string]string{"SANDBOX_PROVIDER": "wslc", "SANDBOX_WSLC_IMAGE": "plimsoll/sandbox:latest",
			"SANDBOX_WSLC_ACCEPT_VM_TIER": value}))
		switch {
		case tier == sandbox.IsolationUnknown && err == nil:
			t.Errorf("SANDBOX_WSLC_ACCEPT_VM_TIER=%q, a value -h does not list, started at %s", value, p.Sandbox.IsolationClass())
		case tier != sandbox.IsolationUnknown && (err != nil || p.Sandbox.IsolationClass() != tier):
			t.Errorf("SANDBOX_WSLC_ACCEPT_VM_TIER=%q: %v, %v; want %s", value, p.Sandbox, err, tier)
		}
	}
}
