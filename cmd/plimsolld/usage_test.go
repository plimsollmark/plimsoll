package main

import (
	"io"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/internal/settings"
)

func TestParseArgsAcceptsOnlyHelp(t *testing.T) {
	for _, args := range [][]string{{"-h"}, {"--help"}, {"help"}} {
		help, err := parseArgs(args)
		if err != nil || !help {
			t.Fatalf("parseArgs(%q) = %v, %v; want a help request", args, help, err)
		}
	}
	if help, err := parseArgs(nil); err != nil || help {
		t.Fatalf("parseArgs(nil) = %v, %v; want a normal start", help, err)
	}
	for _, args := range [][]string{{"-x"}, {"-h", "extra"}, {"serve"}, {"--addr=:1"}, {"PLIMSOLL_ADDR=:1"}} {
		if _, err := parseArgs(args); err == nil {
			t.Fatalf("parseArgs(%q) accepted an argument the daemon does not take", args)
		}
	}
}

// TestEveryReadVariableIsASetting: every variable the daemon's loaders read, under a
// deployment of each provider this build has, is one internal/settings declares, so -h
// documents it and a misspelling of it is named at startup. The reads are recorded from
// the loaders themselves, so a name built at run time is caught as well as a literal one
// (internal/settings' TestNoVariableIsReadOutsideTheTable catches a literal one in any
// file).
func TestEveryReadVariableIsASetting(t *testing.T) {
	seen := map[string]bool{}
	for name := range providers {
		env := map[string]string{"SANDBOX_PROVIDER": name, "SANDBOX_MAX_SESSIONS": "2", "SANDBOX_DOCKERCLOUD_STORE_IMAGE": "x", "SANDBOX_WSLC_MODE": "shared"}
		rec := func(k string) string { seen[k] = true; return env[k] }
		_, _ = buildProvider(rec)
		_ = enforceHardenedPolicy(rec, hardenedFacts{Provider: name})
		sc, _ := loadSessionConfig(rec)
		_, _ = loadSessionPool(rec, sc)
		_, _ = loadLimiterConfig(rec, name, 256, 0)
		_, _, _ = minimumIsolationWith(rec)
		_, _ = metricsAddrWith(rec)
		_, _ = guardAddrWith(rec, true)
		_, _ = tlsConfigFromEnv(rec)
		_, _ = loadPaidConfig(rec, true)
		_ = newLogHandler(rec, io.Discard)
	}
	if len(seen) < 40 {
		t.Fatalf("recorded only %d reads; the guard checked too little", len(seen))
	}
	for name := range seen {
		if _, ok := settings.Lookup(name); !ok {
			t.Errorf("the daemon reads %s, which internal/settings does not declare", name)
		}
	}
}

// A variable the daemon does not read is named at startup: a misspelled setting, or one
// a newer plimsolld has, would otherwise be ignored without a word. E2B_ and DOCKER_SBX_
// names are checked too since 2026-11-18 (a misspelled E2B_TEMPLATE was silent).
func TestUnknownVariablesAreNamed(t *testing.T) {
	got := unknownVariables([]string{
		"SANDBOX_MAX_SESSIONS=4", "SANDBOX_MAX_SESION_PER_OWNER=3", "PLIMSOLL_ADDR=:1",
		"PLIMSOLL_TOKN=x", "HOME=/root", "SANDBOX_DOCKERCLOUD_API_URLX=y", "E2B_TEMPLAT=t", "E2B_TEMPLATE=t",
		"DOCKER_SBX_TOKN=x", "AWS_REGION=x",
	})
	want := []string{"DOCKER_SBX_TOKN", "E2B_TEMPLAT", "PLIMSOLL_TOKN", "SANDBOX_DOCKERCLOUD_API_URLX", "SANDBOX_MAX_SESION_PER_OWNER"}
	if !slices.Equal(got, want) {
		t.Fatalf("unknown variables: %v; want %v", got, want)
	}
}

// PLIMSOLL_INSECURE is a Bool setting like every opt-in (internal/settings): until
// 2026-11-18 only exactly "1" acknowledged open mode, " 1" and "true" were read as not
// acknowledging, and a typo such as "yes" was a refusal to start that did not name it.
// Now 1 or true in any case acknowledge, and any other value fails startup naming it.
func TestInsecureIsReadAsABool(t *testing.T) {
	base := []string{"PATH=" + os.Getenv("PATH"), "SANDBOX_PROVIDER=wasm", "PLIMSOLL_ADDR=127.0.0.1:0", "PLIMSOLL_METRICS_ADDR=off"}
	for _, typo := range []string{"yes", "2"} {
		code, log := exitDaemon(t, append(slices.Clone(base), "PLIMSOLL_INSECURE="+typo), 30*time.Second)
		if code == 0 || !strings.Contains(log, "invalid PLIMSOLL_INSECURE") {
			t.Fatalf("PLIMSOLL_INSECURE=%q: exit %d, want a failure naming the setting; log:\n%s", typo, code, log)
		}
	}
	for _, off := range []string{"0", "false"} {
		code, log := exitDaemon(t, append(slices.Clone(base), "PLIMSOLL_INSECURE="+off), 30*time.Second)
		if code == 0 || !strings.Contains(log, "refusing to start") {
			t.Fatalf("PLIMSOLL_INSECURE=%q: exit %d, want open mode refused; log:\n%s", off, code, log)
		}
	}
	for _, on := range []string{"1", " true ", "TRUE"} {
		d := startDaemon(t, append(slices.Clone(base), "PLIMSOLL_INSECURE="+on), 30*time.Second)
		_ = d.cmd.Process.Kill()
	}
}
