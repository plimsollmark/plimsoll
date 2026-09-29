package main

import (
	"maps"
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// TestOpenShellRegistered: this build has the provider and -h documents it.
func TestOpenShellRegistered(t *testing.T) {
	help := helpText()
	for _, want := range []string{"| openshell |", "SANDBOX_PROVIDER=openshell", "SANDBOX_OPENSHELL_GATEWAY_URL", "SANDBOX_OPENSHELL_IMAGE"} {
		if !strings.Contains(help, want) {
			t.Errorf("-h lacks %q", want)
		}
	}
}

// TestBuildOpenShellFromEnv: the five variables and the envelope reach the provider,
// which contacts nothing until Preflight; a process or disk limit, a missing
// variable or a malformed value is refused at construction.
func TestBuildOpenShellFromEnv(t *testing.T) {
	cert, key := writeSelfSignedPair(t)
	good := map[string]string{
		"SANDBOX_PROVIDER":              "openshell",
		"SANDBOX_OPENSHELL_GATEWAY_URL": "https://127.0.0.1:17670",
		"SANDBOX_OPENSHELL_CA_FILE":     cert,
		"SANDBOX_OPENSHELL_CERT_FILE":   cert,
		"SANDBOX_OPENSHELL_KEY_FILE":    key,
		"SANDBOX_OPENSHELL_IMAGE":       "plimsoll/sandbox:latest",
		"SANDBOX_MEMORY_MB":             "192",
		"SANDBOX_CPUS":                  "0.5",
	}
	p, err := buildProvider(getenvFrom(good))
	if err != nil {
		t.Fatal(err)
	}
	if p.Sandbox.Name() != "openshell" || p.Resources.MemoryMB != 192 || p.Resources.CPUs != 0.5 {
		t.Fatalf("built %s with %+v", p.Sandbox.Name(), p.Resources)
	}
	if tier := p.Sandbox.IsolationClass(); tier != sandbox.IsolationUnknown {
		t.Fatalf("tier %v before any gateway check, want unknown", tier)
	}
	if _, ok := p.Sandbox.(sandbox.Drainer); !ok {
		t.Fatal("the provider does not implement sandbox.Drainer, so shutdown would not wait for its deletes")
	}
	disk := maps.Clone(good)
	disk["SANDBOX_DISK_MB"] = "100"
	if p, err := buildProvider(getenvFrom(disk)); err != nil || p.Resources.DiskMB != 100 {
		t.Fatalf("SANDBOX_DISK_MB=100: %+v, %v", p.Resources, err)
	}
	for name, c := range map[string]struct {
		bend func(map[string]string)
		want string
	}{
		"process limit":      {func(e map[string]string) { e["SANDBOX_PIDS"] = "64" }, "SANDBOX_PIDS"},
		"negative disk":      {func(e map[string]string) { e["SANDBOX_DISK_MB"] = "-1" }, "SANDBOX_DISK_MB"},
		"no gateway":         {func(e map[string]string) { delete(e, "SANDBOX_OPENSHELL_GATEWAY_URL") }, "openshell"},
		"no client key":      {func(e map[string]string) { delete(e, "SANDBOX_OPENSHELL_KEY_FILE") }, "mutual TLS"},
		"no image":           {func(e map[string]string) { delete(e, "SANDBOX_OPENSHELL_IMAGE") }, "image is required"},
		"tag under pin rule": {func(e map[string]string) { e["SANDBOX_REQUIRE_PINNED_IMAGES"] = "1" }, "not pinned"},
		"malformed pin flag": {func(e map[string]string) { e["SANDBOX_REQUIRE_PINNED_IMAGES"] = "yes" }, "SANDBOX_REQUIRE_PINNED_IMAGES"},
		"malformed memory":   {func(e map[string]string) { e["SANDBOX_MEMORY_MB"] = "lots" }, "SANDBOX_MEMORY_MB"},
		"unreadable key":     {func(e map[string]string) { e["SANDBOX_OPENSHELL_KEY_FILE"] = cert + ".missing" }, "openshell"},
	} {
		env := maps.Clone(good)
		c.bend(env)
		if _, err := buildProvider(getenvFrom(env)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want a refusal mentioning %q", name, err, c.want)
		}
	}
}

// TestHardenedPolicyOpenShell: hardened mode refuses the provider by its tier
// (container), asks for a pinned image and the disk limit it enforces, and never for
// the process limit the provider itself rejects.
func TestHardenedPolicyOpenShell(t *testing.T) {
	f := hardenedDockerFacts()
	f.Provider, f.Isolation = "openshell", sandbox.IsolationContainer
	err := enforceHardenedPolicy(getenvFrom(map[string]string{"SANDBOX_MEMORY_MB": "256", "SANDBOX_CPUS": "1"}), f)
	if err == nil || !strings.Contains(err.Error(), "requires vm") || !strings.Contains(err.Error(), "SANDBOX_REQUIRE_PINNED_IMAGES=1 so the openshell image") ||
		!strings.Contains(err.Error(), "SANDBOX_DISK_MB") {
		t.Fatalf("err = %v, want the tier, pin and disk limit violations", err)
	}
	if strings.Contains(err.Error(), "SANDBOX_PIDS") {
		t.Fatalf("err = %v, demands a limit the provider rejects", err)
	}
}
