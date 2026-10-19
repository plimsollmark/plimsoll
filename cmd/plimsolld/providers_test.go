package main

import (
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// registerTestProvider adds a daemon-built provider for one test.
func registerTestProvider(t *testing.T, dp daemonProvider) {
	t.Helper()
	daemonProviders["test-built"] = dp
	t.Cleanup(func() { delete(daemonProviders, "test-built") })
}

// TestBuildProviderRoutes: a daemon-built provider goes through its own constructor,
// sandbox.Build's names through Build, and an unknown name is refused naming every
// provider this build has, the daemon-built ones included.
func TestBuildProviderRoutes(t *testing.T) {
	built := false
	registerTestProvider(t, daemonProvider{
		build: func(func(string) string) (sandbox.Provider, error) {
			built = true
			return sandbox.Provider{Sandbox: sandbox.Disabled{}}, nil
		},
		usage: "\n  SANDBOX_PROVIDER=test-built a provider this test registers\n",
	})
	if _, err := buildProvider(getenvFrom(map[string]string{"SANDBOX_PROVIDER": " Test-Built "})); err != nil || !built {
		t.Fatalf("daemon-built provider: built=%v err=%v", built, err)
	}
	for raw, want := range map[string]string{"": "disabled", "docker": "docker", " DOCKER ": "docker"} {
		p, err := buildProvider(getenvFrom(map[string]string{"SANDBOX_PROVIDER": raw}))
		if err != nil || p.Sandbox.Name() != want {
			t.Errorf("SANDBOX_PROVIDER=%q: %v, %v; want %s through sandbox.Build", raw, p.Sandbox, err, want)
		}
	}
	_, err := buildProvider(getenvFrom(map[string]string{"SANDBOX_PROVIDER": "dockr"}))
	if err == nil || !strings.Contains(err.Error(), "dockercloud") || !strings.Contains(err.Error(), "test-built") {
		t.Fatalf("unknown provider: err = %v, want a refusal naming Build's providers and the daemon-built ones", err)
	}
	help := helpText()
	if !strings.Contains(help, "| test-built |") || !strings.Contains(help, "a provider this test registers") {
		t.Fatalf("-h does not name the registered provider or carry its section:\n%s", help)
	}
}

// TestHardenedPolicyDaemonBuiltProvider: a daemon-built provider's own envelope and
// pin rule replace the defaults, so hardened mode never demands a variable its
// configuration rejects.
func TestHardenedPolicyDaemonBuiltProvider(t *testing.T) {
	registerTestProvider(t, daemonProvider{hardenedEnvelope: []string{"SANDBOX_MEMORY_MB"}, pinnedImages: true})
	f := hardenedDockerFacts()
	f.Provider, f.Isolation = "test-built", sandbox.IsolationVM
	env := map[string]string{"SANDBOX_MEMORY_MB": "256", "SANDBOX_REQUIRE_PINNED_IMAGES": "1"}
	if err := enforceHardenedPolicy(getenvFrom(env), f); err != nil {
		t.Fatalf("compliant daemon-built deployment rejected: %v", err)
	}
	delete(env, "SANDBOX_REQUIRE_PINNED_IMAGES")
	err := enforceHardenedPolicy(getenvFrom(env), f)
	if err == nil || !strings.Contains(err.Error(), "SANDBOX_REQUIRE_PINNED_IMAGES=1 so the test-built image") {
		t.Fatalf("err = %v, want the pin rule", err)
	}
	if strings.Contains(err.Error(), "SANDBOX_CPUS") || strings.Contains(err.Error(), "SANDBOX_DISK_MB") {
		t.Fatalf("err = %v, demands a variable outside the provider's envelope", err)
	}
}

// TestHardenedPolicyEnvelopeAtTheProvenTier: agentsandbox enforces a disk budget below the
// vm tier and refuses one under Kata, so hardened mode requires SANDBOX_DISK_MB only once
// the smoke test has proven a tier below vm; the pass before it, with the tier pending,
// does not require it, since it cannot know which.
func TestHardenedPolicyEnvelopeAtTheProvenTier(t *testing.T) {
	dp := daemonProviders["agentsandbox"]
	f := hardenedDockerFacts()
	f.Provider = "agentsandbox"
	env := map[string]string{"SANDBOX_MEMORY_MB": "256", "SANDBOX_CPUS": "1", "SANDBOX_REQUIRE_PINNED_IMAGES": "1"}
	for _, c := range []struct {
		tier     sandbox.IsolationClass
		pending  bool
		wantDisk bool
	}{
		{sandbox.IsolationUnknown, true, false},
		{sandbox.IsolationKernel, false, true},
		{sandbox.IsolationVM, false, false},
	} {
		f.Isolation, f.IsolationPending = c.tier, c.pending
		err := enforceHardenedPolicy(getenvFrom(env), f)
		if got := err != nil && strings.Contains(err.Error(), "SANDBOX_DISK_MB"); got != c.wantDisk || (err != nil && !c.wantDisk) {
			t.Errorf("tier %s (pending %t): err = %v, want SANDBOX_DISK_MB required: %t", c.tier, c.pending, err, c.wantDisk)
		}
	}
	if dp.hardenedEnvelopeAt == nil {
		t.Fatal("agentsandbox names no tier-dependent envelope")
	}
}
