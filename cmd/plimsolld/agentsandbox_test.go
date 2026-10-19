package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAgentSandboxRegistered: this build has the provider and -h documents it.
func TestAgentSandboxRegistered(t *testing.T) {
	help := helpText()
	for _, want := range []string{"| agentsandbox |", "SANDBOX_PROVIDER=agentsandbox", "SANDBOX_AGENTSANDBOX_WARM_POOL", "SANDBOX_AGENTSANDBOX_SANDBOXD_TOKEN_FILE"} {
		if !strings.Contains(help, want) {
			t.Errorf("-h lacks %q", want)
		}
	}
}

// TestBuildAgentSandboxFromEnv: the variables and the envelope reach the provider, which
// contacts nothing until Preflight; a process limit, a missing variable, an unreadable
// token file or a malformed value is refused at construction.
func TestBuildAgentSandboxFromEnv(t *testing.T) {
	cert, _ := writeSelfSignedPair(t)
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "sandboxd.token")
	if err := os.WriteFile(tokenFile, []byte(strings.Repeat("t", 40)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	apiToken := filepath.Join(dir, "api.token")
	if err := os.WriteFile(apiToken, []byte("api"), 0o600); err != nil {
		t.Fatal(err)
	}
	good := map[string]string{
		"SANDBOX_PROVIDER":                         "agentsandbox",
		"SANDBOX_AGENTSANDBOX_API_SERVER":          "https://127.0.0.1:6443",
		"SANDBOX_AGENTSANDBOX_CA_FILE":             cert,
		"SANDBOX_AGENTSANDBOX_TOKEN_FILE":          apiToken,
		"SANDBOX_AGENTSANDBOX_NAMESPACE":           "default",
		"SANDBOX_AGENTSANDBOX_WARM_POOL":           "plimsoll-run",
		"SANDBOX_AGENTSANDBOX_RUNTIME_CLASS":       "gvisor",
		"SANDBOX_AGENTSANDBOX_IMAGE":               "plimsoll/sandbox-agentsandbox:dev",
		"SANDBOX_AGENTSANDBOX_SANDBOXD_TOKEN_FILE": tokenFile,
		"SANDBOX_MEMORY_MB":                        "512",
		"SANDBOX_CPUS":                             "2",
		"SANDBOX_DISK_MB":                          "160",
	}
	p, err := buildProvider(getenvFrom(good))
	if err != nil {
		t.Fatal(err)
	}
	if p.Sandbox.Name() != "agentsandbox" || p.Resources.MemoryMB != 512 || p.Resources.CPUs != 2 || p.Resources.DiskMB != 160 {
		t.Fatalf("built %s with %+v", p.Sandbox.Name(), p.Resources)
	}
	with := func(name, value string) map[string]string {
		env := map[string]string{}
		for k, v := range good {
			env[k] = v
		}
		env[name] = value
		return env
	}
	for _, c := range []struct {
		name string
		env  map[string]string
		want string
	}{
		{"a process limit", with("SANDBOX_PIDS", "64"), "SANDBOX_PIDS"},
		{"no warm pool", with("SANDBOX_AGENTSANDBOX_WARM_POOL", ""), "SANDBOX_AGENTSANDBOX_WARM_POOL"},
		{"no image", with("SANDBOX_AGENTSANDBOX_IMAGE", ""), "SANDBOX_AGENTSANDBOX_IMAGE"},
		{"no token file", with("SANDBOX_AGENTSANDBOX_SANDBOXD_TOKEN_FILE", ""), "SANDBOX_AGENTSANDBOX_SANDBOXD_TOKEN_FILE"},
		{"an unreadable token file", with("SANDBOX_AGENTSANDBOX_SANDBOXD_TOKEN_FILE", filepath.Join(dir, "absent")), "sandboxd token"},
		{"a short token", with("SANDBOX_AGENTSANDBOX_SANDBOXD_TOKEN_FILE", apiToken), "32 to 512"},
		{"a cleartext API server", with("SANDBOX_AGENTSANDBOX_API_SERVER", "http://127.0.0.1:6443"), "https URL"},
		{"an unpinned image when pinning is required", with("SANDBOX_REQUIRE_PINNED_IMAGES", "1"), "not pinned"},
	} {
		if _, err := buildProvider(getenvFrom(c.env)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", c.name, err, c.want)
		}
	}
}
