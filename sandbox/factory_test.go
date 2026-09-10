package sandbox

import (
	"context"
	"testing"
)

func mapEnv(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}

func TestResourcesFromEnvStrictParsing(t *testing.T) {
	res, err := resourcesFromEnv(mapEnv(map[string]string{
		"SANDBOX_MEMORY_MB": "256",
		"SANDBOX_CPUS":      "0.5",
		"SANDBOX_PIDS":      "64",
		"SANDBOX_DISK_MB":   "128",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if res.MemoryMB != 256 || res.CPUs != 0.5 || res.PidsLimit != 64 || res.DiskMB != 128 {
		t.Fatalf("resources = %+v", res)
	}
	for key, value := range map[string]string{
		"SANDBOX_MEMORY_MB": "-1",
		"SANDBOX_CPUS":      "NaN",
		"SANDBOX_PIDS":      "many",
		"SANDBOX_DISK_MB":   "1.5",
	} {
		if _, err := resourcesFromEnv(mapEnv(map[string]string{key: value})); err == nil {
			t.Errorf("%s=%q silently became a default", key, value)
		}
	}
}

func TestBuildFailsClosedOnInvalidSafetyConfig(t *testing.T) {
	cases := []map[string]string{
		{"SANDBOX_PROVIDER": "wasm", "SANDBOX_CPUS": "not-a-number"}, // malformed envelope
		{"SANDBOX_PROVIDER": "wasm", "SANDBOX_PIDS": "64"},           // dimension wasm cannot enforce
		{"SANDBOX_PROVIDER": "e2b", "SANDBOX_PIDS": "64"},            // dimension e2b cannot enforce
		{"SANDBOX_PROVIDER": "e2b", "SANDBOX_CPUS": "0.5"},           // fractional vCPU
		{"SANDBOX_PROVIDER": "dokcer"},                               // typo must not silently disable execution
		{"SANDBOX_PROVIDER": "docker", "SANDBOX_REQUIRE_PINNED_IMAGES": "yes"},
	}
	for _, env := range cases {
		if _, err := Build(mapEnv(env)); err == nil {
			t.Errorf("Build(%v) succeeded, want a configuration error", env)
		}
	}
}

func TestBuildDefaultsToDisabled(t *testing.T) {
	p, err := Build(mapEnv(nil))
	if err != nil {
		t.Fatal(err)
	}
	if p.Sandbox.Name() != "disabled" {
		t.Fatalf("provider = %q, want disabled", p.Sandbox.Name())
	}
	if _, err := p.Sandbox.RunJavaScript(context.Background(), Request{Code: "1"}); err == nil {
		t.Fatal("disabled provider executed code")
	}
	// EnsureReady on a provider without Preflight/SmokeTest is a no-op success.
	if err := p.EnsureReady(context.Background()); err != nil {
		t.Fatalf("EnsureReady on disabled: %v", err)
	}
}

func TestBuildReturnsResourcesMetadata(t *testing.T) {
	p, err := Build(mapEnv(map[string]string{
		"SANDBOX_PROVIDER":  "wasm",
		"SANDBOX_MEMORY_MB": "128",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if p.Resources.MemoryMB != 128 {
		t.Fatalf("resources = %+v, want MemoryMB 128", p.Resources)
	}
	w, ok := p.Sandbox.(*WasmSandbox)
	if !ok || w.MemoryPages != 128*16 {
		t.Fatalf("wasm memory pages = %+v", p.Sandbox)
	}
}

func TestProviderEnsureReadySurfacesPreflightFailure(t *testing.T) {
	p, err := Build(mapEnv(map[string]string{"SANDBOX_PROVIDER": "e2b"})) // no API key
	if err != nil {
		t.Fatal(err)
	}
	if err := p.EnsureReady(context.Background()); err == nil {
		t.Fatal("EnsureReady succeeded without an E2B API key")
	}
}

func TestPinnedImageBooleanIsStrict(t *testing.T) {
	for raw, want := range map[string]bool{"": false, "0": false, "false": false, "1": true, "TRUE": true} {
		got, err := optionalBoolEnv(mapEnv(map[string]string{"PIN": raw}), "PIN")
		if err != nil || got != want {
			t.Errorf("PIN=%q => (%v, %v), want %v", raw, got, err, want)
		}
	}
	if _, err := optionalBoolEnv(mapEnv(map[string]string{"PIN": "yes"}), "PIN"); err == nil {
		t.Fatal("ambiguous boolean PIN=yes was accepted")
	}
}

func TestBuildConfiguresBothPinnedDockerImages(t *testing.T) {
	const digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	snippet := "registry.example/plimsoll/node@sha256:" + digest
	project := "registry.example/plimsoll/toolchain@sha256:" + digest
	p, err := Build(mapEnv(map[string]string{
		"SANDBOX_PROVIDER":              "docker",
		"SANDBOX_DOCKER_IMAGE":          snippet,
		"SANDBOX_DOCKER_PROJECT_IMAGE":  project,
		"SANDBOX_REQUIRE_PINNED_IMAGES": "1",
	}))
	if err != nil {
		t.Fatal(err)
	}
	d, ok := p.Sandbox.(*DockerSandbox)
	if !ok {
		t.Fatalf("provider = %T, want *DockerSandbox", p.Sandbox)
	}
	if d.Image != snippet || d.ProjectImage != project || !d.RequirePinnedImages {
		t.Fatalf("docker config = image %q, project %q, require-pinned %v", d.Image, d.ProjectImage, d.RequirePinnedImages)
	}
	if !isDigestPinned(d.Image) || !isDigestPinned(d.ProjectImage) {
		t.Fatal("Build produced an image that hardened Preflight would reject")
	}
}
