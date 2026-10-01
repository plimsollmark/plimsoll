package sandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestWasmStatesItsInterpreterByHash(t *testing.T) {
	sum := sha256.Sum256(qjsWasm)
	env := DefaultWasm().Environments()
	if want := "quickjs-wasm:sha256:" + hex.EncodeToString(sum[:]); env.JavaScript.Identity != want {
		t.Fatalf("identity = %q, want %q", env.JavaScript.Identity, want)
	}
	if env.JavaScript.MaxTimeout != wasmMaxTimeout {
		t.Fatalf("ceiling = %v, want %v", env.JavaScript.MaxTimeout, wasmMaxTimeout)
	}
	if !reflect.DeepEqual(env.Project, PayloadEnvironment{}) || !reflect.DeepEqual(env.Module, PayloadEnvironment{}) {
		t.Fatalf("wasm runs no projects or modules, yet states %+v", env)
	}
}

// Docker names each kind by the image ID Preflight verified, and only after it
// has: a configured tag is not an identity. The stated ceiling is the one the
// timeout clamp applies.
func TestDockerStatesVerifiedImageIDs(t *testing.T) {
	d := DefaultDocker("node:22-alpine")
	d.MaxProjectTime = 90 * time.Second
	env := d.Environments()
	if env.JavaScript.Identity != "" || env.Project.Identity != "" {
		t.Fatalf("identity stated before Preflight: %+v", env)
	}
	if env.JavaScript.MaxTimeout != d.snippetTimeout(time.Hour) || env.Project.MaxTimeout != 90*time.Second {
		t.Fatalf("ceilings %+v differ from what the clamp applies", env)
	}
	if !reflect.DeepEqual(env.Module, PayloadEnvironment{}) {
		t.Fatalf("module stated with no module image: %+v", env.Module)
	}

	d.ModuleImage = "plimsoll/sandbox-sim:latest"
	d.ready, d.daemonHost = true, "unix:///var/run/docker.sock"
	d.verifiedImageIDs = map[string]string{d.Image: "sha256:aa", d.ProjectImage: "sha256:bb", d.ModuleImage: "sha256:cc"}
	env = d.Environments()
	if env.JavaScript.Identity != "docker-image:sha256:aa" || env.Project.Identity != "docker-image:sha256:bb" ||
		env.Module.Identity != "docker-image:sha256:cc" || env.Module.MaxTimeout != env.Project.MaxTimeout {
		t.Fatalf("after Preflight: %+v", env)
	}
}

func TestCloudProvidersStateOnlyContentAddressedIdentity(t *testing.T) {
	e := &E2B{Template: "base"}
	if env := e.Environments(); env.JavaScript.Identity != "" || env.JavaScript.MaxTimeout != 120*time.Second || !reflect.DeepEqual(env.Module, PayloadEnvironment{}) {
		t.Fatalf("e2b: %+v (a template name is not an identity)", env)
	}

	digest := strings.Repeat("AB", 32)
	dc := &DockerCloud{Image: "example/sandbox:1", MaxTimeout: time.Minute}
	if env := dc.Environments(); env.Project.Identity != "" || env.Project.MaxTimeout != time.Minute {
		t.Fatalf("dockercloud tag: %+v", env)
	}
	dc.Image = "example/sandbox@sha256:" + digest
	want := "dockercloud-image:sha256:" + strings.ToLower(digest)
	if env := dc.Environments(); env.JavaScript.Identity != want || env.Project.Identity != want {
		t.Fatalf("dockercloud digest: %+v, want %q", env, want)
	}
}

func TestAdmissionForwardsEnvironments(t *testing.T) {
	sb, err := WithAdmission(DefaultWasm(), AdmissionConfig{MaxConcurrent: 1})
	if err != nil {
		t.Fatal(err)
	}
	d, ok := sb.(Describer)
	if !ok || !reflect.DeepEqual(d.Environments(), DefaultWasm().Environments()) {
		t.Fatal("admission hid the wrapped provider's statement")
	}
	disabled, err := WithAdmission(Disabled{}, AdmissionConfig{MaxConcurrent: 1})
	if err != nil {
		t.Fatal(err)
	}
	if env := disabled.(Describer).Environments(); !reflect.DeepEqual(env, Environments{}) {
		t.Fatalf("a provider that states nothing gained a statement: %+v", env)
	}
}
