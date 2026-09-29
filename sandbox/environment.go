package sandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"time"
)

// PayloadEnvironment is what a provider states about where one payload kind runs.
// It is a configuration statement for a caller or router choosing among backends,
// never runtime attestation, and nothing enforces it: the isolation tier and the
// per-run checks are what bound a run.
type PayloadEnvironment struct {
	// Identity names the exact outer image artifact or embedded interpreter.
	// An OCI index can change with attached build metadata while its selected
	// executable manifest stays the same. A mutable tag is never reported.
	Identity string
	// SoftwareIdentity names the selected executable image manifest and platform,
	// separately from the outer image index in Identity. Empty means the provider
	// cannot establish the selected artifact. This is evidence, not attestation.
	SoftwareIdentity string
	// MaxTimeout is the provider's own ceiling on one run of this kind: a longer
	// requested timeout is cut to it. 0 means the kind is unsupported or the
	// provider does not state a ceiling.
	MaxTimeout time.Duration
}

// Environments is a provider's statement for each payload kind. A kind the
// provider does not run is the zero PayloadEnvironment.
type Environments struct {
	JavaScript PayloadEnvironment
	Project    PayloadEnvironment
	Module     PayloadEnvironment
	// Policy names the sandbox policy the provider verifies before every run, by a
	// content digest prefixed with how it was derived; "" when the provider has no
	// such object. Like Identity, equal strings mean the same policy.
	Policy string
}

// Describer is the optional interface through which a provider states its
// Environments. Describe reports it; the RPC edge also uses SoftwareIdentity
// for admission before dispatch. A provider that does not implement it states
// nothing and cannot satisfy a required software rule.
type Describer interface {
	Environments() Environments
}

// quickJSIdentity names the embedded interpreter by its content, computed once.
var quickJSIdentity = sync.OnceValue(func() string {
	sum := sha256.Sum256(qjsWasm)
	return "quickjs-wasm:sha256:" + hex.EncodeToString(sum[:])
})

// Environments states the embedded interpreter by hash. Projects and modules are
// unsupported on wasm.
func (w *WasmSandbox) Environments() Environments {
	return Environments{JavaScript: PayloadEnvironment{Identity: quickJSIdentity(), MaxTimeout: w.maxTimeout()}}
}

// Environments states the Preflight-verified content ID of each image a run of
// that kind launches. Before Preflight has verified the current configuration the
// identities are empty (the ceilings are configuration and are always stated).
// A module run goes through the project path, so it shares the project ceiling.
func (d *DockerSandbox) Environments() Environments {
	snippet, project := d.snippetCeiling(), d.projectCeiling()
	env := Environments{
		JavaScript: PayloadEnvironment{MaxTimeout: snippet},
		Project:    PayloadEnvironment{MaxTimeout: project},
	}
	if d.ModuleImage != "" {
		env.Module.MaxTimeout = project
	}
	if state, err := d.executionState(); err == nil {
		env.JavaScript.Identity = dockerImageIdentity(state.imageID)
		env.Project.Identity = dockerImageIdentity(state.projectImageID)
		env.Module.Identity = dockerImageIdentity(state.moduleImageID)
		env.JavaScript.SoftwareIdentity = state.imageManifest
		env.Project.SoftwareIdentity = state.projectManifest
		env.Module.SoftwareIdentity = state.moduleManifest
	}
	return env
}

func dockerImageIdentity(id string) string {
	if id == "" {
		return ""
	}
	return "docker-image:" + id
}

// Environments states the E2B ceilings only. A template is addressed by name and
// can be rebuilt under the same name, so it is not an identity.
func (e *E2B) Environments() Environments {
	ceiling := runCeiling(e.MaxTimeout)
	return Environments{
		JavaScript: PayloadEnvironment{MaxTimeout: ceiling},
		Project:    PayloadEnvironment{MaxTimeout: ceiling},
	}
}

// Environments states the image digest when the image is pinned by one (each run
// verifies that the booted digest matches it); a tag is not an identity.
func (d *DockerCloud) Environments() Environments {
	identity := ""
	if image := strings.TrimSpace(d.Image); isDigestPinned(image) {
		identity = "dockercloud-image:" + strings.ToLower(image[strings.LastIndex(image, "@")+1:])
	}
	ceiling := runCeiling(d.MaxTimeout)
	return Environments{
		JavaScript: PayloadEnvironment{Identity: identity, MaxTimeout: ceiling},
		Project:    PayloadEnvironment{Identity: identity, MaxTimeout: ceiling},
	}
}
