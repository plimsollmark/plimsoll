package sandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox/internal/providerkit"
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
	// Languages are the interpreters this environment runs, as the provider's startup
	// checks proved them: the languages a project's steps can invoke, and on a
	// provider with sessions the languages a cell may use. Empty when none is proved.
	Languages []Language
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

// GuestGuarded is the optional interface through which a provider states whether its last
// startup smoke test proved plimsoll's guest guard in force (the filter in front of every program
// plimsoll starts in a sandbox, which refuses the requests that make a namespace or a mount,
// clone3 and tracing: docs/seccomp.md), and the guest guard's word in its policy. Hardened mode
// refuses to serve a provider that must state it and has not proved it (plimsolld's provider
// table). Informational otherwise, like the tier.
type GuestGuarded interface {
	GuestGuard() (policy string, proven bool)
}

// Qualifier is the optional interface through which a provider states the sentence that
// goes with its tier wherever the tier is stated. Describe reports it as
// isolation_qualification, and every run's answer and its record (version 5) state it
// beside that run's tier; a provider that does not implement it, or returns "", has none.
// Informational, like the tier. It must pass record.ValidQualification (at most 1024
// bytes of UTF-8, no control or bidirectional format character), or plimsolld refuses
// to start and a call is refused before it runs.
type Qualifier interface {
	Qualification() string
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
		// The seccomp profile runs apply, by digest, and the variant a run whose grant
		// sets sdk_env gets instead (docker_seccomp.go), then the guest guard every
		// command starts behind (withGuard); each run's record names the profile it
		// applied and the guard.
		env.Policy = state.withGuard(state.seccomp.describe(state.runtime))
	}
	d.stateMu.RLock()
	env.Project.Languages = slices.Clone(d.projectLanguages)
	d.stateMu.RUnlock()
	return env
}

func dockerImageIdentity(id string) string {
	if id == "" {
		return ""
	}
	return "docker-image:" + id
}

// Environments states the E2B ceilings and the languages the smoke test proved. A
// template is addressed by name and can be rebuilt under the same name, so it is not
// an identity.
func (e *E2B) Environments() Environments {
	ceiling := runCeiling(e.MaxTimeout)
	langs := e.languages()
	return Environments{
		JavaScript: PayloadEnvironment{MaxTimeout: ceiling, Languages: langs},
		Project:    PayloadEnvironment{MaxTimeout: ceiling, Languages: langs},
	}
}

// Environments states the image digest when the image is pinned by one and the API
// reports the digest each sandbox booted, so every run verifies it (Connect); a tag is
// not an identity. The REST API reports no booted digest, so there a pin is what was
// asked for, not evidence, and no identity is stated: a caller's software rule then
// fails closed, as on E2B.
func (d *DockerCloud) Environments() Environments {
	identity := ""
	if digest, pinned := providerkit.PinnedDigest(strings.TrimSpace(d.Image)); pinned && !d.rest() {
		identity = "dockercloud-image:" + digest
	}
	ceiling := runCeiling(d.MaxTimeout)
	langs := d.languages()
	return Environments{
		JavaScript: PayloadEnvironment{Identity: identity, MaxTimeout: ceiling, Languages: langs},
		Project:    PayloadEnvironment{Identity: identity, MaxTimeout: ceiling, Languages: langs},
	}
}
