package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/plimsollmark/plimsoll/internal/settings"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// providerDescriptor is what plimsolld knows about one SANDBOX_PROVIDER value, in one
// place: how it is built, its help section, and hardened mode's requirements for it.
// Every provider has one; a name without one cannot be selected, so a provider added
// to sandbox.Build without its hardened rules fails startup and its test instead of
// running under the generic checks alone. These facts once lived in four places (Build's
// switch, a map for the daemon-built providers, a hardened switch with no default and
// the startup log's per-provider wording; review D3, 2026-10-23).
type providerDescriptor struct {
	// build constructs the provider from the environment; nil uses sandbox.Build. A
	// daemon-built provider sets it: one whose dependencies must not reach every program
	// that imports package sandbox, such as generated protocol code that registers
	// protobuf names another SDK also registers (protobuf-go panics at start on a
	// duplicate). Each registers from its own file, so that file's presence decides
	// whether a build has the provider.
	build func(getenv func(string) string) (sandbox.Provider, error)
	// hardenedEnvelope is the resource envelope hardened mode requires for the
	// provider: every dimension it enforces and none its configuration rejects.
	hardenedEnvelope []settings.Size
	// hardenedEnvelopeAt adds, once the tier is proven (the pass after the smoke test),
	// what the provider enforces only at that tier; nil adds nothing.
	hardenedEnvelopeAt func(sandbox.IsolationClass) []settings.Size
	// pinnedImages makes hardened mode require SANDBOX_REQUIRE_PINNED_IMAGES=1.
	pinnedImages bool
	// guestGuard makes hardened mode require, once the smoke test has run, that the provider
	// states plimsoll's guest guard proven in force (sandbox.GuestGuarded): the filter in front
	// of every program it starts in a sandbox. Set for each provider whose commands start
	// behind the guard (docker today; the guard's design, step 4, adds the others).
	guestGuard bool
	// hardened checks the provider's own hardened-mode rules (its immutable execution
	// surface), calling fail, or bad with an unreadable setting, for each violation.
	hardened func(getenv func(string) string, fail func(string, ...any), bad func(error))
	// remoteMemory: runs draw on another machine's memory, so SANDBOX_TOTAL_MEMORY_MB
	// does not clamp this daemon's concurrency.
	remoteMemory bool
	// tierFromChecks reports whether the provider's startup checks (Preflight, then the
	// smoke test) establish its tier, so it is not known from its configuration alone.
	// plimsolld holds SANDBOX_MIN_ISOLATION against every other provider's tier before
	// anything starts work, and against these only after the checks. nil: the tier is
	// known from configuration, which is the strict default, since a provider wrongly
	// left nil is refused at startup rather than started.
	tierFromChecks func(sb sandbox.Sandbox) bool
	// resourceLog is the startup log's account of the resource envelope; nil logs the
	// envelope as enforced on each run.
	resourceLog func(sb sandbox.Sandbox, res sandbox.Resources) []any
}

// providers maps a SANDBOX_PROVIDER value to its descriptor: sandbox.Build's providers
// here, the daemon-built ones from their own files.
var providers = map[string]providerDescriptor{
	"docker": {
		hardenedEnvelope: hardenedEnvelopeFor["docker"],
		guestGuard:       true,
		hardened: func(getenv func(string) string, fail func(string, ...any), bad func(error)) {
			pinned, err := settings.RequirePinnedImages.Get(getenv)
			if err != nil {
				bad(err)
			} else if !pinned {
				fail("hardened mode requires SANDBOX_REQUIRE_PINNED_IMAGES=1 so every configured docker image is an immutable @sha256 digest (a mutable tag can be repushed under you)")
			}
			// The vm/kernel requirement already forces runsc, whose user-space kernel does
			// its own syscall interception (the host seccomp profile is deliberately not
			// applied under runsc; see lockdownArgs). Only an operator explicitly
			// signalling seccomp-off intent is rejected here.
			if settings.DockerSeccomp.Get(getenv) == "unconfined" {
				fail("hardened mode forbids SANDBOX_DOCKER_SECCOMP=unconfined")
			}
			if settings.DockerSeccompSDK.Get(getenv) == "unconfined" {
				fail("hardened mode forbids SANDBOX_DOCKER_SECCOMP_SDK=unconfined")
			}
		},
		// Under runsc the tier is kernel only once Preflight has verified that the daemon
		// registers runsc (DockerSandbox.IsolationClass); under any other runtime it is
		// container whatever the checks find.
		tierFromChecks: func(sb sandbox.Sandbox) bool {
			d, ok := sb.(*sandbox.DockerSandbox)
			return !ok || d.Runtime == "runsc"
		},
	},
	"dockercloud": {
		hardenedEnvelope: hardenedEnvelopeFor["dockercloud"],
		hardened: func(getenv func(string) string, fail func(string, ...any), bad func(error)) {
			// The sandbox boots a raw OCI reference, so the same pinning rule as docker
			// applies: a mutable tag could be repushed under a running deployment. A
			// store image (SANDBOX_DOCKERCLOUD_STORE_IMAGE) always carries its digest,
			// checked against every sandbox's booted digest, so it needs no flag.
			pinned, err := settings.RequirePinnedImages.Get(getenv)
			if err != nil {
				bad(err)
			} else if !pinned && settings.DockercloudStoreImage.Get(getenv) == "" {
				fail("hardened mode requires SANDBOX_REQUIRE_PINNED_IMAGES=1 so SANDBOX_DOCKERCLOUD_IMAGE is an immutable @sha256 digest")
			}
			// A pin is only evidence where the API reports the digest each sandbox
			// booted; the REST API reports none, so the API must be named, not left to
			// the default (Connect, today).
			if settings.DockercloudAPI.Get(getenv) != "connect" {
				fail("hardened mode requires SANDBOX_DOCKERCLOUD_API=connect, named rather than left to the default: the REST API does not report which image a sandbox booted, so the pinned image cannot be proven")
			}
		},
		remoteMemory: true,
		resourceLog: func(sb sandbox.Sandbox, res sandbox.Resources) []any {
			var args []any
			if dc, ok := sb.(*sandbox.DockerCloud); ok {
				args = append(args, "api", dc.APIName())
			}
			return append(args,
				"resources", "requested at create and verified after it; 0 = backend default",
				"max_mem_mb", res.MemoryMB,
				"max_cpus", res.CPUs,
				"disk_and_pids", "unsupported (non-zero fails startup)",
			)
		},
	},
	"e2b": {
		hardenedEnvelope: hardenedEnvelopeFor["e2b"],
		hardened: func(getenv func(string) string, fail func(string, ...any), _ func(error)) {
			// E2B offers no digest pinning; an explicit template (never the implicit
			// "base" default) is the strongest surface selection available. The startup
			// SmokeTest then proves that template behaves.
			if settings.E2BTemplate.Get(getenv) == "" {
				fail("hardened mode requires an explicit E2B_TEMPLATE (the implicit \"base\" default is not a pinned execution surface)")
			}
		},
		remoteMemory: true,
		resourceLog: func(_ sandbox.Sandbox, res sandbox.Resources) []any {
			return []any{
				"resources", "template-managed; configured values are post-create maxima",
				"max_mem_mb", res.MemoryMB,
				"max_cpus", res.CPUs,
				"max_disk_mb", res.DiskMB,
				"pids", "unsupported (non-zero fails startup)",
			}
		},
	},
	// wasm is in-process: hardened mode refuses its tier before any rule here applies.
	"wasm": {hardenedEnvelope: hardenedEnvelopeDefault},
}

// daemonProviderNames are the daemon-built providers, the ones with their own build.
func daemonProviderNames() []string {
	var names []string
	for name, d := range providers {
		if d.build != nil {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// buildProvider constructs the provider SANDBOX_PROVIDER names: a daemon-built one
// through its own constructor, any other through sandbox.Build. A name with no
// descriptor is refused here, naming every provider this build has, since Build's own
// refusal would list only its own.
func buildProvider(getenv func(string) string) (sandbox.Provider, error) {
	raw := settings.Provider.Raw(getenv)
	name := settings.Provider.Get(getenv)
	d, ok := providers[name]
	switch {
	case name == "":
		return sandbox.Build(getenv) // disabled
	case !ok:
		return sandbox.Provider{}, fmt.Errorf("SANDBOX_PROVIDER=%q is not recognized (known: %s; unset = disabled)",
			raw, strings.Join(append(sandbox.ProviderNames(), daemonProviderNames()...), ", "))
	case d.build != nil:
		return d.build(getenv)
	}
	return sandbox.Build(getenv)
}

// helpText is what -h prints: the table of settings (internal/settings), with every
// provider this build has in the SANDBOX_PROVIDER line and a section for each
// daemon-built provider it has.
func helpText() string {
	return settings.Help(append(sandbox.ProviderNames(), daemonProviderNames()...), hasProvider)
}

// hasProvider reports whether this build can build the named provider.
func hasProvider(name string) bool {
	_, ok := providers[name]
	return ok
}
