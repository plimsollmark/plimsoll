package sandbox

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/plimsollmark/plimsoll/internal/settings"
)

// Provider is a checked, constructed execution provider plus the effective
// configuration an embedder needs for wiring that is not derivable from the
// Sandbox itself: the per-run resource envelope (e.g. for sizing a local
// admission budget with WithAdmission, or an RPC limiter's memory clamp).
type Provider struct {
	Sandbox   Sandbox
	Resources Resources
}

// EnsureReady runs the provider's readiness checks — Preflight (configuration/
// dependency evidence) and, when implemented, SmokeTest (behavioral proof via
// throwaway sandboxes) — so a local embedder cannot forget the wiring the daemon
// does at startup. Call it once before serving hostile code; SmokeTest may start
// real sandboxes, so never call this on an unauthenticated poll path.
func (p Provider) EnsureReady(ctx context.Context) error {
	if pf, ok := p.Sandbox.(Preflighter); ok {
		if err := pf.Preflight(ctx); err != nil {
			return fmt.Errorf("sandbox preflight: %w", err)
		}
	}
	if sm, ok := p.Sandbox.(SmokeTester); ok {
		if err := sm.SmokeTest(ctx); err != nil {
			return fmt.Errorf("sandbox smoke test: %w", err)
		}
	}
	return nil
}

// Build selects and constructs the provider named by SANDBOX_PROVIDER, read
// through getenv (nil = os.Getenv). It fails closed: malformed safety
// configuration — an unparseable resource envelope, an invalid boolean, a
// resource dimension the selected provider cannot enforce — is an explicit
// error, never a silently defaulted provider. The default (unset) provider is
// Disabled, so code execution must be turned on deliberately.
//
//	SANDBOX_PROVIDER=docker   # locked-down `docker run` (self-host / dev)
//	SANDBOX_PROVIDER=e2b      # Firecracker microVM (production; see e2b.go)
//	SANDBOX_PROVIDER=dockercloud # Docker Cloud Sandboxes microVM (see dockercloud.go;
//	                             # verified against the live service 2026-09-24)
//	SANDBOX_PROVIDER=wasm     # in-process QuickJS/WASM (snippet-only)
//	unset                     # Disabled: refuses to execute
//	anything else             # an error: an unknown name never falls back to Disabled
//
// The per-run resource envelope (SANDBOX_MEMORY_MB / SANDBOX_CPUS /
// SANDBOX_PIDS / SANDBOX_DISK_MB) is translated into the selected provider's
// enforceable controls and returned as Provider.Resources. E2B verifies its
// template-level live allocation as a maximum after create.
//
// The optional host-API capability (HostAPIGrant) is NOT configured here: it is
// a per-run capability attached to a Request/ProjectRequest (Request.Grant),
// not provider state. Off by default — a run with no grant is fully isolated.
func Build(getenv func(string) string) (Provider, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	res, err := ResourcesFromEnv(getenv)
	if err != nil {
		return Provider{}, err
	}
	// Normalize so casing/whitespace variants from a .env or k8s manifest ("WASM",
	// " docker", "e2b ") select the intended provider instead of silently falling to
	// Disabled. The default branch stays fail-safe: an unknown value never executes.
	raw := settings.Provider.Raw(getenv)
	name := settings.Provider.Get(getenv)
	// A security setting that does nothing must not look applied: only docker picks
	// its guests' uid.
	if settings.GuestUID.Set(getenv) && name != "docker" {
		return Provider{}, fmt.Errorf("SANDBOX_GUEST_UID applies to the docker provider only, not %q: leave it unset", strings.TrimSpace(raw))
	}
	switch name {
	case "docker":
		d := DefaultDocker(settings.DockerImage.Get(getenv))
		if projectImage := settings.DockerProjectImage.Get(getenv); projectImage != "" {
			d.ProjectImage = projectImage
		}
		d.ModuleImage = settings.DockerModuleImage.Get(getenv) // "" = module runs unsupported
		d.Runtime = settings.DockerRuntime.Get(getenv)         // e.g. "runsc" (gVisor); "" = runc
		d.Seccomp = settings.DockerSeccomp.Get(getenv)         // "" = docker default (explicit); path or "unconfined"
		d.SeccompSDK = settings.DockerSeccompSDK.Get(getenv)   // the profile a run whose grant sets sdk_env gets instead; "" = none
		requirePinned, err := settings.RequirePinnedImages.Get(getenv)
		if err != nil {
			return Provider{}, err
		}
		d.RequirePinnedImages = requirePinned
		if raw := settings.GuestUID.Get(getenv); raw != "" {
			uid, err := strconv.Atoi(raw)
			if err != nil {
				return Provider{}, fmt.Errorf("SANDBOX_GUEST_UID %q is not a number", raw)
			}
			if err := validateGuestUID(uid); err != nil {
				return Provider{}, err
			}
			d.GuestUID = uid
		}
		res.applyDocker(d)
		return Provider{Sandbox: d, Resources: res}, nil
	case "e2b":
		e := &E2B{APIKey: settings.E2BAPIKey.Get(getenv), Template: settings.E2BTemplate.Get(getenv), GuardURL: settings.E2BGuardURL.Get(getenv),
			SessionGrants: settings.E2BSessionGrants.Get(getenv)}
		if err := validateE2BSessionGrants(e.SessionGrants, e.GuardURL); err != nil {
			return Provider{}, err
		}
		// E2B sizes resources at template level. Verify the live allocation from the
		// control plane and reject templates that exceed the requested cap; dimensions
		// E2B cannot enforce fail configuration here rather than at first run.
		e.MaxMemoryMB = res.MemoryMB
		e.MaxVCPU = res.CPUs
		e.MaxDiskMB = res.DiskMB
		e.PidsLimit = res.PidsLimit
		if err := e.validateResourceConfig(); err != nil {
			return Provider{}, err
		}
		return Provider{Sandbox: e, Resources: res}, nil
	case "dockercloud":
		d := &DockerCloud{
			Token:      settings.DockerSBXToken.Get(getenv),
			Username:   settings.DockerSBXUsername.Get(getenv),
			AuthURL:    settings.DockercloudAuthURL.Get(getenv),
			API:        settings.DockercloudAPI.Get(getenv),
			APIURL:     settings.DockercloudAPIURL.Get(getenv),
			Image:      settings.DockercloudImage.Get(getenv),
			StoreImage: settings.DockercloudStoreImage.Get(getenv),
			GuardURL:   settings.DockercloudGuardURL.Get(getenv),
			PolicyURL:  settings.DockercloudPolicyURL.Get(getenv),
		}
		requirePinned, err := settings.RequirePinnedImages.Get(getenv)
		if err != nil {
			return Provider{}, err
		}
		d.RequirePinnedImage = requirePinned
		// CPU and memory are requested at create and verified after it; the API has
		// no disk or process-count control, so those dimensions fail here.
		d.MaxMemoryMB = res.MemoryMB
		d.MaxVCPU = res.CPUs
		d.MaxDiskMB = res.DiskMB
		d.PidsLimit = res.PidsLimit
		if err := d.validateConfig(); err != nil {
			return Provider{}, err
		}
		return Provider{Sandbox: d, Resources: res}, nil
	case "wasm":
		w := DefaultWasm()
		res.applyWasm(w)
		if w.configErr != nil {
			return Provider{}, w.configErr
		}
		return Provider{Sandbox: w, Resources: res}, nil
	case "":
		return Provider{Sandbox: Disabled{}, Resources: res}, nil
	default:
		// Set-but-unrecognized: almost certainly a misconfiguration — an operator
		// who meant to enable a provider must not silently get the inert one.
		return Provider{}, fmt.Errorf("SANDBOX_PROVIDER=%q is not recognized (known: %s; unset = disabled)", raw, strings.Join(ProviderNames(), ", "))
	}
}

// ProviderNames lists the SANDBOX_PROVIDER values Build constructs. An embedder that
// constructs further providers itself names its own alongside these.
func ProviderNames() []string { return []string{"wasm", "docker", "e2b", "dockercloud"} }

// ResourcesFromEnv parses the per-run resource envelope (SANDBOX_MEMORY_MB,
// SANDBOX_CPUS, SANDBOX_PIDS, SANDBOX_DISK_MB) exactly as Build does: unset is 0,
// and a malformed or negative value is an error. It is exported for a provider an
// embedder constructs outside Build, which must read the envelope the same way.
func ResourcesFromEnv(getenv func(string) string) (Resources, error) {
	memory, err := settings.MemoryMB.Get(getenv)
	if err != nil {
		return Resources{}, err
	}
	cpus, err := settings.CPUs.Get(getenv)
	if err != nil {
		return Resources{}, err
	}
	pids, err := settings.Pids.Get(getenv)
	if err != nil {
		return Resources{}, err
	}
	disk, err := settings.DiskMB.Get(getenv)
	if err != nil {
		return Resources{}, err
	}
	return Resources{MemoryMB: memory, CPUs: cpus, PidsLimit: pids, DiskMB: disk}, nil
}

// applyDocker translates the envelope into the docker provider's flag strings. Only
// dimensions the operator set (non-zero) override the provider defaults.
func (r Resources) applyDocker(d *DockerSandbox) {
	if r.MemoryMB > 0 {
		d.Memory = fmt.Sprintf("%dm", r.MemoryMB)
	}
	if r.CPUs > 0 {
		d.CPUs = strconv.FormatFloat(r.CPUs, 'f', -1, 64)
	}
	if r.PidsLimit > 0 {
		d.PidsLimit = strconv.Itoa(r.PidsLimit)
	}
	// SANDBOX_DISK_MB is the run's AGGREGATE writable budget, not just /work:
	// /tmp and /dev/shm are writable too, and it is the sum hostile code fills.
	// The provider derives /work from the remainder and fails Preflight if the
	// mounts cannot fit.
	if r.DiskMB > 0 {
		d.DiskBudgetMB = r.DiskMB
	}
}

// applyWasm translates the memory dimension into wazero pages (1 page = 64 KiB, so
// 16 pages per MiB). CPUs/pids/disk have no in-process analogue for wasm.
func (r Resources) applyWasm(w *WasmSandbox) {
	if r.CPUs > 0 || r.PidsLimit > 0 || r.DiskMB > 0 {
		w.configErr = fmt.Errorf("wasm can enforce only SANDBOX_MEMORY_MB; CPU/PID/disk resource caps require docker or e2b")
	}
	if r.MemoryMB > 0 {
		pages := uint64(r.MemoryMB) * 16
		if pages > uint64(wasmMaxPages) {
			pages = uint64(wasmMaxPages)
		}
		w.MemoryPages = uint32(pages)
	}
}

// BoolFromEnv parses an opt-in boolean variable an embedder's own provider reads, by the
// rule every plimsoll boolean setting follows (internal/settings): unset, 0 or false is
// false, 1 or true is true (any case), and anything else is an error, so a typo can
// never silently disable a safety opt-in. It is exported, like ResourcesFromEnv, for a
// provider an embedder constructs outside Build; plimsoll's own code reads each of its
// variables through its setting.
func BoolFromEnv(getenv func(string) string, key string) (bool, error) {
	return settings.ParseBool(key, getenv(key))
}
