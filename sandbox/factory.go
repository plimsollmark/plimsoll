package sandbox

import (
	"context"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
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
//	SANDBOX_PROVIDER=wasm     # in-process QuickJS/WASM (snippet-only)
//	unset / anything else     # Disabled: refuses to execute
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
	res, err := resourcesFromEnv(getenv)
	if err != nil {
		return Provider{}, err
	}
	// Normalize so casing/whitespace variants from a .env or k8s manifest ("WASM",
	// " docker", "e2b ") select the intended provider instead of silently falling to
	// Disabled. The default branch stays fail-safe: an unknown value never executes.
	raw := getenv("SANDBOX_PROVIDER")
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "docker":
		d := DefaultDocker(getenv("SANDBOX_DOCKER_IMAGE"))
		if projectImage := getenv("SANDBOX_DOCKER_PROJECT_IMAGE"); projectImage != "" {
			d.ProjectImage = projectImage
		}
		d.ModuleImage = getenv("SANDBOX_DOCKER_MODULE_IMAGE") // "" = module runs unsupported
		d.Runtime = getenv("SANDBOX_DOCKER_RUNTIME")          // e.g. "runsc" (gVisor); "" = runc
		d.Seccomp = getenv("SANDBOX_DOCKER_SECCOMP")          // "" = docker default (explicit); path or "unconfined"
		requirePinned, err := optionalBoolEnv(getenv, "SANDBOX_REQUIRE_PINNED_IMAGES")
		if err != nil {
			return Provider{}, err
		}
		d.RequirePinnedImages = requirePinned
		res.applyDocker(d)
		return Provider{Sandbox: d, Resources: res}, nil
	case "e2b":
		e := &E2B{APIKey: getenv("E2B_API_KEY"), Template: getenv("E2B_TEMPLATE"), GuardURL: getenv("E2B_GUARD_URL")}
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
		return Provider{}, fmt.Errorf("SANDBOX_PROVIDER=%q is not recognized (known: docker, e2b, wasm; unset = disabled)", raw)
	}
}

func resourcesFromEnv(getenv func(string) string) (Resources, error) {
	memory, err := nonNegativeIntEnv(getenv, "SANDBOX_MEMORY_MB")
	if err != nil {
		return Resources{}, err
	}
	cpus, err := nonNegativeFloatEnv(getenv, "SANDBOX_CPUS")
	if err != nil {
		return Resources{}, err
	}
	pids, err := nonNegativeIntEnv(getenv, "SANDBOX_PIDS")
	if err != nil {
		return Resources{}, err
	}
	disk, err := nonNegativeIntEnv(getenv, "SANDBOX_DISK_MB")
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

func nonNegativeIntEnv(getenv func(string) string, key string) (int, error) {
	raw := strings.TrimSpace(getenv(key))
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%s=%q must be a non-negative integer", key, raw)
	}
	return n, nil
}

func nonNegativeFloatEnv(getenv func(string) string, key string) (float64, error) {
	raw := strings.TrimSpace(getenv(key))
	if raw == "" {
		return 0, nil
	}
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil || f < 0 || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, fmt.Errorf("%s=%q must be a finite non-negative number", key, raw)
	}
	return f, nil
}

func optionalBoolEnv(getenv func(string) string, key string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(getenv(key))) {
	case "", "0", "false":
		return false, nil
	case "1", "true":
		return true, nil
	default:
		return false, fmt.Errorf("%s must be one of 0, 1, false, or true", key)
	}
}
