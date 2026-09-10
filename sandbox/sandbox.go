// Package sandbox runs untrusted, agent-authored code through an explicitly tiered
// execution provider. It is deliberately transport-agnostic (no Connect/HTTP
// types) so the same providers can back an RPC, a CLI, or a test. Agent code must
// never execute as a native host process. The WASM provider does run its interpreter
// in-process and is therefore only a process-tier boundary; hostile deployments
// should require the verified kernel or VM tiers.
//
// Providers:
//   - WASM     — low-latency in-process QuickJS (process tier).
//   - Docker   — self-hosted locked-down `docker run` (runc or verified runsc).
//   - E2B      — remote Firecracker microVM; see e2b.go.
//   - Disabled — safe default that refuses to execute (returns ErrDisabled).
package sandbox

import (
	"context"
	"errors"
	"time"
)

// ErrDisabled is returned when no execution provider is configured. Callers
// should surface this as a "sandbox not configured" precondition failure, not as
// an internal error.
var ErrDisabled = errors.New("code execution sandbox is not configured")

// ErrUnsupported is returned by a configured provider for an operation it
// structurally cannot perform (e.g. the wasm provider has no toolchain, so it
// cannot run multi-file projects). It is distinct from ErrDisabled (no provider at
// all): callers should surface it as "not implemented by this provider"
// (Unimplemented), not a precondition failure. Providers must return it as a
// returned error, never stuffed into a *Result.Err string, so the signal is
// uniform across providers.
var ErrUnsupported = errors.New("operation not supported by this sandbox provider")

// ErrInsufficientIsolation is returned before dispatch when the selected
// provider's current boundary is weaker than a request's MinimumIsolation. It is
// a deterministic precondition failure: no hostile code ran.
var ErrInsufficientIsolation = errors.New("sandbox isolation requirement not met")

// ErrIsolationEvidenceMismatch is a post-dispatch integrity failure: a remote
// response reported Unknown or weaker isolation than the request required. Unlike
// ErrInsufficientIsolation, execution MAY already have occurred, so callers must
// not automatically retry a non-idempotent run.
var ErrIsolationEvidenceMismatch = errors.New("sandbox result isolation evidence does not meet the request")

// IsolationClass ranks how strong a provider's boundary is around hostile code —
// the single most security-relevant fact about a run, which the provider name
// alone hides ("docker" is a real kernel boundary under gVisor but only
// shared-kernel namespaces under runc). A caller can assert a minimum with Meets
// and refuse a weaker provider; every Result also reports the tier that actually
// ran, so the boundary is never invisible.
type IsolationClass int

const (
	// IsolationUnknown means the tier cannot be determined locally (e.g. a remote
	// plimsolld whose provider is not known here). Meets is always false for it —
	// you cannot statically assert an unknown boundary; read Result.Isolation for
	// the tier a specific run reported.
	IsolationUnknown IsolationClass = iota
	// IsolationNone: no execution boundary — the provider refuses to run (Disabled).
	IsolationNone
	// IsolationProcess: in-process, in the host's own OS process (wasm/WASI). Memory
	// is capped and there are no syscalls beyond WASI, but a runtime escape lands in
	// the host process — not a boundary that survives hostile native code.
	IsolationProcess
	// IsolationContainer: an OS container sharing the host kernel (docker under
	// runc). Namespaces + dropped caps + cgroups, but NOT a hostile-code boundary on
	// its own — a kernel exploit reaches the host.
	IsolationContainer
	// IsolationKernel: a user-space kernel between guest and host (docker under
	// gVisor/runsc). A real boundary against hostile code.
	IsolationKernel
	// IsolationVM: a hardware-virtualized microVM (E2B/Firecracker). The strongest
	// boundary offered here.
	IsolationVM
)

// Meets reports whether this tier is at least as strong as min. An unknown tier
// meets nothing (a remote provider cannot promise a boundary statically).
func (c IsolationClass) Meets(min IsolationClass) bool {
	return c >= IsolationNone && c <= IsolationVM &&
		min >= IsolationNone && min <= IsolationVM && c >= min
}

// String is the stable wire/log name of the tier.
func (c IsolationClass) String() string {
	switch c {
	case IsolationNone:
		return "none"
	case IsolationProcess:
		return "process"
	case IsolationContainer:
		return "container"
	case IsolationKernel:
		return "kernel"
	case IsolationVM:
		return "vm"
	default:
		return "unknown"
	}
}

// ParseIsolationClass maps a wire/log name back to a tier ("" or unrecognized →
// IsolationUnknown). It lets a remote client report the tier the server sent.
func ParseIsolationClass(s string) IsolationClass {
	switch s {
	case "none":
		return IsolationNone
	case "process":
		return IsolationProcess
	case "container":
		return IsolationContainer
	case "kernel":
		return IsolationKernel
	case "vm":
		return IsolationVM
	default:
		return IsolationUnknown
	}
}

// Resources is the requested per-run resource envelope. Build applies enforceable
// dimensions and makes unsupported configured dimensions fail closed. A zero field
// takes that provider's built-in default. Providers must document any semantic gap.
//
// The aggregate host budget is roughly the RPC limiter's max-concurrent times this
// envelope (e.g. 8 concurrent × 256 MiB ≈ 2 GiB RAM): size the two together, since
// a count alone is not a resource budget.
type Resources struct {
	MemoryMB  int     // hard RAM cap per run; 0 = provider default
	CPUs      float64 // CPU cores per run; 0 = provider default
	PidsLimit int     // max processes per run; 0 = provider default
	DiskMB    int     // writable disk/tmpfs cap per run; 0 = provider default
}

// The opt-in host-API capability (HostAPIGrant) lives in capability.go.

// Request is a single execution. Timeout of 0 means "use the provider default".
// Grant, when non-nil, gives this run scoped host-API access (see HostAPIGrant);
// nil keeps the run fully isolated. MinimumIsolation is a per-dispatch security
// floor; Unknown means no request-specific floor.
type Request struct {
	Code             string
	Timeout          time.Duration
	Grant            *HostAPIGrant
	MinimumIsolation IsolationClass // Unknown = no request-specific floor
}

// File is one file written into a project's work dir before steps run.
type File struct {
	Path    string
	Content string
}

// ProjectRequest runs a multi-file project: write Files, then run Steps in order
// (stopping on the first failure). Timeout is the total wall-clock budget.
// Artifacts lists relative file paths to capture and return after the run.
// MinimumIsolation has the same semantics as Request.MinimumIsolation.
type ProjectRequest struct {
	Files            []File
	Steps            []string
	Timeout          time.Duration
	Artifacts        []string
	Grant            *HostAPIGrant  // optional per-run scoped host-API access; nil = isolated
	MinimumIsolation IsolationClass // Unknown = no request-specific floor
}

// Artifact is an output file captured after a run (binary-safe).
type Artifact struct {
	Path    string
	Content []byte
}

// StepResult is the outcome of one project step. StdoutTruncated/StderrTruncated
// report that the sandbox's output cap dropped bytes from that stream; the
// retained prefix is returned unmarked, so the flag is the only truncation signal.
type StepResult struct {
	Command         string
	Stdout          string
	Stderr          string
	StdoutTruncated bool
	StderrTruncated bool
	ExitCode        int
	TimedOut        bool
	Duration        time.Duration
}

// ProjectOutcome classifies the top-level completion of a project run so callers
// can make retry/status decisions without parsing failure strings. It reports how
// the RUN concluded, not whether the user's steps passed: per-step failures live
// in ProjectResult.Steps.
type ProjectOutcome int

const (
	// ProjectOutcomeUnspecified is the zero value. It never accompanies a nil
	// error: a provider that returns a ProjectResult without an error must set a
	// real outcome.
	ProjectOutcomeUnspecified ProjectOutcome = iota
	// ProjectOutcomeCompleted: the runner executed the plan to its normal
	// conclusion (stop on first failing step included). Inspect Steps for the
	// user's build/lint/run results.
	ProjectOutcomeCompleted
	// ProjectOutcomeSetupFailed: the run failed around step execution for a
	// request-attributable reason the runner itself reported — an illegal file
	// path, an unwritable file, or a result exceeding the response budget.
	// Retrying without changing the request will fail again.
	ProjectOutcomeSetupFailed
	// ProjectOutcomeTimedOut: the outer wall-clock budget expired before the
	// runner reported. Steps may be partial or missing.
	ProjectOutcomeTimedOut
	// ProjectOutcomeProtocolError: the sandbox produced no parseable result, so
	// the execution state is unknown — the boundary launched but the runner never
	// reported (e.g. it was OOM-killed inside the sandbox, or its output was cut).
	// Retry only if the project is idempotent.
	ProjectOutcomeProtocolError
)

// String is the stable wire/log name of the outcome.
func (o ProjectOutcome) String() string {
	switch o {
	case ProjectOutcomeCompleted:
		return "completed"
	case ProjectOutcomeSetupFailed:
		return "setup_failed"
	case ProjectOutcomeTimedOut:
		return "timed_out"
	case ProjectOutcomeProtocolError:
		return "protocol_error"
	default:
		return "unspecified"
	}
}

// ProjectResult is the outcome of a project run. Per-step failures live in Steps;
// Outcome types the top-level conclusion (Detail carries human-readable context
// for a non-completed outcome). Pre-dispatch validation/capability/admission
// failures and infrastructure faults are returned as Go errors instead.
// ArtifactsTruncated reports that the aggregate artifact byte budget dropped one
// or more requested artifacts that existed.
type ProjectResult struct {
	Steps              []StepResult
	Sandbox            string
	Isolation          IsolationClass // boundary tier this run executed behind
	Outcome            ProjectOutcome
	Detail             string // context for a non-completed Outcome; "" when completed
	Artifacts          []Artifact
	ArtifactsTruncated bool
	// CallTrace is bounded, metadata-only evidence of the host.* calls this project
	// run's broker served (route templates, methods, sizes, timings), mirroring
	// Result.CallTrace. Non-nil only when the run carried a host-API grant that made
	// calls, and purely advisory: it never changes Steps, Outcome, or Isolation.
	CallTrace *CallTrace
}

// Result is the outcome of an execution. A non-zero ExitCode is a normal guest
// result, not a Go error. A returned error means no ordinary guest result is
// available: callers should classify ErrInvalidRequest, ErrUnsupported,
// ErrDisabled, ErrAtCapacity, ErrInsufficientIsolation,
// ErrIsolationEvidenceMismatch, and context
// cancellation/deadline with errors.Is; unmatched errors are infrastructure
// failures. StdoutTruncated/StderrTruncated report that the output cap dropped
// bytes; the retained prefix is returned unmarked.
type Result struct {
	Stdout          string
	Stderr          string
	StdoutTruncated bool
	StderrTruncated bool
	ExitCode        int
	TimedOut        bool
	Duration        time.Duration
	Sandbox         string
	Isolation       IsolationClass // boundary tier this run executed behind
	// CallTrace is bounded, metadata-only evidence of the host.* calls this run's
	// broker served (route templates, methods, sizes, timings). It is non-nil only
	// when the run carried a host-API grant that made calls, and is purely advisory:
	// it never changes ExitCode, Stdout/Stderr, or Isolation.
	CallTrace *CallTrace
}

// Sandbox is an isolated code runner.
type Sandbox interface {
	// RunJavaScript executes JavaScript in the provider's engine (Node or QuickJS)
	// and returns its captured output. Implementations must enforce a non-Unknown
	// MinimumIsolation against the boundary actually selected for this dispatch.
	RunJavaScript(ctx context.Context, req Request) (Result, error)
	// RunProject writes a multi-file project and runs build/lint/run steps, with the
	// same per-dispatch MinimumIsolation enforcement as RunJavaScript.
	RunProject(ctx context.Context, req ProjectRequest) (ProjectResult, error)
	// Name identifies the provider (e.g. "docker").
	Name() string
	// IsolationClass reports the strength of this provider's boundary around
	// hostile code, so a caller can assert a minimum (see IsolationClass.Meets)
	// instead of trusting the provider name. For docker this depends on the OCI
	// runtime (gVisor vs runc); providers report their own tier.
	IsolationClass() IsolationClass
}

// ProjectCapable is an optional interface a provider implements to declare
// statically whether RunProject works (the wasm provider has no toolchain, so it
// cannot). The RPC server surfaces it via the Describe RPC; a remote caller asks
// the server rather than asserting locally, so treat "not implemented" as false.
type ProjectCapable interface {
	SupportsProjects() bool
}

// GrantCapable declares which operations can enforce HostAPIGrant without exposing
// credentials or silently dropping the SDK contract. Capability support is
// operation-specific: Docker brokers both snippets and projects, WASM rejects both,
// and E2B supports both only with its configured host-side egress guard. The RPC
// Describe method reports these facts so callers can fail before dispatch.
type GrantCapable interface {
	SupportsJavaScriptGrants() bool
	SupportsProjectGrants() bool
}

// EgressGuardResponse is the bounded result returned by a provider's remote
// egress guard. It deliberately contains only the upstream status, content type,
// and body; transport headers, redirects, cookies, and credentials never cross
// into the guest.
type EgressGuardResponse struct {
	Status      int
	ContentType string
	Body        []byte
}

// E2BGuardHeader is the header E2B injects outside the guest when its beta
// per-host transform is configured. The value is a per-run guard credential,
// not the customer API credential.
const E2BGuardHeader = "X-Plimsoll-E2B-Guard"

// EgressGuardCapable is the transport-neutral seam used by a daemon or another
// embedder to expose an E2B provider's per-run guard over its chosen HTTP server.
// The adapter owns HTTP framing and limits; the provider owns the guard token,
// broker session, route enforcement, and credential injection.
//
// This interface intentionally carries no net/http types so sandbox remains
// reusable by non-HTTP embedders.
type EgressGuardCapable interface {
	EgressGuardPath() string
	EgressGuardCall(ctx context.Context, token, method, rawTarget string, body []byte) EgressGuardResponse
}

// Preflighter is an optional interface a provider implements to report whether its
// external dependencies are ready (an API key present, a daemon/runtime reachable)
// WITHOUT running untrusted code. The server runs it at startup (fail-fast) and
// serves it at /readyz, so a misconfigured provider — an unset E2B key, a missing
// runsc — is caught before traffic rather than failing every request. It must be a
// cheap, internally bounded diagnostic. Providers with no external dependency may
// omit it.
type Preflighter interface {
	Preflight(ctx context.Context) error
}

// OrphanReconciler is an optional interface a provider implements when its
// execution resources live off-process (remote microVMs) and can therefore leak
// past the per-run lifecycle — a create acknowledgement whose ID never arrived,
// or a teardown whose retries all failed. ReconcileOrphans finds resources this
// provider instance created but no longer tracks and destroys them, returning
// how many were destroyed. The daemon runs it periodically in the background;
// it must never destroy resources belonging to other instances.
type OrphanReconciler interface {
	ReconcileOrphans(ctx context.Context) (int, error)
}

// SmokeTester is an optional interface a provider implements to prove, by
// actually exercising the exact configured execution stack (image, runtime,
// profile), that its promised run-time bounds are in force — behavior, where
// Preflight checks configuration. It may start real (throwaway) sandboxes, so
// the server runs it once at startup, never on unauthenticated poll paths.
type SmokeTester interface {
	SmokeTest(ctx context.Context) error
}
