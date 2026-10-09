package rpc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1/plimsollv1connect"
	"github.com/plimsollmark/plimsoll/internal/grants"
	"github.com/plimsollmark/plimsoll/internal/softwarewire"
	"github.com/plimsollmark/plimsoll/protocol"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
)

const (
	// maxRunTimeout is a hard defense-in-depth ceiling applied at the RPC edge,
	// independent of each provider's own clamp. timeout_ms is attacker-controlled
	// (proto int32, up to ~24.8 days), and a provider built without a MaxTimeout —
	// a zero-value WasmSandbox, or e2b via Build — would otherwise honor an
	// arbitrary multi-day budget. For in-process wasm that pins host RAM for the
	// whole run. Bounding it here means no single provider is the only backstop.
	maxRunTimeout = 5 * time.Minute
)

// clampTimeoutMs converts an attacker-supplied timeout_ms to a Duration and caps it
// at maxRunTimeout. A non-positive value passes through as 0 so the provider applies
// its own default (every provider treats <= 0 as "use default").
func clampTimeoutMs(ms int32) time.Duration {
	d := time.Duration(ms) * time.Millisecond
	if d < 0 {
		d = 0
	}
	if d > maxRunTimeout {
		d = maxRunTimeout
	}
	return d
}

// runContext passes the RPC ceiling to the provider as a context deadline even
// when its own timeout fields are unconfigured. It stops only providers that
// honor ctx; a provider that ignores ctx may keep the handler running.
func runContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, maxRunTimeout)
}

// parseMinimumIsolation keeps the empty wire value distinct from an invalid
// floor. "none" is deliberately rejected: requesting no boundary is not a
// meaningful security floor and would make a likely configuration mistake pass.
func parseMinimumIsolation(raw string) (sandbox.IsolationClass, error) {
	if raw == "" {
		return sandbox.IsolationUnknown, nil
	}
	minimum := sandbox.ParseIsolationClass(raw)
	if minimum < sandbox.IsolationProcess || minimum > sandbox.IsolationVM {
		return sandbox.IsolationUnknown, fmt.Errorf("%w: minimum_isolation must be empty or one of process, container, kernel, or vm", sandbox.ErrInvalidRequest)
	}
	return minimum, nil
}

// SandboxService implements the SandboxService RPC by delegating to a
// sandbox.Sandbox. It validates and bounds requests, then maps results to/from
// the proto types. The sandbox provider is chosen at construction (sandbox.Build).
type SandboxService struct {
	plimsollv1connect.UnimplementedSandboxServiceHandler
	Sandbox sandbox.Sandbox
	Limiter *CodeLimiter // optional; nil = unlimited
	// Spend bounds the daily use of a metered provider, per caller and in total
	// (spend.go); nil = no bound.
	Spend  *SpendCap
	Grants *grants.Registry // optional; nil/empty = no host-API profiles
	Logger *slog.Logger     // optional; nil = slog.Default()
	// Resources is the per-run envelope the provider was built with, reported by
	// Describe (sandbox.Build returns it as Provider.Resources). Zero = not stated.
	Resources sandbox.Resources
	// Sessions is the operator's session settings; the zero value keeps sessions off.
	Sessions SessionConfig
	sessions sessionRegistry

	// run counters for /metrics (design-review #9). A non-zero user exit is a normal
	// result, not a failure; runsFailed counts only infrastructure errors.
	runsTotal  atomic.Int64
	runsFailed atomic.Int64

	// hostCalls aggregates per-run CallTraces into labeled host-API call/latency
	// metrics (Prospector Phase 0). The zero value is ready to use.
	hostCalls hostCallStats

	// adviceStats aggregates per-run efficiency findings into labeled advice/waste
	// metrics (Prospector Phase 4). The zero value is ready to use.
	adviceStats adviceStats
}

// RunCounts returns cumulative run totals for metrics: total dispatched to the
// provider, and those that failed with an infrastructure error.
func (s *SandboxService) RunCounts() (total, failed int64) {
	return s.runsTotal.Load(), s.runsFailed.Load()
}

func (s *SandboxService) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

// auditCaller returns the principal's UserID for audit logs, or "anon" in open dev
// mode / when unauthenticated. Never logs the token itself.
func auditCaller(ctx context.Context) string {
	if p, ok := PrincipalFrom(ctx); ok && p.UserID != "" {
		return p.UserID
	}
	return "anon"
}

// mintingSubject returns the authenticated principal's identity for per-session
// token minting, and whether a real authenticated principal is present. Unlike
// auditCaller (which returns "anon" for logs), it returns ("", false) when there is
// no authenticated caller, so a subject-bound grant can be REFUSED rather than
// collapsing every caller into one shared identity against the host API.
func mintingSubject(ctx context.Context) (string, bool) {
	if p, ok := PrincipalFrom(ctx); ok && p.UserID != "" {
		return p.UserID, true
	}
	return "", false
}

// applyGrantSubject stamps the caller identity onto ctx for per-run token minting
// and enforces that a subject-bound grant (a per-session JWT) is never run without
// an authenticated caller — otherwise every unauthenticated caller collapses into
// one shared `sub` against the host API, defeating per-caller rate limiting,
// tenancy, and audit. Such a run is refused (PermissionDenied). A static-token
// grant carries no caller identity, so it is unaffected.
func applyGrantSubject(ctx context.Context, grant *sandbox.HostAPIGrant) (context.Context, error) {
	subj, ok := mintingSubject(ctx)
	if grant.RequiresSubject() && !ok {
		return ctx, refuse(connect.CodePermissionDenied, sandbox.RefusalPermission,
			errors.New("grant_profile mints a per-caller credential and requires an authenticated caller; refusing to run it without one (e.g. open dev mode)"))
	}
	return sandbox.WithSubject(ctx, subj), nil
}

// grantFor resolves a request's grant_profile to a host-API grant. An empty profile
// means no grant (fully isolated); an unknown profile is a caller error. The caller
// can only SELECT a server-registered profile — never define BaseURL/routes/token.
func (s *SandboxService) grantFor(ctx context.Context, profile string) (*sandbox.HostAPIGrant, error) {
	if profile == "" {
		return nil, nil
	}
	if len(profile) > grants.MaxProfileNameBytes {
		return nil, refuse(connect.CodeInvalidArgument, sandbox.RefusalRequest,
			fmt.Errorf("grant_profile exceeds %d bytes", grants.MaxProfileNameBytes))
	}
	// An unknown profile and one the caller is not on get the same code and the same
	// words: two different answers would let any caller holding code:run enumerate the
	// operator's profile names, which name the host APIs behind them.
	p, ok := s.Grants.Get(profile)
	caller, authenticated := mintingSubject(ctx)
	if !ok || !authenticated || !p.Allows(caller) {
		return nil, refuse(connect.CodePermissionDenied, sandbox.RefusalPermission,
			fmt.Errorf("grant_profile %q is not available to this caller", profile))
	}
	// Grant() deep-copies, so the dispatched run can never mutate the registry.
	return p.Grant(), nil
}

// NewSandboxService wraps a sandbox provider as an RPC handler.
func NewSandboxService(s sandbox.Sandbox) *SandboxService {
	return &SandboxService{Sandbox: s}
}

func (s *SandboxService) limit(ctx context.Context) (func(), error) {
	if s.Limiter == nil {
		return func() {}, nil
	}
	key := "anon"
	if p, ok := PrincipalFrom(ctx); ok && p.UserID != "" {
		key = p.UserID
	}
	return s.Limiter.Acquire(ctx, key)
}

// Describe reports the protocol number, the active provider's current isolation
// evidence and static operation support. It runs no code and takes no limiter slot. Project support is
// structural: it does not prove that a selected image/template contains a specific
// toolchain, so readiness still matters.
//
// SEAM(gateway): Describe is the per-instance discovery surface. A future fleet
// gateway (a control plane in front of many plimsolld instances, routing a run
// to one by required isolation tier and grant capability, and aggregating /metrics
// and advisory findings across the fleet) composes OVER this response: it reads
// structural capability here and current isolation evidence here and on each run
// result, and needs no change to this service to route by them. Keep Describe a
// truthful, side-effect-free capability report so a gateway can trust it without a
// separate control channel. See docs/seams.md#gateway.
func (s *SandboxService) Describe(_ context.Context, _ *connect.Request[plimsollv1.DescribeRequest]) (*connect.Response[plimsollv1.DescribeResponse], error) {
	supportsProject := false
	if pc, ok := s.Sandbox.(sandbox.ProjectCapable); ok {
		supportsProject = pc.SupportsProjects()
	}
	supportsModule := false
	if mc, ok := s.Sandbox.(sandbox.ModuleCapable); ok {
		supportsModule = mc.SupportsModules()
	}
	var env sandbox.Environments
	if d, ok := s.Sandbox.(sandbox.Describer); ok {
		env = d.Environments()
	}
	supportsJavaScriptGrants, supportsProjectGrants := false, false
	if gc, ok := s.Sandbox.(sandbox.GrantCapable); ok {
		supportsJavaScriptGrants = gc.SupportsJavaScriptGrants()
		supportsProjectGrants = gc.SupportsProjectGrants()
	}
	sp, supportsSessions := s.sessionProvider()
	var sessionLifetime, sessionIdle uint32
	var sessionEnv *plimsollv1.PayloadEnvironment
	if supportsSessions {
		sessionLifetime = uint32(s.Sessions.Lifetime / time.Millisecond)
		sessionIdle = uint32(s.Sessions.IdleTimeout / time.Millisecond)
		// Every call of a session runs in its one sandbox; the provider states where
		// (docker: the project image), as OpenSession checks a software rule against.
		sessionEnv = payloadEnvironment(sp.SessionEnvironments().JavaScript)
	}
	return connect.NewResponse(&plimsollv1.DescribeResponse{
		Sandbox:                  s.Sandbox.Name(),
		Isolation:                s.Sandbox.IsolationClass().String(),
		SupportsProject:          supportsProject,
		SupportsModule:           supportsModule,
		SupportsJavascriptGrants: supportsJavaScriptGrants,
		SupportsProjectGrants:    supportsProjectGrants,
		Protocol:                 protocol.Number,
		JavascriptEnvironment:    payloadEnvironment(env.JavaScript),
		ProjectEnvironment:       payloadEnvironment(env.Project),
		ModuleEnvironment:        payloadEnvironment(env.Module),
		Resources: &plimsollv1.RunResources{
			MemoryMb: nonNegative(s.Resources.MemoryMB),
			Cpus:     s.Resources.CPUs,
			Pids:     nonNegative(s.Resources.PidsLimit),
			DiskMb:   nonNegative(s.Resources.DiskMB),
		},
		Policy:               env.Policy,
		SupportsSessions:     supportsSessions,
		SessionLifetimeMs:    sessionLifetime,
		SessionIdleTimeoutMs: sessionIdle,
		SessionEnvironment:   sessionEnv,
		MaxSessionsPerCaller: sessionCap(supportsSessions, s.Sessions.MaxPerCaller),
		MaxSessionsPerOwner:  sessionCap(supportsSessions, s.Sessions.MaxPerOwner),
	}), nil
}

// payloadEnvironment puts a provider's statement on the wire. The stated ceiling
// is capped by maxRunTimeout, the daemon's own, because that is the longest a run
// can actually take here.
func payloadEnvironment(e sandbox.PayloadEnvironment) *plimsollv1.PayloadEnvironment {
	ceiling := e.MaxTimeout
	if ceiling > maxRunTimeout {
		ceiling = maxRunTimeout
	}
	langs := make([]string, 0, len(e.Languages))
	for _, l := range e.Languages {
		langs = append(langs, string(l))
	}
	return &plimsollv1.PayloadEnvironment{Identity: e.Identity, SoftwareIdentity: e.SoftwareIdentity, MaxTimeoutMs: uint32(ceiling / time.Millisecond), Languages: langs}
}

func nonNegative(n int) uint32 {
	if n < 0 {
		return 0
	}
	return uint32(n)
}

// envelope is the part of a RunRequest every payload kind shares, parsed once
// before the payload is looked at.
type envelope struct {
	minimum  sandbox.IsolationClass
	timeout  time.Duration
	traceID  string
	software sandbox.SoftwareRule
}

// target is where a checked call runs: the provider itself for a run, or a session
// for a session call. The request pipeline (pipeline.go) is the same code for both.
type target struct {
	provider string                 // for a failed run's audit line
	tier     sandbox.IsolationClass // the evidence the request's floor is checked against
	admit    func(context.Context) (func(), error)
	js       func(context.Context, sandbox.Request) (sandbox.Result, error)
	project  func(context.Context, sandbox.ProjectRequest) (sandbox.ProjectResult, error)
	module   func(context.Context, sandbox.ModuleRequest) (sandbox.ModuleResult, error) // runs only
	// teardown is the provider's BillingTeardown: positive when it bills by the second
	// (sandbox.Metered), so a run draws on the daily allowances (SpendCap). Runs only:
	// a session's paid time is charged by its sessionMeter, from its open to its
	// suspend and from a resume to the next.
	teardown time.Duration
	software sandbox.Environments
	// session is set for a session call: software then holds the identities its
	// sandbox was opened with, which every call runs on.
	session bool
	attrs   []slog.Attr // added to the audit line (a session's fingerprint and call number)
}

// runTarget is the provider, admitted through the limiter.
func (s *SandboxService) runTarget() target {
	var software sandbox.Environments
	if d, ok := s.Sandbox.(sandbox.Describer); ok {
		software = d.Environments()
	}
	return target{
		provider: s.Sandbox.Name(),
		tier:     s.Sandbox.IsolationClass(),
		admit:    s.limit,
		js:       s.Sandbox.RunJavaScript,
		project:  s.Sandbox.RunProject,
		module:   s.Sandbox.RunModule,
		teardown: sandbox.MeteredTeardown(s.Sandbox),
		software: software,
	}
}

// checkEnvelope is the first thing Run does. The protocol number comes before
// everything else: a request that omits it is a client bug (InvalidArgument) and
// a request on any other number comes from a client this daemon must not serve
// (Unimplemented), in both cases before the payload is read, so nothing can run.
// Then the floor is parsed (an unparseable floor is InvalidArgument, never "no
// floor") and the timeout clamped.
func checkEnvelope(req *plimsollv1.RunRequest) (envelope, error) {
	return parseEnvelope(req.GetProtocol(), req.GetMinimumIsolation(), req.GetTimeoutMs(), req.GetTraceId(), req.GetSoftwareRule())
}

// parseEnvelope is checkEnvelope over the fields themselves, which a session
// call's request shares.
func parseEnvelope(proto uint32, floor string, timeoutMs int32, traceID string, rule *plimsollv1.SoftwareRule) (envelope, error) {
	if err := checkProtocol(proto); err != nil {
		return envelope{}, err
	}
	minimum, err := parseMinimumIsolation(floor)
	if err != nil {
		return envelope{}, refuse(connect.CodeInvalidArgument, sandbox.RefusalRequest, err)
	}
	software := softwarewire.FromWire(rule)
	if err := software.Validate(); err != nil {
		return envelope{}, mapSandboxErr(err)
	}
	return envelope{minimum: minimum, timeout: clampTimeoutMs(timeoutMs), traceID: traceID, software: software}, nil
}

// checkProtocol refuses a request that omits the protocol number or states
// another, before anything else in it is read.
func checkProtocol(p uint32) error {
	switch {
	case p == 0:
		return refuse(connect.CodeInvalidArgument, sandbox.RefusalProtocol,
			fmt.Errorf("protocol must be stated; this daemon serves protocol %d", protocol.Number))
	case p != protocol.Number:
		return refuse(connect.CodeUnimplemented, sandbox.RefusalProtocol, errors.New(protocol.Mismatch(protocol.Number, p)))
	}
	return nil
}

// Run is the one execution procedure: envelope checked, then exactly one payload
// kind dispatched. Every kind goes through the same floor check, the same
// limiter, the same audit line shape, and returns the same evidence fields.
func (s *SandboxService) Run(ctx context.Context, req *connect.Request[plimsollv1.RunRequest]) (*connect.Response[plimsollv1.RunResponse], error) {
	received := time.Now()
	env, err := checkEnvelope(req.Msg)
	if err != nil {
		return nil, err
	}
	var k kind
	switch p := req.Msg.GetPayload().(type) {
	case *plimsollv1.RunRequest_Javascript:
		k = &javascriptKind{p: p.Javascript}
	case *plimsollv1.RunRequest_Project:
		k = &projectKind{p: p.Project}
	case *plimsollv1.RunRequest_Module:
		k = &moduleKind{p: p.Module}
	case *plimsollv1.RunRequest_Cell:
		return nil, refuse(connect.CodeInvalidArgument, sandbox.RefusalRequest,
			fmt.Errorf("%w: a cell runs only in a session (SessionRun)", sandbox.ErrInvalidRequest))
	default:
		return nil, refuse(connect.CodeInvalidArgument, sandbox.RefusalRequest,
			errors.New("payload must be exactly one of javascript, project, or module"))
	}
	resp, err := s.pipeline(ctx, env, k, s.runTarget())
	if err != nil {
		return nil, err
	}
	resp.Record = s.runRecord(record.RunRequestDigest(req.Msg), resp, received, time.Now(), sandbox.RunRecord{}, env.software)
	return connect.NewResponse(resp), nil
}

// runRecord states a finished run for the caller's harness to check and sign: the
// request digest over what the caller sent, the result digest over the response
// as it will be sent, the evidence, and the times. link carries a session call's
// chain fields and is zero for a single run. The daemon holds no key, so this is
// hashing only.
// recordEnd is the end a record states: its start on the wall clock plus the time
// that passed on the monotonic clock, never a second wall-clock reading. The wall
// clock can be stepped during a run (NTP, a virtual machine resyncing its time), and
// two readings would then put the end before the start. A reading without a
// monotonic clock that still lands before the start is held at the start.
func recordEnd(started, ended time.Time) time.Time {
	return started.Add(max(ended.Sub(started), 0))
}

func (s *SandboxService) runRecord(requestDigest string, resp *plimsollv1.RunResponse, started, ended time.Time, link sandbox.RunRecord, rule sandbox.SoftwareRule) *plimsollv1.RunRecord {
	return record.Stamp(sandbox.RunRecord{
		RequestSHA256:  requestDigest,
		SoftwareRuleID: rule.ID(),
		Policy:         s.policy(),
		Started:        started,
		Ended:          recordEnd(started, ended),
		Session:        link.Session,
		Sequence:       link.Sequence,
		PreviousSHA256: link.PreviousSHA256,
	}, resp)
}

// policy is the verified sandbox policy's digest the provider states, or "".
func (s *SandboxService) policy() string {
	if d, ok := s.Sandbox.(sandbox.Describer); ok {
		return d.Environments().Policy
	}
	return ""
}

// ranSoftware is the software identity a response states: what the run reported,
// or for a session call the identity its sandbox was opened with. Never the
// Describe answer read before a single run's admission, which a Preflight between
// admission and launch can change; an empty identity fails a required rule at the
// client.
func (t target) ranSoftware(reported, opened string) string {
	if reported != "" || !t.session {
		return reported
	}
	return opened
}

// describedEnvironment is the outer environment a response states. Docker reports
// the image each run launched; the other providers state one fixed, configured
// identity through Describe and not per run, so their Describe value stands in.
// The software identity a rule is checked against never falls back to Describe:
// see ranSoftware.
func describedEnvironment(actual, described string) string {
	if actual != "" {
		return actual
	}
	return described
}

// outcomeWire maps the sandbox package's typed project outcome to its wire enum.
func outcomeWire(o sandbox.ProjectOutcome) plimsollv1.ProjectOutcome {
	switch o {
	case sandbox.ProjectOutcomeCompleted:
		return plimsollv1.ProjectOutcome_PROJECT_OUTCOME_COMPLETED
	case sandbox.ProjectOutcomeSetupFailed:
		return plimsollv1.ProjectOutcome_PROJECT_OUTCOME_SETUP_FAILED
	case sandbox.ProjectOutcomeTimedOut:
		return plimsollv1.ProjectOutcome_PROJECT_OUTCOME_TIMED_OUT
	case sandbox.ProjectOutcomeProtocolError:
		return plimsollv1.ProjectOutcome_PROJECT_OUTCOME_PROTOCOL_ERROR
	default:
		return plimsollv1.ProjectOutcome_PROJECT_OUTCOME_UNSPECIFIED
	}
}

// isInfraErr reports whether a sandbox error is a true infrastructure fault, as
// opposed to a deterministic client/config condition (a disabled provider, an
// unsupported operation, or ordinary load shedding). Only infra faults count
// toward plimsoll_runs_failed_total.
func isInfraErr(err error) bool {
	return err != nil &&
		!errors.Is(err, sandbox.ErrUnsupported) &&
		!errors.Is(err, sandbox.ErrDisabled) &&
		!errors.Is(err, sandbox.ErrAtCapacity) &&
		!errors.Is(err, sandbox.ErrInvalidRequest) &&
		!errors.Is(err, sandbox.ErrInsufficientIsolation) &&
		!errors.Is(err, sandbox.ErrSoftwareMismatch) &&
		!errors.Is(err, context.Canceled) &&
		!errors.Is(err, context.DeadlineExceeded)
}

// mapSandboxErr translates a sandbox error to a Connect code. A disabled provider
// is a precondition failure (the caller should configure one); an operation the
// configured provider structurally cannot do is Unimplemented; admission shedding
// is ResourceExhausted; anything else is an internal fault. When the provider
// marked the error as refused before dispatch, the NotDispatched detail is
// attached; an unmarked error carries none, whatever its code. An internal fault's
// text can carry a vendor's response body, envd's or docker's stderr, or host
// configuration, so the caller gets a generic message with an ID and the text goes to
// the log under that ID, cut to internalErrorLogBytes.
func mapSandboxErr(err error) error {
	code := sandboxErrCode(err)
	shown := err
	if code == connect.CodeInternal {
		id := internalErrorID()
		text := err.Error()
		if len(text) > internalErrorLogBytes {
			text = text[:internalErrorLogBytes] + "...(cut)"
		}
		slog.Warn("internal error answered to a caller", "error_id", id, "error", wireString(text))
		shown = fmt.Errorf("internal error %s; the daemon's log holds its detail", id)
	}
	ce := connect.NewError(code, shown)
	// A session's end travels as a typed detail, so a caller learns why without
	// parsing the message.
	var se *sandbox.SessionEndedError
	if errors.As(err, &se) {
		if d, derr := connect.NewErrorDetail(&plimsollv1.SessionEnded{Reason: sessionEndWire(se.Reason), Detail: wireString(se.Detail)}); derr == nil {
			ce.AddDetail(d)
		}
	}
	if reason, ok := sandbox.NotDispatchedReason(err); ok {
		return withNotDispatched(ce, reason)
	}
	return ce
}

// internalErrorLogBytes bounds an internal error's text in the log: enough for any
// message plimsoll writes, short of the megabyte a vendor's error body can be.
const internalErrorLogBytes = 4096

// internalErrorID joins a caller's generic error to its log line.
func internalErrorID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func sandboxErrCode(err error) connect.Code {
	switch {
	case errors.Is(err, context.Canceled):
		return connect.CodeCanceled
	case errors.Is(err, context.DeadlineExceeded):
		return connect.CodeDeadlineExceeded
	case errors.Is(err, sandbox.ErrDisabled), errors.Is(err, sandbox.ErrInsufficientIsolation), errors.Is(err, sandbox.ErrSoftwareMismatch), errors.Is(err, sandbox.ErrSessionEnded):
		return connect.CodeFailedPrecondition
	case errors.Is(err, sandbox.ErrGrantNotForSessions):
		return connect.CodePermissionDenied
	case errors.Is(err, sandbox.ErrUnsupported):
		return connect.CodeUnimplemented
	case errors.Is(err, sandbox.ErrAtCapacity):
		return connect.CodeResourceExhausted
	case errors.Is(err, sandbox.ErrInvalidRequest):
		return connect.CodeInvalidArgument
	default:
		return connect.CodeInternal
	}
}

// wireString repairs a provider-produced string before assigning it to a
// protobuf string field. Guest stdout/stderr travel as bytes, but the remaining
// string fields can still carry guest-influenced content (a command echoed back
// by the runner, an outcome detail built from stderr); protobuf strings require
// valid UTF-8, and without this guard a completed run could fail during response
// serialization and disappear as an unstructured transport error.
func wireString(s string) string {
	return strings.ToValidUTF8(s, "\uFFFD")
}

// hostCallAttrs is the bounded, metadata-only summary of a run's brokered host.*
// calls for its audit line (never paths, bodies, or credentials); nothing when the
// run brokered nothing.
func hostCallAttrs(t *sandbox.CallTrace) []slog.Attr {
	if t == nil {
		return nil
	}
	attrs := []slog.Attr{slog.Int("host_calls", len(t.Calls))}
	if t.Denied > 0 {
		attrs = append(attrs, slog.Int("host_calls_denied", t.Denied))
	}
	if t.Dropped > 0 {
		attrs = append(attrs, slog.Int("host_calls_dropped", t.Dropped))
	}
	if t.Shed > 0 {
		attrs = append(attrs, slog.Int("host_calls_shed", t.Shed))
	}
	return attrs
}

// wireNaN is the one NaN a module result carries: the quiet NaN with no sign and no
// payload. Protobuf JSON writes every NaN as "NaN", and Python's float("nan") and
// JavaScript's NaN both encode back to these bits, so a JSON client recomputes the
// record's digest over exactly what was hashed. A simulator that blew up yields x86's
// default NaN, which has the sign bit set, and that used to fail the record check.
var wireNaN = math.Float64frombits(0x7ff8000000000000)

// canonicalNaNs returns outputs with every NaN as wireNaN, copying only when one is
// not already.
func canonicalNaNs(outputs []float64) []float64 {
	var out []float64
	for i, v := range outputs {
		if v == v || math.Float64bits(v) == math.Float64bits(wireNaN) {
			continue
		}
		if out == nil {
			out = slices.Clone(outputs)
		}
		out[i] = wireNaN
	}
	if out == nil {
		return outputs
	}
	return out
}

// sessionCap is a session cap as Describe states it: only where sessions work.
func sessionCap(supportsSessions bool, n int) uint32 {
	if !supportsSessions || n <= 0 {
		return 0
	}
	return uint32(n)
}
