package rpc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1/plimsollv1connect"
	"github.com/plimsollmark/plimsoll/internal/grants"
	"github.com/plimsollmark/plimsoll/internal/quantise"
	"github.com/plimsollmark/plimsoll/protocol"
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

// runContext makes the RPC ceiling an actual context deadline, not merely a hint
// in Request.Timeout. Providers are required to honor ctx; this backstop still
// bounds a provider whose own timeout fields were left unconfigured.
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
	Limiter *CodeLimiter     // optional; nil = unlimited
	Grants  *grants.Registry // optional; nil/empty = no host-API profiles
	Logger  *slog.Logger     // optional; nil = slog.Default()

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
		return ctx, connect.NewError(connect.CodePermissionDenied,
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
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("grant_profile exceeds %d bytes", grants.MaxProfileNameBytes))
	}
	p, ok := s.Grants.Get(profile)
	if !ok {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("unknown grant_profile %q", profile))
	}
	caller, authenticated := mintingSubject(ctx)
	if !authenticated || !p.Allows(caller) {
		return nil, connect.NewError(connect.CodePermissionDenied,
			errors.New("authenticated caller is not allowed to select the requested grant_profile"))
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
	supportsJavaScriptGrants, supportsProjectGrants := false, false
	if gc, ok := s.Sandbox.(sandbox.GrantCapable); ok {
		supportsJavaScriptGrants = gc.SupportsJavaScriptGrants()
		supportsProjectGrants = gc.SupportsProjectGrants()
	}
	return connect.NewResponse(&plimsollv1.DescribeResponse{
		Sandbox:                  s.Sandbox.Name(),
		Isolation:                s.Sandbox.IsolationClass().String(),
		SupportsProject:          supportsProject,
		SupportsModule:           supportsModule,
		SupportsJavascriptGrants: supportsJavaScriptGrants,
		SupportsProjectGrants:    supportsProjectGrants,
		Protocol:                 protocol.Number,
	}), nil
}

// envelope is the part of a RunRequest every payload kind shares, parsed once
// before the payload is looked at.
type envelope struct {
	minimum sandbox.IsolationClass
	timeout time.Duration
	traceID string
}

// checkEnvelope is the first thing Run does. The protocol number comes before
// everything else: a request that omits it is a client bug (InvalidArgument) and
// a request on any other number comes from a client this daemon must not serve
// (Unimplemented), in both cases before the payload is read, so nothing can run.
// Then the floor is parsed (an unparseable floor is InvalidArgument, never "no
// floor") and the timeout clamped.
func checkEnvelope(req *plimsollv1.RunRequest) (envelope, error) {
	switch p := req.GetProtocol(); {
	case p == 0:
		return envelope{}, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("protocol must be stated; this daemon serves protocol %d", protocol.Number))
	case p != protocol.Number:
		return envelope{}, connect.NewError(connect.CodeUnimplemented, errors.New(protocol.Mismatch(protocol.Number, p)))
	}
	minimum, err := parseMinimumIsolation(req.GetMinimumIsolation())
	if err != nil {
		return envelope{}, connect.NewError(connect.CodeInvalidArgument, err)
	}
	return envelope{minimum: minimum, timeout: clampTimeoutMs(req.GetTimeoutMs()), traceID: req.GetTraceId()}, nil
}

// Run is the one execution procedure: envelope checked, then exactly one payload
// kind dispatched. Every kind goes through the same floor check, the same
// limiter, the same audit line shape, and returns the same evidence fields.
func (s *SandboxService) Run(ctx context.Context, req *connect.Request[plimsollv1.RunRequest]) (*connect.Response[plimsollv1.RunResponse], error) {
	env, err := checkEnvelope(req.Msg)
	if err != nil {
		return nil, err
	}
	var resp *plimsollv1.RunResponse
	switch p := req.Msg.GetPayload().(type) {
	case *plimsollv1.RunRequest_Javascript:
		resp, err = s.runJavaScript(ctx, env, p.Javascript)
	case *plimsollv1.RunRequest_Project:
		resp, err = s.runProject(ctx, env, p.Project)
	case *plimsollv1.RunRequest_Module:
		resp, err = s.runModule(ctx, env, p.Module)
	default:
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("payload must be exactly one of javascript, project, or module"))
	}
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(resp), nil
}

// runJavaScript is the snippet kind. The envelope has been checked; the grant
// profile is the payload's, because a module payload has no such field.
func (s *SandboxService) runJavaScript(ctx context.Context, env envelope, p *plimsollv1.JavaScriptRun) (*plimsollv1.RunResponse, error) {
	code := p.GetCode()
	sbReq := sandbox.Request{Code: code, Timeout: env.timeout, MinimumIsolation: env.minimum}
	if err := sandbox.ValidateRequest(sbReq); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	grant, err := s.grantFor(ctx, p.GetGrantProfile())
	if err != nil {
		return nil, err
	}
	if grant != nil {
		ctx, err = applyGrantSubject(ctx, grant) // per-session token minting; refuses anon subject-bound grants
		if err != nil {
			return nil, err
		}
	}
	sbReq.Grant = grant
	if err := sandbox.CheckMinimumIsolation(s.Sandbox.IsolationClass(), sbReq.MinimumIsolation); err != nil {
		return nil, mapSandboxErr(err)
	}

	release, err := s.limit(ctx)
	if err != nil {
		return nil, err
	}
	defer release()

	s.runsTotal.Add(1)
	runCtx, cancel := runContext(ctx)
	defer cancel()
	started := time.Now()
	res, err := s.Sandbox.RunJavaScript(runCtx, sbReq)
	if err != nil {
		if isInfraErr(err) {
			s.runsFailed.Add(1)
		}
		failed := []slog.Attr{
			slog.String("op", "javascript"),
			slog.String("caller", auditCaller(ctx)),
			slog.Int("code_bytes", len(code)),
			slog.String("grant_profile", p.GetGrantProfile()),
			slog.String("sandbox", s.Sandbox.Name()),
			slog.String("isolation", s.Sandbox.IsolationClass().String()),
			slog.Int64("duration_ms", time.Since(started).Milliseconds()),
			slog.String("error", err.Error()),
		}
		// A failed run is exactly the one an operator will go looking for, so it
		// carries the join key too.
		failed = append(failed, traceAttrs(env.traceID)...)
		s.logger().LogAttrs(ctx, slog.LevelError, "code run failed", failed...)
		return nil, mapSandboxErr(err)
	}
	attrs := []slog.Attr{
		slog.String("op", "javascript"),
		slog.String("caller", auditCaller(ctx)),
		slog.Int("code_bytes", len(code)),
		slog.String("grant_profile", p.GetGrantProfile()),
		slog.String("sandbox", res.Sandbox),
		slog.String("isolation", res.Isolation.String()),
		slog.Int("exit_code", res.ExitCode),
		slog.Bool("timed_out", res.TimedOut),
		slog.Int64("duration_ms", res.Duration.Milliseconds()),
	}
	// The caller's opaque join key, so this metadata-only line can be matched to
	// the caller's own record of the same request. Recorded, never interpreted.
	attrs = append(attrs, traceAttrs(env.traceID)...)
	// Fold the run's brokered calls into the labeled /metrics series (metadata only:
	// profile, method, route template). No-op when the run brokered nothing.
	s.hostCalls.observe(p.GetGrantProfile(), res.CallTrace)
	// Bounded, metadata-only summary of the run's brokered host.* calls (never
	// paths, bodies, or credentials). Emitted only when the run brokered something.
	if t := res.CallTrace; t != nil {
		attrs = append(attrs, slog.Int("host_calls", len(t.Calls)))
		if t.Denied > 0 {
			attrs = append(attrs, slog.Int("host_calls_denied", t.Denied))
		}
		if t.Dropped > 0 {
			attrs = append(attrs, slog.Int("host_calls_dropped", t.Dropped))
		}
		if t.Shed > 0 {
			attrs = append(attrs, slog.Int("host_calls_shed", t.Shed))
		}
	}
	// Prospector advisory channel (Phase 2). Post-dispatch analysis over the
	// immutable CallTrace: res is already final above, so computing advice cannot
	// change ExitCode/Stdout/Stderr/Isolation — a run with advice is byte-identical
	// in execution to one without. Findings go to the operator surface (audit) for
	// operator|caller; only the agent-fixable subset is returned to the caller, and
	// only for caller.
	var allow []sandbox.HostRoute
	if grant != nil {
		allow = grant.Allow
	}
	mode := s.adviceFor(p.GetGrantProfile())
	allFindings, callerFindings := computeAdvice(mode, res.CallTrace, allow, s.catalogFor(p.GetGrantProfile()))
	// Fold the run's findings into the labeled advice/waste series for /metrics. No-op
	// when advice is off (no findings computed) or the run tripped no detector. These
	// aggregates carry no route templates and are not gated by advice_retention: they
	// are the operator's bounded operational metric, not the durable finding record.
	s.adviceStats.observe(p.GetGrantProfile(), allFindings)
	// The durable audit-log record of the run's findings is gated by the profile's
	// retention level (Phase 5); it is off by default, so advice can drive the live
	// wire hint and /metrics without writing per-run findings to the log.
	retention := s.adviceRetentionFor(p.GetGrantProfile())
	attrs = append(attrs, adviceAuditAttrs(mode, retention, allFindings)...)
	s.logger().LogAttrs(ctx, slog.LevelInfo, "code run", attrs...)
	return &plimsollv1.RunResponse{
		Sandbox:    wireString(res.Sandbox),
		Isolation:  res.Isolation.String(),
		DurationMs: res.Duration.Milliseconds(),
		Result: &plimsollv1.RunResponse_Javascript{Javascript: &plimsollv1.JavaScriptResult{
			Stdout:          []byte(res.Stdout),
			Stderr:          []byte(res.Stderr),
			StdoutTruncated: res.StdoutTruncated,
			StderrTruncated: res.StderrTruncated,
			ExitCode:        int32(res.ExitCode),
			TimedOut:        res.TimedOut,
			Advice:          adviceWire(callerFindings),
		}},
	}, nil
}

// runProject is the project kind: files written, steps run in order, artifacts
// captured. Same envelope, same grant path as a snippet.
func (s *SandboxService) runProject(ctx context.Context, env envelope, p *plimsollv1.ProjectRun) (*plimsollv1.RunResponse, error) {
	steps := p.GetSteps()
	files := p.GetFiles()
	total := 0
	sbFiles := make([]sandbox.File, 0, len(files))
	for _, f := range files {
		total += len(f.GetContent())
		sbFiles = append(sbFiles, sandbox.File{Path: f.GetPath(), Content: f.GetContent()})
	}
	artifacts := p.GetArtifacts()
	sbReq := sandbox.ProjectRequest{
		Files:            sbFiles,
		Steps:            append([]string(nil), steps...),
		Timeout:          env.timeout,
		Artifacts:        append([]string(nil), artifacts...),
		MinimumIsolation: env.minimum,
	}
	if err := sandbox.ValidateProjectRequest(sbReq); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	grant, err := s.grantFor(ctx, p.GetGrantProfile())
	if err != nil {
		return nil, err
	}
	if grant != nil {
		ctx, err = applyGrantSubject(ctx, grant) // per-session token minting; refuses anon subject-bound grants
		if err != nil {
			return nil, err
		}
	}
	sbReq.Grant = grant
	if err := sandbox.CheckMinimumIsolation(s.Sandbox.IsolationClass(), sbReq.MinimumIsolation); err != nil {
		return nil, mapSandboxErr(err)
	}

	release, err := s.limit(ctx)
	if err != nil {
		return nil, err
	}
	defer release()

	s.runsTotal.Add(1)
	runCtx, cancel := runContext(ctx)
	defer cancel()
	started := time.Now()
	res, err := s.Sandbox.RunProject(runCtx, sbReq)
	if err != nil {
		if isInfraErr(err) {
			s.runsFailed.Add(1)
		}
		failed := []slog.Attr{
			slog.String("op", "project"),
			slog.String("caller", auditCaller(ctx)),
			slog.Int("files", len(files)),
			slog.Int("steps", len(steps)),
			slog.Int("total_bytes", total),
			slog.String("grant_profile", p.GetGrantProfile()),
			slog.String("sandbox", s.Sandbox.Name()),
			slog.String("isolation", s.Sandbox.IsolationClass().String()),
			slog.Int64("duration_ms", time.Since(started).Milliseconds()),
			slog.String("error", err.Error()),
		}
		failed = append(failed, traceAttrs(env.traceID)...)
		s.logger().LogAttrs(ctx, slog.LevelError, "project run failed", failed...)
		return nil, mapSandboxErr(err)
	}
	exitCode, timedOut := 0, false
	if len(res.Steps) > 0 {
		last := res.Steps[len(res.Steps)-1]
		exitCode, timedOut = last.ExitCode, last.TimedOut
	}
	attrs := []slog.Attr{
		slog.String("op", "project"),
		slog.String("caller", auditCaller(ctx)),
		slog.Int("files", len(files)),
		slog.Int("steps", len(steps)),
		slog.Int("total_bytes", total),
		slog.String("grant_profile", p.GetGrantProfile()),
		slog.String("sandbox", res.Sandbox),
		slog.String("isolation", res.Isolation.String()),
		slog.String("outcome", res.Outcome.String()),
		slog.String("outcome_detail", res.Detail),
		slog.Int("steps_ran", len(res.Steps)),
		slog.Int("exit_code", exitCode),
		slog.Bool("timed_out", timedOut),
		slog.Int64("duration_ms", time.Since(started).Milliseconds()),
	}
	attrs = append(attrs, traceAttrs(env.traceID)...)
	// Prospector: a project run brokers host.* calls through the same core as a snippet,
	// so it feeds the identical metadata-only surfaces. Fold the run's calls into the
	// labeled /metrics series and summarize them on the audit line (never paths, bodies,
	// or credentials). No-op when the run brokered nothing.
	s.hostCalls.observe(p.GetGrantProfile(), res.CallTrace)
	if t := res.CallTrace; t != nil {
		attrs = append(attrs, slog.Int("host_calls", len(t.Calls)))
		if t.Denied > 0 {
			attrs = append(attrs, slog.Int("host_calls_denied", t.Denied))
		}
		if t.Dropped > 0 {
			attrs = append(attrs, slog.Int("host_calls_dropped", t.Dropped))
		}
		if t.Shed > 0 {
			attrs = append(attrs, slog.Int("host_calls_shed", t.Shed))
		}
	}
	// Advisory channel (Phase 2), identical to the snippet kind: post-dispatch analysis
	// over the immutable CallTrace. res is already final above, so computing advice
	// cannot change any step's output/exit or the outcome — a project run with advice is
	// byte-identical in execution to one without. Operator surface (audit/metrics) sees
	// every finding; only the agent-fixable subset returns to the caller, and only for
	// advice: caller.
	var allow []sandbox.HostRoute
	if grant != nil {
		allow = grant.Allow
	}
	mode := s.adviceFor(p.GetGrantProfile())
	allFindings, callerFindings := computeAdvice(mode, res.CallTrace, allow, s.catalogFor(p.GetGrantProfile()))
	s.adviceStats.observe(p.GetGrantProfile(), allFindings)
	retention := s.adviceRetentionFor(p.GetGrantProfile())
	attrs = append(attrs, adviceAuditAttrs(mode, retention, allFindings)...)
	s.logger().LogAttrs(ctx, slog.LevelInfo, "project run", attrs...)

	result := &plimsollv1.ProjectResult{
		Outcome:            outcomeWire(res.Outcome),
		OutcomeDetail:      wireString(res.Detail),
		ArtifactsTruncated: res.ArtifactsTruncated,
		Advice:             adviceWire(callerFindings),
	}
	for _, st := range res.Steps {
		result.Steps = append(result.Steps, &plimsollv1.StepResult{
			Command:         wireString(st.Command),
			Stdout:          []byte(st.Stdout),
			Stderr:          []byte(st.Stderr),
			StdoutTruncated: st.StdoutTruncated,
			StderrTruncated: st.StderrTruncated,
			ExitCode:        int32(st.ExitCode),
			TimedOut:        st.TimedOut,
			DurationMs:      st.Duration.Milliseconds(),
		})
	}
	for _, a := range res.Artifacts {
		result.Artifacts = append(result.Artifacts, &plimsollv1.Artifact{Path: wireString(a.Path), Content: a.Content})
	}
	return &plimsollv1.RunResponse{
		Sandbox:    wireString(res.Sandbox),
		Isolation:  res.Isolation.String(),
		DurationMs: time.Since(started).Milliseconds(),
		Result:     &plimsollv1.RunResponse_Project{Project: result},
	}, nil
}

// runModule is the model kind: a compiled model once per parameter row. No
// grant: a model has no host API and the payload cannot name one. The audit
// line names the model (validated to a filename stem), counts rows, values per
// row and the step bound, and records the outcome; a parameter value never
// reaches a log.
func (s *SandboxService) runModule(ctx context.Context, env envelope, p *plimsollv1.ModuleRun) (*plimsollv1.RunResponse, error) {
	rows := make([][]float64, 0, len(p.GetRows()))
	for _, r := range p.GetRows() {
		rows = append(rows, append([]float64(nil), r.GetValues()...))
	}
	sbReq := sandbox.ModuleRequest{
		Model:            p.GetModel(),
		Rows:             rows,
		EndTime:          p.GetEndTime(),
		Step:             p.GetStep(),
		Timeout:          env.timeout,
		MinimumIsolation: env.minimum,
	}
	if err := sandbox.ValidateModuleRequest(sbReq); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if err := sandbox.CheckMinimumIsolation(s.Sandbox.IsolationClass(), sbReq.MinimumIsolation); err != nil {
		return nil, mapSandboxErr(err)
	}

	release, err := s.limit(ctx)
	if err != nil {
		return nil, err
	}
	defer release()

	s.runsTotal.Add(1)
	runCtx, cancel := runContext(ctx)
	defer cancel()
	started := time.Now()
	res, err := s.Sandbox.RunModule(runCtx, sbReq)
	attrs := []slog.Attr{
		slog.String("op", "module"),
		slog.String("caller", auditCaller(ctx)),
		slog.String("model", sbReq.Model),
		slog.Int("rows", len(sbReq.Rows)),
		slog.Int("row_width", sbReq.RowWidth()),
		slog.Int("max_steps", sbReq.MaxSteps()),
	}
	if err != nil {
		if isInfraErr(err) {
			s.runsFailed.Add(1)
		}
		attrs = append(attrs,
			slog.String("sandbox", s.Sandbox.Name()),
			slog.String("isolation", s.Sandbox.IsolationClass().String()),
			slog.Int64("duration_ms", time.Since(started).Milliseconds()),
			slog.String("error", err.Error()),
		)
		attrs = append(attrs, traceAttrs(env.traceID)...)
		s.logger().LogAttrs(ctx, slog.LevelError, "module run failed", attrs...)
		return nil, mapSandboxErr(err)
	}
	attrs = append(attrs,
		slog.String("sandbox", res.Sandbox),
		slog.String("isolation", res.Isolation.String()),
		slog.String("outcome", res.Outcome.String()),
		slog.String("outcome_detail", res.Detail),
		slog.Int("runs", len(res.Runs)),
		slog.Int("width", res.Width),
		slog.Int64("duration_ms", time.Since(started).Milliseconds()),
	)
	// Post-dispatch, over results already computed: no model is run, nothing
	// about the result changes, and a caller paying for rows that return an
	// answer it already has is worth an operator seeing. Counts only. The
	// tread widths this derives are differences between the caller's parameter
	// values, and the audit line carries no parameter value.
	for _, f := range quantise.Analyze(sbReq.Rows, res.Runs) {
		attrs = append(attrs,
			slog.Int("tread_column", f.Column),
			slog.Int("tread_distinct", f.Distinct),
			slog.Int("tread_repeated", f.Repeated),
			slog.Bool("tread_covers_whole_sweep", f.WholeSweepInOneTread()),
		)
	}
	attrs = append(attrs, traceAttrs(env.traceID)...)
	s.logger().LogAttrs(ctx, slog.LevelInfo, "module run", attrs...)

	result := &plimsollv1.ModuleResult{
		Width:         int32(res.Width),
		Outcome:       outcomeWire(res.Outcome),
		OutcomeDetail: wireString(res.Detail),
		Stdout:        []byte(res.Stdout),
		Stderr:        []byte(res.Stderr),
	}
	for _, run := range res.Runs {
		result.Runs = append(result.Runs, &plimsollv1.ModuleRowResult{Status: run.Status, Outputs: run.Outputs})
	}
	return &plimsollv1.RunResponse{
		Sandbox:    wireString(res.Sandbox),
		Isolation:  res.Isolation.String(),
		DurationMs: res.Duration.Milliseconds(),
		Result:     &plimsollv1.RunResponse_Module{Module: result},
	}, nil
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
		!errors.Is(err, context.Canceled) &&
		!errors.Is(err, context.DeadlineExceeded)
}

// mapSandboxErr translates a sandbox infrastructure error to a Connect code. A
// disabled provider is a precondition failure (the caller should configure one);
// an operation the configured provider structurally cannot do is Unimplemented;
// admission shedding is ResourceExhausted; anything else is an internal fault.
func mapSandboxErr(err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return connect.NewError(connect.CodeCanceled, err)
	case errors.Is(err, context.DeadlineExceeded):
		return connect.NewError(connect.CodeDeadlineExceeded, err)
	case errors.Is(err, sandbox.ErrDisabled):
		return connect.NewError(connect.CodeFailedPrecondition, err)
	case errors.Is(err, sandbox.ErrInsufficientIsolation):
		return connect.NewError(connect.CodeFailedPrecondition, err)
	case errors.Is(err, sandbox.ErrUnsupported):
		return connect.NewError(connect.CodeUnimplemented, err)
	case errors.Is(err, sandbox.ErrAtCapacity):
		return connect.NewError(connect.CodeResourceExhausted, err)
	case errors.Is(err, sandbox.ErrInvalidRequest):
		return connect.NewError(connect.CodeInvalidArgument, err)
	default:
		return connect.NewError(connect.CodeInternal, err)
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
