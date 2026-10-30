package rpc

import (
	"context"
	"log/slog"
	"time"

	"connectrpc.com/connect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/internal/quantise"
	"github.com/plimsollmark/plimsoll/internal/wireenum"
	"github.com/plimsollmark/plimsoll/internal/withheld"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// Every payload kind, as a run and as a session call, goes through one request
// pipeline: check (validate, grant, the floor, the software rule), then run (admit,
// dispatch, audit, answer). The order is the security order, the same for every
// kind: nothing is admitted, so no rate token is spent and no slot taken, before
// every check has passed. The one exception is a call the ship scan reads, the last
// check: the scan is work the rate must bound, so it takes the call's rate token
// before it runs, and admission then takes the slot alone (withheld.go). A session
// call checks before it takes the session's turn,
// so a call that can never run is refused as what it is, never as busy. What differs
// between kinds is a kind's.

// kind is one payload kind's part of the pipeline: its provider request and result,
// and the fields of its audit line and response.
type kind interface {
	// op names the kind on the audit line; msg is the line's message, with " failed"
	// added when the provider returns an error.
	op() string
	msg() string
	// check builds the provider request from the payload and the envelope and
	// validates it; an error is the request's own fault.
	check(env envelope) error
	// profile is the grant profile the payload names ("" for none, and always for a
	// kind that cannot carry a grant); setGrant puts the resolved grant on the request.
	profile() string
	setGrant(g *sandbox.HostAPIGrant)
	grant() *sandbox.HostAPIGrant
	// environment is where the kind runs on t.
	environment(t target) sandbox.PayloadEnvironment
	// requestAttrs describe the request on the audit line, never its content.
	requestAttrs() []slog.Attr
	// dispatch runs the request on t and keeps the result.
	dispatch(ctx context.Context, t target) error
	// trace is the brokered calls the run made, also after a failure.
	trace() *sandbox.CallTrace
	// ran is the result's evidence; took is the run's duration, given the time the
	// handler dispatched it.
	ran() evidence
	took(started time.Time) time.Duration
	// resultAttrs describe the result on the audit line.
	resultAttrs() []slog.Attr
	// answer puts the result, with the caller's advice, on the response.
	answer(resp *plimsollv1.RunResponse, advice []*plimsollv1.AdviceFinding)
	// shipped is what the call carries into its sandbox, for the ship scan (withheld.go):
	// a function that copies it out, or nil for a kind the scan does not read.
	shipped() func() []withheld.Part
}

// pipeline checks and runs one call.
func (s *SandboxService) pipeline(ctx context.Context, env envelope, k kind, t target) (*plimsollv1.RunResponse, error) {
	ctx, err := s.check(ctx, env, k, t)
	if err != nil {
		return nil, err
	}
	return s.run(ctx, env, k, t)
}

// check is everything before admission. The provider checks the floor and the rule
// again before it dispatches. The returned context carries the grant's subject.
func (s *SandboxService) check(ctx context.Context, env envelope, k kind, t target) (context.Context, error) {
	if err := k.check(env); err != nil {
		return ctx, refuse(connect.CodeInvalidArgument, sandbox.RefusalRequest, err)
	}
	grant, err := s.grantFor(ctx, k.profile())
	if err != nil {
		return ctx, err
	}
	if t.session {
		if err := sandbox.CheckSessionGrant(grant); err != nil {
			return ctx, mapSandboxErr(err)
		}
	}
	if grant != nil {
		ctx, err = applyGrantSubject(ctx, grant) // per-session token minting; refuses anon subject-bound grants
		if err != nil {
			return ctx, err
		}
	}
	k.setGrant(grant)
	if err := sandbox.CheckMinimumIsolation(t.tier, env.minimum); err != nil {
		return ctx, mapSandboxErr(err)
	}
	if err := env.software.Check(k.environment(t).SoftwareIdentity); err != nil {
		return ctx, mapSandboxErr(err)
	}
	// Last, so only a call that would otherwise run is scanned; the result rides on the
	// context to run's audit line and answer.
	return s.shipScan(ctx, env, k, t)
}

// run admits a checked call, dispatches it, writes its audit line and answers. The
// audit line carries what describes the call, never its content; the advisory channel
// runs after the result is final, so a run with advice is byte-identical in execution
// to one without.
func (s *SandboxService) run(ctx context.Context, env envelope, k kind, t target) (*plimsollv1.RunResponse, error) {
	// On a metered provider the run's whole possible cost is reserved first, against
	// the caller's and the daemon's allowances for the day, and settled at the end.
	// A request the provider cannot run reserves nothing: it is refused as what it is
	// (unsupported), never as a spent allowance. A panic under the run charges the time
	// since the reservation; a normal end settles first, which makes this a no-op.
	settle := func(time.Duration, time.Time) float64 { return 0 }
	var whole time.Duration // the reservation; 0 when nothing was reserved
	if t.teardown > 0 && s.Spend != nil && s.supports(k) {
		p, _ := PrincipalFrom(ctx)
		reserved := time.Now()
		whole = reservation(env.timeout, k.environment(t).MaxTimeout, t.teardown)
		var err error
		if settle, err = s.Spend.reserve(auditCaller(ctx), p.PaidSecondsPerDay, whole); err != nil {
			return nil, err
		}
		defer func() { settle(time.Since(reserved), time.Time{}) }()
	}
	release, err := t.admit(ctx)
	if err != nil {
		settle(0, time.Time{})
		return nil, err
	}
	// The slot comes back once the call has returned and its sandbox is gone, which
	// can be later for a provider that deletes it off the result path (HoldCapacity).
	ctx, release = sandbox.WithCapacity(ctx, release)
	defer release()

	s.runsTotal.Add(1)
	runCtx, cancel := runContext(ctx)
	defer cancel()
	// A microVM the provider could not delete bills on until the provider's own
	// lifetime for it ends: the run is charged its whole reservation, and owes until
	// the time the provider said, when that is later than the reservation's window
	// (sandbox.WatchTeardownUntil, SpendCap.leak).
	runCtx, teardownGaveUp := sandbox.WatchTeardownUntil(runCtx)
	started := time.Now()
	err = k.dispatch(runCtx, t)
	billed := time.Since(started)
	gaveUp, billsUntil := teardownGaveUp()
	leaked := whole > 0 && gaveUp
	if leaked {
		billed = whole
	} else {
		billsUntil = time.Time{}
	}
	charged := settle(billed, billsUntil)
	attrs := append([]slog.Attr{slog.String("op", k.op()), slog.String("caller", auditCaller(ctx))}, k.requestAttrs()...)
	if t.teardown > 0 && s.Spend != nil {
		attrs = append(attrs, slog.Float64("paid_seconds", charged))
	}
	if leaked {
		attrs = append(attrs, slog.Bool("teardown_gave_up", true))
	}
	scan := shipScanFrom(ctx)
	attrs = append(attrs, scan.attrs()...)
	// A run can fail after it brokered calls; they happened, so they are counted.
	s.hostCalls.observe(k.profile(), k.trace())
	if err != nil {
		if isInfraErr(err) {
			s.runsFailed.Add(1)
		}
		attrs = append(attrs,
			slog.String("sandbox", t.provider),
			slog.String("isolation", t.tier.String()),
			slog.Int64("duration_ms", time.Since(started).Milliseconds()),
			errAttr(err))
		attrs = append(attrs, hostCallAttrs(k.trace())...)
		// A failed run is exactly the one an operator will go looking for, so it
		// carries the join key too.
		attrs = append(append(attrs, traceAttrs(env.traceID)...), t.attrs...)
		s.logger().LogAttrs(ctx, slog.LevelError, k.msg()+" failed", attrs...)
		return nil, mapSandboxErr(err)
	}
	ev := k.ran()
	provider, isolation, software, environment := ev.provider, ev.isolation, ev.software, ev.environment
	instance := ev.instance
	if !sandbox.ValidInstance(instance) {
		// A provider's bug, never the caller's text: the record names no instance rather
		// than one outside the typed form, and the operator sees that it happened.
		attrs = append(attrs, slog.Bool("instance_rejected", true))
		instance = ""
	}
	took := k.took(started)
	attrs = append(attrs, slog.String("sandbox", provider), slog.String("isolation", isolation.String()))
	attrs = append(attrs, k.resultAttrs()...)
	attrs = append(attrs, slog.Int64("duration_ms", took.Milliseconds()))
	if t, ok := k.(trailer); ok {
		attrs = append(attrs, t.trailingAttrs()...)
	}
	// The caller's opaque join key, so this metadata-only line can be matched to the
	// caller's own record of the same request. Recorded, never interpreted.
	attrs = append(append(attrs, traceAttrs(env.traceID)...), t.attrs...)
	// Bounded, metadata-only summary of the run's brokered host.* calls (never paths,
	// bodies, or credentials). Emitted only when the run brokered something.
	attrs = append(attrs, hostCallAttrs(k.trace())...)
	// The advisory channel, over the immutable CallTrace: findings go to the operator
	// surface (audit) for operator|caller; only the agent-fixable subset returns to
	// the caller, and only for caller. The /metrics aggregates carry no route
	// templates and are not gated by advice_retention; the durable audit record of
	// the findings is, and is off by default.
	profile := k.profile()
	mode := s.adviceFor(profile)
	all, caller := computeAdvice(mode, k.trace(), s.adviceRoutes(profile, k.grant()))
	s.adviceStats.observe(profile, all)
	attrs = append(attrs, adviceAuditAttrs(mode, s.adviceRetentionFor(profile), all)...)
	s.logger().LogAttrs(ctx, slog.LevelInfo, k.msg(), attrs...)

	described := k.environment(t)
	resp := &plimsollv1.RunResponse{
		Sandbox:          wireString(provider),
		Isolation:        isolation.String(),
		DurationMs:       took.Milliseconds(),
		SoftwareIdentity: t.ranSoftware(software, described.SoftwareIdentity),
		Environment:      describedEnvironment(environment, described.Identity),
		Instance:         instance,
	}
	k.answer(resp, adviceWire(caller))
	return resp, nil
}

// evidence is what a result states it ran under: the provider, the tier, the selected
// software, the outer environment and the sandbox instance.
type evidence struct {
	provider    string
	isolation   sandbox.IsolationClass
	software    string
	environment string
	instance    string
	// policy is the sandbox policy this run was dispatched under, when the provider
	// states one per run (docker names the seccomp profile a run applied); "" means
	// the provider's one policy, which the daemon states (SandboxService.policy).
	policy string
}

// trailer is a kind whose audit line carries more after the duration.
type trailer interface{ trailingAttrs() []slog.Attr }

// reservation is what a run on a metered provider reserves: its timeout as it will be
// clamped (the provider's ceiling, itself at most the RPC ceiling, when the request
// leaves it to the provider's default, which is at most that), plus the provider's
// teardown bound.
func reservation(requested, ceiling, teardown time.Duration) time.Duration {
	if ceiling <= 0 || ceiling > maxRunTimeout {
		ceiling = maxRunTimeout
	}
	if requested <= 0 || requested > ceiling {
		requested = ceiling
	}
	return requested + teardown
}

// supports reports whether the provider can run k as it stands: what it states through
// the capability interfaces. A kind it cannot run is refused by the provider, before
// anything runs.
func (s *SandboxService) supports(k kind) bool {
	switch k := k.(type) {
	case *javascriptKind:
		g, ok := s.Sandbox.(sandbox.GrantCapable)
		return k.g == nil || (ok && g.SupportsJavaScriptGrants())
	case *projectKind:
		p, ok := s.Sandbox.(sandbox.ProjectCapable)
		g, gok := s.Sandbox.(sandbox.GrantCapable)
		return ok && p.SupportsProjects() && (k.g == nil || (gok && g.SupportsProjectGrants()))
	case *moduleKind:
		m, ok := s.Sandbox.(sandbox.ModuleCapable)
		return ok && m.SupportsModules()
	}
	return true
}

// grantHolder is the grant a kind's request carries.
type grantHolder struct{ g *sandbox.HostAPIGrant }

func (h *grantHolder) setGrant(g *sandbox.HostAPIGrant) { h.g = g }
func (h *grantHolder) grant() *sandbox.HostAPIGrant     { return h.g }

// javascriptKind is a snippet.
type javascriptKind struct {
	grantHolder
	p   *plimsollv1.JavaScriptRun
	req sandbox.Request
	res sandbox.Result
}

func (*javascriptKind) op() string  { return "javascript" }
func (*javascriptKind) msg() string { return "code run" }
func (k *javascriptKind) check(env envelope) error {
	k.req = sandbox.Request{Code: k.p.GetCode(), Timeout: env.timeout, MinimumIsolation: env.minimum, Software: env.software}
	return sandbox.ValidateRequest(k.req)
}
func (k *javascriptKind) profile() string { return k.p.GetGrantProfile() }
func (*javascriptKind) environment(t target) sandbox.PayloadEnvironment {
	return t.software.JavaScript
}
func (k *javascriptKind) requestAttrs() []slog.Attr {
	return []slog.Attr{slog.Int("code_bytes", len(k.req.Code)), slog.String("grant_profile", k.p.GetGrantProfile())}
}
func (k *javascriptKind) dispatch(ctx context.Context, t target) (err error) {
	k.req.Grant = k.g
	k.res, err = t.js(ctx, k.req)
	return err
}
func (k *javascriptKind) trace() *sandbox.CallTrace { return k.res.CallTrace }
func (k *javascriptKind) ran() evidence {
	return evidence{k.res.Sandbox, k.res.Isolation, k.res.SoftwareIdentity, k.res.EnvironmentIdentity, k.res.Instance, k.res.Policy}
}
func (k *javascriptKind) took(time.Time) time.Duration { return k.res.Duration }
func (k *javascriptKind) resultAttrs() []slog.Attr {
	return []slog.Attr{slog.Int("exit_code", k.res.ExitCode), slog.Bool("timed_out", k.res.TimedOut)}
}
func (k *javascriptKind) answer(resp *plimsollv1.RunResponse, advice []*plimsollv1.AdviceFinding) {
	resp.Result = &plimsollv1.RunResponse_Javascript{Javascript: &plimsollv1.JavaScriptResult{
		Stdout:          []byte(k.res.Stdout),
		Stderr:          []byte(k.res.Stderr),
		StdoutTruncated: k.res.StdoutTruncated,
		StderrTruncated: k.res.StderrTruncated,
		ExitCode:        int32(k.res.ExitCode),
		TimedOut:        k.res.TimedOut,
		Advice:          advice,
	}}
}

// projectKind is files written, steps run in order, artifacts captured.
type projectKind struct {
	grantHolder
	p     *plimsollv1.ProjectRun
	req   sandbox.ProjectRequest
	res   sandbox.ProjectResult
	bytes int
}

func (*projectKind) op() string  { return "project" }
func (*projectKind) msg() string { return "project run" }
func (k *projectKind) check(env envelope) error {
	files := make([]sandbox.File, 0, len(k.p.GetFiles()))
	for _, f := range k.p.GetFiles() {
		k.bytes += len(f.GetContent())
		files = append(files, sandbox.File{Path: f.GetPath(), Content: f.GetContent()})
	}
	k.req = sandbox.ProjectRequest{
		Files:            files,
		Steps:            append([]string(nil), k.p.GetSteps()...),
		Timeout:          env.timeout,
		Artifacts:        append([]string(nil), k.p.GetArtifacts()...),
		MinimumIsolation: env.minimum,
		Software:         env.software,
	}
	return sandbox.ValidateProjectRequest(k.req)
}
func (k *projectKind) profile() string { return k.p.GetGrantProfile() }
func (*projectKind) environment(t target) sandbox.PayloadEnvironment {
	return t.software.Project
}
func (k *projectKind) requestAttrs() []slog.Attr {
	return []slog.Attr{slog.Int("files", len(k.req.Files)), slog.Int("steps", len(k.req.Steps)),
		slog.Int("total_bytes", k.bytes), slog.String("grant_profile", k.p.GetGrantProfile())}
}
func (k *projectKind) dispatch(ctx context.Context, t target) (err error) {
	k.req.Grant = k.g
	k.res, err = t.project(ctx, k.req)
	return err
}
func (k *projectKind) trace() *sandbox.CallTrace { return k.res.CallTrace }
func (k *projectKind) ran() evidence {
	return evidence{k.res.Sandbox, k.res.Isolation, k.res.SoftwareIdentity, k.res.EnvironmentIdentity, k.res.Instance, k.res.Policy}
}

// took is the handler's clock: a project result states its steps' durations, not
// its own.
func (*projectKind) took(started time.Time) time.Duration { return time.Since(started) }

// resultAttrs states the run's outcome, and from it whether the run timed out: a run
// stopped by the outer deadline reports no step, and read off the last step alone it was
// logged timed_out=false, exit_code=0 (review, 2026-10-23). The exit code is the last
// reported step's, and absent when no step reported, which is not an exit code of 0
// (auditline.Run.ExitCode).
func (k *projectKind) resultAttrs() []slog.Attr {
	timedOut := k.res.Outcome == sandbox.ProjectOutcomeTimedOut
	attrs := []slog.Attr{
		slog.String("outcome", k.res.Outcome.String()),
		slog.String("outcome_detail", k.res.Detail),
		slog.Int("steps_ran", len(k.res.Steps)),
	}
	if len(k.res.Steps) > 0 {
		last := k.res.Steps[len(k.res.Steps)-1]
		timedOut = timedOut || last.TimedOut
		attrs = append(attrs, slog.Int("exit_code", last.ExitCode))
	}
	return append(attrs, slog.Bool("timed_out", timedOut))
}
func (k *projectKind) answer(resp *plimsollv1.RunResponse, advice []*plimsollv1.AdviceFinding) {
	result := &plimsollv1.ProjectResult{
		Outcome:            wireenum.OutcomeToWire(k.res.Outcome),
		OutcomeDetail:      wireString(k.res.Detail),
		ArtifactsTruncated: k.res.ArtifactsTruncated,
		Advice:             advice,
	}
	for _, st := range k.res.Steps {
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
	for _, a := range k.res.Artifacts {
		result.Artifacts = append(result.Artifacts, &plimsollv1.Artifact{Path: wireString(a.Path), Content: a.Content})
	}
	resp.Result = &plimsollv1.RunResponse_Project{Project: result}
}

// moduleKind is a compiled simulator once per parameter row. No grant: a simulator
// has no host API and the payload cannot name one. The audit line names the model
// (validated to a filename stem) and counts rows, values per row and the step bound;
// a parameter value never reaches a log.
type moduleKind struct {
	grantHolder
	p   *plimsollv1.ModuleRun
	req sandbox.ModuleRequest
	res sandbox.ModuleResult
}

func (*moduleKind) op() string  { return "module" }
func (*moduleKind) msg() string { return "module run" }
func (k *moduleKind) check(env envelope) error {
	rows := make([][]float64, 0, len(k.p.GetRows()))
	for _, r := range k.p.GetRows() {
		rows = append(rows, append([]float64(nil), r.GetValues()...))
	}
	k.req = sandbox.ModuleRequest{
		Model:            k.p.GetModel(),
		Rows:             rows,
		EndTime:          k.p.GetEndTime(),
		Step:             k.p.GetStep(),
		Timeout:          env.timeout,
		MinimumIsolation: env.minimum,
		Software:         env.software,
	}
	return sandbox.ValidateModuleRequest(k.req)
}
func (*moduleKind) profile() string { return "" }
func (*moduleKind) environment(t target) sandbox.PayloadEnvironment {
	return t.software.Module
}
func (k *moduleKind) requestAttrs() []slog.Attr {
	return []slog.Attr{slog.String("model", k.req.Model), slog.Int("rows", len(k.req.Rows)),
		slog.Int("row_width", k.req.RowWidth()), slog.Int("max_steps", k.req.MaxSteps())}
}
func (k *moduleKind) dispatch(ctx context.Context, t target) (err error) {
	k.res, err = t.module(ctx, k.req)
	return err
}
func (*moduleKind) trace() *sandbox.CallTrace { return nil }
func (k *moduleKind) ran() evidence {
	return evidence{k.res.Sandbox, k.res.Isolation, k.res.SoftwareIdentity, k.res.EnvironmentIdentity, k.res.Instance, k.res.Policy}
}
func (k *moduleKind) took(time.Time) time.Duration { return k.res.Duration }

func (k *moduleKind) resultAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("outcome", k.res.Outcome.String()),
		slog.String("outcome_detail", k.res.Detail),
		slog.Int("runs", len(k.res.Runs)),
		slog.Int("width", k.res.Width),
		slog.Bool("timed_out", k.res.Outcome == sandbox.ProjectOutcomeTimedOut),
	}
}

// trailingAttrs say, post-dispatch and over results already computed, how many of the
// caller's rows returned an answer it already had (counts only: the tread widths
// derive from differences between the caller's parameter values, and the audit line
// carries no parameter value).
func (k *moduleKind) trailingAttrs() []slog.Attr {
	var attrs []slog.Attr
	for _, f := range quantise.Analyze(k.req.Rows, k.res.Runs) {
		attrs = append(attrs,
			slog.Int("tread_column", f.Column),
			slog.Int("tread_distinct", f.Distinct),
			slog.Int("tread_repeated", f.Repeated),
			slog.Int("tread_flat", f.Flat),
			slog.Bool("tread_covers_whole_sweep", f.WholeSweepInOneTread()),
		)
	}
	return attrs
}
func (k *moduleKind) answer(resp *plimsollv1.RunResponse, _ []*plimsollv1.AdviceFinding) {
	result := &plimsollv1.ModuleResult{
		Width:         int32(k.res.Width),
		Outcome:       wireenum.OutcomeToWire(k.res.Outcome),
		OutcomeDetail: wireString(k.res.Detail),
		Stdout:        []byte(k.res.Stdout),
		Stderr:        []byte(k.res.Stderr),
	}
	for _, run := range k.res.Runs {
		result.Runs = append(result.Runs, &plimsollv1.ModuleRowResult{Status: run.Status, Outputs: canonicalNaNs(run.Outputs)})
	}
	resp.Result = &plimsollv1.RunResponse_Module{Module: result}
}

// cellKind is code handed to an interpreter for its language, after the cell's files
// are written: a session's, or for a cell Run runs by itself (run), one in a sandbox of
// its own (onecall.go). A cell carries no grant.
type cellKind struct {
	grantHolder
	p   *plimsollv1.CellRun
	req sandbox.CellRequest
	res sandbox.CellResult
	run bool
}

func (*cellKind) op() string  { return "cell" }
func (*cellKind) msg() string { return "code run" }

// request is the cell as the provider takes it.
func (k *cellKind) request(env envelope) sandbox.CellRequest {
	files := make([]sandbox.File, 0, len(k.p.GetFiles()))
	for _, f := range k.p.GetFiles() {
		files = append(files, sandbox.File{Path: f.GetPath(), Content: f.GetContent()})
	}
	return sandbox.CellRequest{
		Language: sandbox.Language(k.p.GetLanguage()), Code: k.p.GetCode(), Files: files,
		Timeout: env.timeout, MinimumIsolation: env.minimum, Software: env.software,
	}
}

func (k *cellKind) check(env envelope) error {
	k.req = k.request(env)
	return sandbox.ValidateCellRequest(k.req)
}
func (*cellKind) profile() string { return "" }

// environment is the session's project environment: a cell runs in the session's
// one sandbox.
func (*cellKind) environment(t target) sandbox.PayloadEnvironment {
	return t.software.Project
}
func (k *cellKind) requestAttrs() []slog.Attr {
	return []slog.Attr{slog.String("language", string(k.req.Language)), slog.Int("code_bytes", len(k.req.Code)),
		slog.Int("files", len(k.req.Files))}
}
func (k *cellKind) dispatch(ctx context.Context, t target) (err error) {
	k.res, err = t.cell(ctx, k.req)
	return err
}
func (*cellKind) trace() *sandbox.CallTrace { return nil }
func (k *cellKind) ran() evidence {
	return evidence{k.res.Sandbox, k.res.Isolation, k.res.SoftwareIdentity, k.res.EnvironmentIdentity, k.res.Instance, k.res.Policy}
}
func (k *cellKind) took(time.Time) time.Duration { return k.res.Duration }
func (k *cellKind) resultAttrs() []slog.Attr {
	attrs := []slog.Attr{
		slog.Int("exit_code", k.res.ExitCode),
		slog.Bool("timed_out", k.res.TimedOut),
		slog.Bool("interpreter_started", k.res.InterpreterStarted),
		slog.Bool("interpreter_ended", k.res.InterpreterEnded),
	}
	if k.run {
		// Which sandbox a cell Run ran by itself was in: a waiting pool member, or one
		// made for it.
		attrs = append(attrs, slog.Bool("warm", k.res.Warm))
	}
	return attrs
}
func (k *cellKind) answer(resp *plimsollv1.RunResponse, _ []*plimsollv1.AdviceFinding) {
	resp.Warm = k.res.Warm
	resp.Result = &plimsollv1.RunResponse_Cell{Cell: &plimsollv1.CellResult{
		Stdout:             []byte(k.res.Stdout),
		Stderr:             []byte(k.res.Stderr),
		ExitCode:           int32(k.res.ExitCode),
		TimedOut:           k.res.TimedOut,
		StdoutTruncated:    k.res.StdoutTruncated,
		StderrTruncated:    k.res.StderrTruncated,
		InterpreterStarted: k.res.InterpreterStarted,
		InterpreterEnded:   k.res.InterpreterEnded,
	}}
}
