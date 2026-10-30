package rpc

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// A cell Run runs by itself keeps nothing for a later call, so it runs in a sandbox of
// its own: a waiting pool member when the call asks for one (prefer_warm) and one fits,
// else one made for it (sandbox.RunCellFresh). Either way it goes through Run's whole
// pipeline first (pipeline.go): the floor, the software rule, the ship scan, the spend
// reservation and the caller's limiter are the same for both, and checked in the same
// place, before either sandbox is touched.
//
// A pool member has run only plimsoll's own programs, is handed to this one call and is
// deleted after it, never returned to the pool: the rule the pool keeps for sessions
// (docs/sessions.md, "A warm pool"). The session the member is opened as never enters the
// session table: its ID never leaves this file, so nothing else can call it, and the
// call holds a run's place, not a session's.
//
// Cancellation is decided here, once. A call canceled before or while its member is
// claimed is answered canceled and marked not dispatched, since nothing of it ran, and
// it is not run fresh either; a member claimed after the cancel is closed unused. A call
// canceled during its cell is answered canceled and unmarked: the code may have run.
// The member is closed on every path, the run's slot held until it is gone.

// oneCallMargin is a member's lifetime beyond the call's budget, for the claim before
// the cell and the close after it: ample for both, and short, since the lifetime is
// what bounds a member whose close never came.
const oneCallMargin = time.Minute

// cellRun is how Run runs its cell.
func (s *SandboxService) cellRun(preferWarm bool) func(context.Context, sandbox.CellRequest) (sandbox.CellResult, error) {
	return func(ctx context.Context, req sandbox.CellRequest) (sandbox.CellResult, error) {
		if preferWarm {
			if res, served, err := s.warmCell(ctx, req); served || err != nil {
				return res, err
			}
		}
		return sandbox.RunCellFresh(ctx, s.Sandbox, req)
	}
}

// fitsCell reports whether a sandbox of env can run req's cell: it runs the language and
// meets the request's software rule, as an open checks a session's.
func fitsCell(env sandbox.Environments, req sandbox.CellRequest) bool {
	return (env.JavaScript.SupportsLanguage(req.Language) || env.Project.SupportsLanguage(req.Language)) &&
		req.Software.Check(env.JavaScript.SoftwareIdentity) == nil && req.Software.Check(env.Project.SoftwareIdentity) == nil
}

// warmCell runs req in a waiting pool member, when this daemon keeps a pool and one fits.
// served is false with a nil error when none did and nothing of the call ran: no pool, a
// language or rule the members do not meet, a claim refused (none waiting, no slot), a
// claimed member whose identity no longer meets the rule or whose tier is below the
// call's floor, or one whose cell was refused before any of it ran for a reason a fresh
// sandbox does not share. The caller then runs it fresh, so a miss is never a refusal of
// its own. served is false with an error only for a call canceled before its cell was
// sent (not dispatched); every other error is the cell's, as is.
func (s *SandboxService) warmCell(ctx context.Context, req sandbox.CellRequest) (res sandbox.CellResult, served bool, err error) {
	sp, ok := s.sessionProvider()
	if !ok || s.Sessions.Pool <= 0 {
		return res, false, nil
	}
	stated := sp.SessionEnvironments()
	if !fitsCell(stated, req) {
		return res, false, nil
	}
	languages, err := sandbox.SessionLanguages([]sandbox.Language{req.Language}, stated.Project.Languages)
	if err != nil {
		return res, false, nil
	}
	// The session must outlive its one cell: the call's budget, or with none the longest a
	// cell may take there, at most the RPC ceiling, plus the margin; never longer than the
	// daemon's session lifetime, for which the pool made its members.
	budget := req.Timeout
	if budget <= 0 {
		budget = stated.Project.MaxTimeout
	}
	if budget <= 0 || budget > maxRunTimeout {
		budget = maxRunTimeout
	}
	sess, err := sp.OpenSession(ctx, sandbox.SessionOptions{
		MinimumIsolation: req.MinimumIsolation,
		Lifetime:         min(s.Sessions.Lifetime, budget+oneCallMargin),
		DiskBytes:        s.Sessions.DiskBytes,
		Languages:        languages,
		WarmOnly:         true,
	})
	if err != nil {
		if ctx.Err() != nil {
			return res, false, sandbox.RefuseGaveUp(ctx)
		}
		return res, false, nil
	}
	// The member goes when the call does, on every path below, off the answer's path; the
	// run's slot stays held until its sandbox is gone, as for a provider that deletes a
	// fresh run's sandbox after answering.
	hold := sandbox.HoldCapacity(ctx)
	defer func() {
		go func() {
			closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), sessionOrphanCloseBudget)
			err := sess.Close(closeCtx)
			cancel()
			if err != nil {
				s.logger().LogAttrs(context.WithoutCancel(ctx), slog.LevelWarn, "closing a pool member after its one call failed; its lifetime ends it", errAttr(err))
			}
			<-sess.Done()
			hold()
		}()
	}()
	if ctx.Err() != nil {
		return res, false, sandbox.RefuseGaveUp(ctx)
	}
	// The rule again, against what the member runs: the provider can refresh its image
	// while members wait, so what it stated before may name an earlier one.
	opened := sess.Environments()
	if !fitsCell(opened, req) {
		return res, false, nil
	}
	// The floor (the request's, raised to the daemon's where the envelope was parsed)
	// again, against the tier the member measured when it was made: the pipeline checked
	// the provider's evidence as it stands, and a member made earlier may sit below it.
	if sandbox.CheckMinimumIsolation(sess.Isolation(), req.MinimumIsolation) != nil {
		return res, false, nil
	}
	res, err = sess.RunCell(ctx, req)
	if err != nil {
		reason, marked := sandbox.NotDispatchedReason(err)
		if marked && ctx.Err() == nil && (reason != sandbox.RefusalRequest || errors.Is(err, sandbox.ErrSessionEnded)) {
			// None of it ran (an interpreter that could not start, a member that ended
			// first), for a reason of this member's: a fresh sandbox may well run it. A
			// request's own fault, its files, would fail there the same way, so it stands.
			return sandbox.CellResult{}, false, nil
		}
		res.Warm = true
		return res, true, err
	}
	// A Run's cell keeps nothing on either path: its interpreter is gone with the member.
	res.Warm, res.InterpreterStarted, res.InterpreterEnded = true, true, true
	if res.SoftwareIdentity == "" {
		res.SoftwareIdentity = opened.Project.SoftwareIdentity
	}
	if res.EnvironmentIdentity == "" {
		res.EnvironmentIdentity = opened.Project.Identity
	}
	return res, true, nil
}
