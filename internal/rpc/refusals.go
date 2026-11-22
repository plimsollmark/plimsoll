package rpc

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"

	"github.com/plimsollmark/plimsoll/internal/wireenum"
)

// A call refused before anything ran used to leave no line in the audit stream unless
// its refusal had a line of its own (the ship scan's, a session attach's): a caller
// trying grant profile names, a floor its provider cannot meet or a procedure its token
// lacks the scope for was invisible to the operator (hunt-security-3, 2026-11-20). Every
// such refusal of a known caller now passes through one refusal log, which writes one line
// per caller per refusalLogEvery:
//
//	caller     the principal (an operator-defined identity, or "anon" in open mode)
//	procedure  the procedure Connect routed (a fixed name; "unknown" for a path the
//	           scope check refused before routing)
//	code       the Connect code
//	reason     the not-dispatched reason, one of the fixed sandbox.Refusal words
//	refused    how many refusals the line stands for: this one and those folded since
//	           the caller's previous line
//	trace_id   the caller's join key, through traceAttrs (dropped whole if malformed)
//
// It never carries the refusal's text or anything else the caller sent: the text of a
// grant profile refusal names the profile the caller asked for, and caller text does not
// enter the audit stream (trace.go).
//
// Where it sits: the refusal interceptor NewHandler installs (outermost after
// HandlerReached) sees every error a procedure returns, the procedure's own refusals and
// AuthInterceptor's scope refusal alike, and notes the ones that carry the not-dispatched
// mark; AuthenticateHTTP notes its scope refusal, which is answered before Connect. A
// refusal whose request already has a line of its own is not noted twice (see
// markRefusalLogged): the ship scan's refusal, a session attach's, a session open that
// failed in the provider, and a run's "failed" line. A refused credential is not noted
// here either: no caller is known, and authFailureLog counts those.

const (
	// refusalLogEvery is how often one caller's refusals get a line: the bad-credential
	// log's window (authFailureLogEvery), read at the same human pace.
	refusalLogEvery = 30 * time.Second
	// refusalLogCallers bounds the table of callers seen within the window. Callers come
	// from the callers file or an embedder's verifier, so a deployment has far fewer;
	// past it, refusals of callers not in the table fold into one line without a caller,
	// so a verifier that mints identities cannot grow the table, and the log carries at
	// most refusalLogCallers+1 lines per window.
	refusalLogCallers = 1024
)

// RefusalNoter is told of a call refused before anything ran. A SandboxService is one;
// AuthenticateHTTP takes one for the scope refusal it answers before Connect.
type RefusalNoter interface {
	NoteRefusal(caller, procedure string, err error)
}

// NoteRefusal puts a refusal of caller's on the service's refusal log. err is the
// refusal as refuse built it; an error without the not-dispatched mark is ignored.
func (s *SandboxService) NoteRefusal(caller, procedure string, err error) {
	s.refusals.note(s.logger(), caller, procedure, err, "")
}

type refusalEntry struct {
	logged                  time.Time // when this caller's last line was written
	folded                  int       // refusals since then, not yet on a line
	procedure, code, reason string    // the last folded refusal's
}

// refusalLog is the rate limit. Its zero value is ready to use.
type refusalLog struct {
	now func() time.Time // nil = time.Now; tests set it

	mu      sync.Mutex
	callers map[string]*refusalEntry
	over    refusalEntry // callers past the table's bound
	swept   time.Time
}

type refusalLine struct {
	caller                  string // "" = past the table's bound
	procedure, code, reason string
	refused                 int
	trace                   string
}

func (l *refusalLog) clock() time.Time {
	if l.now != nil {
		return l.now()
	}
	return time.Now()
}

func (l *refusalLog) note(log *slog.Logger, caller, procedure string, err error, traceID string) {
	r, marked := notDispatchedOf(err)
	if !marked {
		return
	}
	code := connect.CodeOf(err).String()
	reason := wireenum.RefusalFromWire(r).String()
	now := l.clock()
	var lines []refusalLine
	l.mu.Lock()
	if l.callers == nil {
		l.callers = map[string]*refusalEntry{}
	}
	// Once a window, entries whose window has passed leave the table; a count still
	// owed goes on a line of its own then, so a caller that stops refusing does not take
	// its last count with it. This refusal's caller keeps its entry: its count goes on
	// the line this refusal writes.
	if now.Sub(l.swept) >= refusalLogEvery {
		l.swept = now
		for c, e := range l.callers {
			if c != caller && now.Sub(e.logged) >= refusalLogEvery {
				if e.folded > 0 {
					lines = append(lines, refusalLine{caller: c, procedure: e.procedure, code: e.code, reason: e.reason, refused: e.folded})
				}
				delete(l.callers, c)
			}
		}
		if now.Sub(l.over.logged) >= refusalLogEvery && l.over.folded > 0 {
			o := l.over
			lines = append(lines, refusalLine{procedure: o.procedure, code: o.code, reason: o.reason, refused: o.folded})
			l.over = refusalEntry{}
		}
	}
	e, key := l.callers[caller], caller
	if e == nil {
		if len(l.callers) < refusalLogCallers {
			e = &refusalEntry{}
			l.callers[caller] = e
		} else {
			e, key = &l.over, ""
		}
	}
	if !e.logged.IsZero() && now.Sub(e.logged) < refusalLogEvery {
		e.folded++
		e.procedure, e.code, e.reason = procedure, code, reason
	} else {
		lines = append(lines, refusalLine{caller: key, procedure: procedure, code: code, reason: reason, refused: e.folded + 1, trace: traceID})
		e.logged, e.folded = now, 0
	}
	l.mu.Unlock()
	for _, ln := range lines {
		attrs := make([]slog.Attr, 0, 8)
		if ln.caller != "" {
			attrs = append(attrs, slog.String("caller", ln.caller))
		} else {
			attrs = append(attrs, slog.Bool("callers_over_bound", true))
		}
		attrs = append(attrs,
			slog.String("procedure", ln.procedure),
			slog.String("code", ln.code),
			slog.String("reason", ln.reason),
			slog.Int("refused", ln.refused),
			slog.String("window", refusalLogEvery.String()))
		attrs = append(attrs, traceAttrs(ln.trace)...)
		log.LogAttrs(context.Background(), slog.LevelWarn, "call refused before it ran", attrs...)
	}
}

// refusalState rides a request's context from the refusal interceptor inward.
type refusalState struct {
	logged atomic.Bool // the refusal already has a line of its own
	caller atomic.Pointer[string]
}

type refusalStateKey struct{}

// markRefusalLogged records that the request's refusal has a line of its own, so the
// refusal log does not write a second. Every site that writes a line for a refusal calls
// it; a site that forgets costs one more rate-limited line, never a missing one.
func markRefusalLogged(ctx context.Context) {
	if st, ok := ctx.Value(refusalStateKey{}).(*refusalState); ok {
		st.logged.Store(true)
	}
}

// noteCaller tells the refusal interceptor who the caller is, for a principal the
// interceptor cannot see because AuthInterceptor stamps it on the context it passes inward.
func noteCaller(ctx context.Context, p Principal) {
	if st, ok := ctx.Value(refusalStateKey{}).(*refusalState); ok {
		c := auditCallerOf(p)
		st.caller.Store(&c)
	}
}

func auditCallerOf(p Principal) string {
	if p.UserID != "" {
		return p.UserID
	}
	return "anon"
}

// refusalInterceptor notes every refusal a procedure returns that has no line of its own,
// for a caller who is known (stamped by AuthenticateHTTP, or by AuthInterceptor through
// noteCaller). A call with no known caller (a refused credential under AuthInterceptor
// alone) is not noted.
func refusalInterceptor(s *SandboxService) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			st := &refusalState{}
			resp, err := next(context.WithValue(ctx, refusalStateKey{}, st), req)
			if err == nil || st.logged.Load() {
				return resp, err
			}
			caller := ""
			if p, ok := PrincipalFrom(ctx); ok {
				caller = auditCallerOf(p)
			} else if c := st.caller.Load(); c != nil {
				caller = *c
			}
			if caller == "" {
				return resp, err
			}
			var trace string
			if m, ok := req.Any().(interface{ GetTraceId() string }); ok {
				trace = m.GetTraceId()
			}
			s.refusals.note(s.logger(), caller, req.Spec().Procedure, err, trace)
			return resp, err
		}
	}
}
