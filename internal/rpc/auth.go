// Package rpc serves the plimsoll SandboxService over Connect, wrapping the
// transport-agnostic sandbox package with auth, rate limiting, and request
// validation. The sandbox package itself stays free of transport concerns.
package rpc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"connectrpc.com/connect"

	"github.com/plimsollmark/plimsoll/sandbox"

	"github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1/plimsollv1connect"
)

// ScopeCodeRun is the scope a caller must hold to execute code. It is the only
// scope this service grants; a token that lacks it cannot run anything.
const ScopeCodeRun = "code:run"

// requiredScopes maps each procedure to the scope it requires. A procedure that
// is NOT listed is denied by default — new RPCs are locked down until explicitly
// granted a scope here (fail-closed).
var requiredScopes = map[string]string{
	plimsollv1connect.SandboxServiceRunProcedure: ScopeCodeRun,
	// Describe runs no code, but it describes the code-running boundary; its only
	// audience is code-running callers, so it shares their scope.
	plimsollv1connect.SandboxServiceDescribeProcedure: ScopeCodeRun,
	// A session is code execution spread over calls; all three share the scope.
	plimsollv1connect.SandboxServiceOpenSessionProcedure:  ScopeCodeRun,
	plimsollv1connect.SandboxServiceSessionRunProcedure:   ScopeCodeRun,
	plimsollv1connect.SandboxServiceCloseSessionProcedure: ScopeCodeRun,
}

// Principal is an authenticated caller.
type Principal struct {
	UserID string
	Scopes []string
	// PaidSecondsPerDay is the caller's daily allowance on a metered provider (its
	// paid_seconds_per_day); 0 = none of its own (SpendCap).
	PaidSecondsPerDay int64
}

// HasScope reports whether the principal holds scope (or the "*" wildcard).
func (p Principal) HasScope(scope string) bool {
	for _, s := range p.Scopes {
		if s == scope || s == "*" {
			return true
		}
	}
	return false
}

type principalKey struct{}

// PrincipalFrom returns the caller stamped by AuthInterceptor, if any.
func PrincipalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}

// TokenVerifier resolves a bearer token to a Principal. ok=false means the token
// is unknown/expired (the interceptor maps that to Unauthenticated).
type TokenVerifier interface {
	VerifyToken(ctx context.Context, token string) (principal Principal, ok bool, err error)
}

func authenticatePrincipal(ctx context.Context, header string, verifier TokenVerifier) (Principal, error) {
	token := bearerToken(header)
	if token == "" {
		return Principal{}, refuse(connect.CodeUnauthenticated, sandbox.RefusalPermission, errors.New("missing bearer token"))
	}
	p, ok, err := verifier.VerifyToken(ctx, token)
	if err != nil {
		switch {
		case errors.Is(err, context.Canceled):
			return Principal{}, connect.NewError(connect.CodeCanceled, context.Canceled)
		case errors.Is(err, context.DeadlineExceeded):
			return Principal{}, connect.NewError(connect.CodeDeadlineExceeded, context.DeadlineExceeded)
		default:
			slog.Error("token verifier failed", "error", err)
			return Principal{}, connect.NewError(connect.CodeUnavailable, errors.New("authentication service unavailable"))
		}
	}
	if !ok {
		return Principal{}, refuse(connect.CodeUnauthenticated, sandbox.RefusalPermission, errors.New("invalid or expired token"))
	}
	if !utf8.ValidString(p.UserID) || p.UserID == "*" || p.UserID == "" ||
		p.UserID != strings.TrimSpace(p.UserID) || strings.IndexFunc(p.UserID, unicode.IsControl) >= 0 {
		return Principal{}, refuse(connect.CodeUnauthenticated, sandbox.RefusalPermission,
			errors.New("authenticated principal has no stable identity"))
	}
	return p, nil
}

// AuthenticateHTTP rejects invalid credentials before Connect reads, decompresses,
// or unmarshals the request body. The unary interceptor alone runs after that work,
// allowing unauthenticated slow-body and decode amplification against the daemon.
// The interceptor remains the procedure-scope gate and fallback for handlers that
// are embedded without this HTTP middleware. A refusal leaves the body unread and
// unclosed: closing it would read it (Go's HTTP/1.x server drains a small unread body
// on Close), and the server's unreadbody wrapper closes the connection instead.
func AuthenticateHTTP(verifier TokenVerifier, next http.Handler) http.Handler {
	if verifier == nil {
		return next
	}
	errorWriter := connect.NewErrorWriter()
	failures := &authFailureLog{}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := authenticatePrincipal(r.Context(), r.Header.Get("Authorization"), verifier)
		if err != nil {
			failures.note()
			_ = errorWriter.Write(w, r, err)
			return
		}
		scope, mapped := requiredScopes[r.URL.Path]
		if !mapped || !p.HasScope(scope) {
			_ = errorWriter.Write(w, r, refuse(connect.CodePermissionDenied, sandbox.RefusalPermission,
				fmt.Errorf("token lacks required scope %q", scope)))
			return
		}
		ctx := context.WithValue(r.Context(), principalKey{}, p)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// authFailureLog counts refused credentials and logs the count at most once per
// authFailureLogEvery, so an operator sees guessing without the log becoming the
// attacker's to fill. Nothing about the attempt is logged: not the token, not a
// fingerprint of it.
type authFailureLog struct {
	mu     sync.Mutex
	count  int
	logged time.Time
}

const authFailureLogEvery = 30 * time.Second

func (a *authFailureLog) note() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.count++
	if time.Since(a.logged) < authFailureLogEvery {
		return
	}
	slog.Warn("refused requests with an unknown or malformed credential", "count", a.count, "window", authFailureLogEvery.String())
	a.count, a.logged = 0, time.Now()
}

// LimitHTTPConcurrency bounds authenticated requests while Connect is still
// reading and decoding them, before the run limiter can be acquired. A slot covers
// the body's reading, decompression and unmarshalling: it is given back once the
// request has been decoded (ReleaseDecodeSlot, the first interceptor, which Connect
// runs only on a decoded request) or the handler returns, so a long run or a session
// call waiting for its turn does not hold decode capacity. Connect reads the whole
// body before it decompresses and unmarshals it, so a slot given back at the body's
// end let more decoding run at once than the slots allow (round-7 review,
// 2026-10-08). One caller may hold at most half the slots at once, so one caller's
// requests, however slowly they arrive, always leave the other half for everyone else.
func LimitHTTPConcurrency(n int, next http.Handler) http.Handler {
	if n < 1 {
		n = 1
	}
	perCaller := max(1, n/2)
	sem := make(chan struct{}, n)
	var mu sync.Mutex
	held := map[string]int{}
	errorWriter := connect.NewErrorWriter()
	refuseFull := func(w http.ResponseWriter, r *http.Request) {
		_ = errorWriter.Write(w, r, refuse(connect.CodeResourceExhausted, sandbox.RefusalCapacity,
			errors.New("RPC decode capacity exhausted, retry shortly")))
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller := auditCaller(r.Context())
		mu.Lock()
		if held[caller] >= perCaller {
			mu.Unlock()
			refuseFull(w, r)
			return
		}
		held[caller]++
		mu.Unlock()
		leave := func() {
			mu.Lock()
			if held[caller]--; held[caller] == 0 {
				delete(held, caller)
			}
			mu.Unlock()
		}
		select {
		case sem <- struct{}{}:
		default:
			leave()
			refuseFull(w, r)
			return
		}
		var once sync.Once
		release := func() { once.Do(func() { <-sem; leave() }) }
		defer release()
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), decodeSlotKey{}, release)))
	})
}

type decodeSlotKey struct{}

// ReleaseDecodeSlot gives back the decode slot LimitHTTPConcurrency holds for the
// request. It must come first among a handler's interceptors: Connect calls an
// interceptor with the request already decoded, so this is the earliest point at which
// the decoding the slot bounds is over. Without it the slot is held until the handler
// returns, a whole run included.
func ReleaseDecodeSlot() connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			if release, ok := ctx.Value(decodeSlotKey{}).(func()); ok {
				release()
			}
			return next(ctx, req)
		}
	}
}

// LimitBody caps a request body at n bytes. A body that declares more is refused
// before any of it is read, at the constant cost of a refused credential; without that
// check the cap trips only once n bytes have arrived, so a caller declaring 100 MB and
// sending two bytes held its handler, connection and decode slot until the read
// timeout. A body that declares no length (chunked) is cut off once it passes n.
func LimitBody(n int64, next http.Handler) http.Handler {
	errorWriter := connect.NewErrorWriter()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > n {
			_ = errorWriter.Write(w, r, refuse(connect.CodeResourceExhausted, sandbox.RefusalRequest,
				fmt.Errorf("request body declares %d bytes, over the %d-byte limit", r.ContentLength, n)))
			return
		}
		r2 := new(http.Request)
		*r2 = *r
		r2.Body = http.MaxBytesReader(w, r.Body, n)
		next.ServeHTTP(w, r2)
	})
}

func bearerToken(header string) string {
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return parts[1]
}

// AuthInterceptor enforces bearer-token auth and per-procedure scopes.
//
// verifier == nil DISABLES auth (dev mode): every call is allowed and a wildcard
// principal is stamped. main.go logs a warning; never run that in production.
//
// verifier != nil is fail-closed: a missing or invalid token → Unauthenticated;
// a valid token lacking the required scope (or hitting a procedure with no scope
// mapping) → PermissionDenied.
func AuthInterceptor(verifier TokenVerifier) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			procedure := req.Spec().Procedure
			if verifier == nil { // dev mode: no verification
				ctx = context.WithValue(ctx, principalKey{}, Principal{Scopes: []string{"*"}})
				return next(ctx, req)
			}

			p, alreadyAuthenticated := PrincipalFrom(ctx)
			if !alreadyAuthenticated {
				var err error
				p, err = authenticatePrincipal(ctx, req.Header().Get("Authorization"), verifier)
				if err != nil {
					return nil, err
				}
			}
			scope, mapped := requiredScopes[procedure]
			if !mapped || !p.HasScope(scope) {
				return nil, refuse(connect.CodePermissionDenied, sandbox.RefusalPermission, fmt.Errorf("token lacks required scope %q", scope))
			}
			ctx = context.WithValue(ctx, principalKey{}, p)
			return next(ctx, req)
		}
	}
}
