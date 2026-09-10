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
	"unicode"
	"unicode/utf8"

	"connectrpc.com/connect"

	"github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1/plimsollv1connect"
)

// ScopeCodeRun is the scope a caller must hold to execute code. It is the only
// scope this service grants; a token that lacks it cannot run anything.
const ScopeCodeRun = "code:run"

// requiredScopes maps each procedure to the scope it requires. A procedure that
// is NOT listed is denied by default — new RPCs are locked down until explicitly
// granted a scope here (fail-closed).
var requiredScopes = map[string]string{
	plimsollv1connect.SandboxServiceRunJavaScriptV2Procedure: ScopeCodeRun,
	plimsollv1connect.SandboxServiceRunProjectV2Procedure:    ScopeCodeRun,
	// Describe runs no code, but it describes the code-running boundary; its only
	// audience is code-running callers, so it shares their scope.
	plimsollv1connect.SandboxServiceDescribeProcedure: ScopeCodeRun,
}

// Principal is an authenticated caller.
type Principal struct {
	UserID string
	Scopes []string
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
		return Principal{}, connect.NewError(connect.CodeUnauthenticated, errors.New("missing bearer token"))
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
		return Principal{}, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid or expired token"))
	}
	if !utf8.ValidString(p.UserID) || p.UserID == "*" || p.UserID == "" ||
		p.UserID != strings.TrimSpace(p.UserID) || strings.IndexFunc(p.UserID, unicode.IsControl) >= 0 {
		return Principal{}, connect.NewError(connect.CodeUnauthenticated,
			errors.New("authenticated principal has no stable identity"))
	}
	return p, nil
}

// AuthenticateHTTP rejects invalid credentials before Connect reads, decompresses,
// or unmarshals the request body. The unary interceptor alone runs after that work,
// allowing unauthenticated slow-body and decode amplification against the daemon.
// The interceptor remains the procedure-scope gate and fallback for handlers that
// are embedded without this HTTP middleware.
func AuthenticateHTTP(verifier TokenVerifier, next http.Handler) http.Handler {
	if verifier == nil {
		return next
	}
	errorWriter := connect.NewErrorWriter()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := authenticatePrincipal(r.Context(), r.Header.Get("Authorization"), verifier)
		if err != nil {
			_ = r.Body.Close() // do not drain attacker-controlled slow/large bodies
			_ = errorWriter.Write(w, r, err)
			return
		}
		scope, mapped := requiredScopes[r.URL.Path]
		if !mapped || !p.HasScope(scope) {
			_ = r.Body.Close()
			_ = errorWriter.Write(w, r, connect.NewError(connect.CodePermissionDenied,
				fmt.Errorf("token lacks required scope %q", scope)))
			return
		}
		ctx := context.WithValue(r.Context(), principalKey{}, p)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// LimitHTTPConcurrency bounds authenticated requests while Connect is still
// reading/decoding them, before the run limiter can be acquired.
func LimitHTTPConcurrency(max int, next http.Handler) http.Handler {
	if max < 1 {
		max = 1
	}
	sem := make(chan struct{}, max)
	errorWriter := connect.NewErrorWriter()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
			next.ServeHTTP(w, r)
		default:
			_ = r.Body.Close()
			_ = errorWriter.Write(w, r, connect.NewError(connect.CodeResourceExhausted,
				errors.New("RPC decode capacity exhausted, retry shortly")))
		}
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
				return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("token lacks required scope %q", scope))
			}
			ctx = context.WithValue(ctx, principalKey{}, p)
			return next(ctx, req)
		}
	}
}
