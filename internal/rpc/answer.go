package rpc

import (
	"context"
	"net/http"
	"sync/atomic"

	"connectrpc.com/connect"

	"github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1/plimsollv1connect"
	"github.com/plimsollmark/plimsoll/protocol"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// What an answer says about a call holds only for the request it answers. A client
// sends a fresh random ID on every request (protocol.RequestIDHeader) and accepts an
// answer only if it carries the same ID back; without that, an intermediary that
// answers one request with another's answer (an HTTP/1.1 desynchronisation, a cache
// keying POSTs by URL) makes a call that ran read "nothing ran", and a caller retrying
// on that runs it twice.

// NewHandler is plimsollv1connect.NewSandboxServiceHandler behind BindAnswers, with
// HandlerReached first among the interceptors. Every server of the procedures uses
// it, fakes in tests included, since the official clients refuse an answer that does
// not carry their request's ID.
func NewHandler(svc plimsollv1connect.SandboxServiceHandler, opts ...connect.HandlerOption) (string, http.Handler) {
	opts = append([]connect.HandlerOption{connect.WithInterceptors(HandlerReached())}, opts...)
	path, h := plimsollv1connect.NewSandboxServiceHandler(svc, opts...)
	return path, BindAnswers(h)
}

type answerState struct{ reached atomic.Bool }

type answerKey struct{}

// BindAnswers puts the request's ID on every answer next gives, and marks not
// dispatched every answer of status 300 or more written before a procedure's handler
// was reached (HandlerReached): connect-go's own refusals (a malformed or oversized
// body, an unsupported content type) and net/http's 404 carry no detail, yet nothing
// can have run. A 404 is marked unsupported (no such procedure here), anything else
// request. The ID is set before next runs, so the HTTP middlewares' refusals carry it
// too. An ID that is not exactly one value of 32 lowercase hex digits is not echoed,
// and not refused: the client that sent it learns its answers are unbound. Inside
// another BindAnswers it does nothing, so a server can bind its whole listener and
// still serve a NewHandler.
func BindAnswers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, nested := r.Context().Value(answerKey{}).(*answerState); nested {
			next.ServeHTTP(w, r)
			return
		}
		if ids := r.Header.Values(protocol.RequestIDHeader); len(ids) == 1 && validRequestID(ids[0]) {
			w.Header().Set(protocol.RequestIDHeader, ids[0])
		}
		st := &answerState{}
		next.ServeHTTP(&answerWriter{ResponseWriter: w, st: st}, r.WithContext(context.WithValue(r.Context(), answerKey{}, st)))
	})
}

// HandlerReached records for BindAnswers that the request reached a procedure's
// interceptors, which Connect calls only once the request is decoded; from there on
// every refusal states through its own detail whether anything ran. It goes first
// among the interceptors, before anything that could refuse.
func HandlerReached() connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			if st, ok := ctx.Value(answerKey{}).(*answerState); ok {
				st.reached.Store(true)
			}
			return next(ctx, req)
		}
	}
}

func validRequestID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for i := range len(s) {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// answerWriter adds the not-dispatched mark when the status is written.
type answerWriter struct {
	http.ResponseWriter
	st      *answerState
	written bool
}

func (a *answerWriter) WriteHeader(status int) {
	// An informational status precedes the answer's own.
	if !a.written && status >= 200 {
		a.written = true
		if status >= 300 && !a.st.reached.Load() {
			reason := sandbox.RefusalRequest
			if status == http.StatusNotFound {
				reason = sandbox.RefusalUnsupported
			}
			a.Header().Set(protocol.NotDispatchedHeader, reason.String())
		}
	}
	a.ResponseWriter.WriteHeader(status)
}

func (a *answerWriter) Write(b []byte) (int, error) {
	if !a.written {
		a.WriteHeader(http.StatusOK)
	}
	return a.ResponseWriter.Write(b)
}

// Flush keeps http.Flusher, which connect-go asserts directly.
func (a *answerWriter) Flush() {
	if !a.written {
		a.WriteHeader(http.StatusOK)
	}
	_ = http.NewResponseController(a.ResponseWriter).Flush()
}

func (a *answerWriter) Unwrap() http.ResponseWriter { return a.ResponseWriter }
