package client

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptrace"
	"slices"
	"sync"

	"connectrpc.com/connect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/internal/wireenum"
	"github.com/plimsollmark/plimsoll/protocol"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// ErrAnswerNotBound means an answer did not carry this request's ID back
// (protocol.RequestIDHeader): the daemon is older than protocol 3, or something
// between this client and the daemon answered with another request's answer or
// dropped the header. Nothing the answer says about the call is believed. A success is
// DataLoss, since the run may have executed; an error keeps its code and message but no
// not-dispatched mark, session end or unanswered-call record, so it reads "may have
// run".
var ErrAnswerNotBound = errors.New("client: the answer does not carry this request's ID back")

// exchange is one call's request ID and what bindingHTTPClient saw of its answer.
type exchange struct {
	id string

	mu       sync.Mutex
	answered bool
	unsent   bool
	echo     []string
	mark     string
	status   int
	// dialed and wrote are what httptrace showed of every attempt the HTTP client made
	// with this call's context: a connection sought, and request headers written.
	dialed bool
	wrote  bool
}

// trace records, across every attempt the HTTP client makes, whether a connection was
// sought and whether any attempt wrote its request headers. Only the pair proves a call
// unsent: the final error alone describes the last attempt, and a retrying client (an
// injected one) can deliver the code on an earlier attempt and then fail to dial.
func (ex *exchange) trace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		GetConn: func(string) {
			ex.mu.Lock()
			ex.dialed = true
			ex.mu.Unlock()
		},
		WroteHeaders: func() {
			ex.mu.Lock()
			ex.wrote = true
			ex.mu.Unlock()
		},
	}
}

type exchangeKey struct{}

func newRequestID() string {
	var b [16]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never returns an error; it crashes instead
	return hex.EncodeToString(b[:])
}

// bindAnswers is the innermost interceptor of every call (one HTTP request each): it
// sends a fresh ID and settles the answer by the echo bindingHTTPClient recorded.
func bindAnswers() connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			ex := &exchange{id: newRequestID()}
			req.Header().Set(protocol.RequestIDHeader, ex.id)
			resp, err := next(context.WithValue(ctx, exchangeKey{}, ex), req)
			return ex.settle(resp, err)
		}
	}
}

// bindingHTTPClient records each answer's echo and mark from the raw HTTP answer:
// connect-go keeps no header of an error answer whose body is not a Connect error (a
// plain 404, say), so the interceptor alone could not read them.
type bindingHTTPClient struct{ next connect.HTTPClient }

func (b bindingHTTPClient) Do(r *http.Request) (*http.Response, error) {
	ex, ok := r.Context().Value(exchangeKey{}).(*exchange)
	if ok {
		r = r.WithContext(httptrace.WithClientTrace(r.Context(), ex.trace()))
	}
	resp, err := b.next.Do(r)
	if ok {
		ex.mu.Lock()
		if resp != nil {
			ex.answered = true
			ex.echo = resp.Header.Values(protocol.RequestIDHeader)
			ex.mark = resp.Header.Get(protocol.NotDispatchedHeader)
			ex.status = resp.StatusCode
		} else {
			// A transport that reports no attempt through httptrace proves nothing, so
			// its failure reads "may have run".
			ex.unsent = failedBeforeSending(err) && ex.dialed && !ex.wrote
		}
		ex.mu.Unlock()
	}
	return resp, err
}

// failedBeforeSending matches transport identities, never their message text.
// A TLS record error with no Conn may have happened after the handshake and send.
func failedBeforeSending(err error) bool {
	var dial *net.OpError
	if errors.As(err, &dial) && dial.Op == "dial" {
		return true
	}
	var dns *net.DNSError
	var cert *tls.CertificateVerificationError
	var header tls.RecordHeaderError
	var authority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	var roots x509.SystemRootsError
	return errors.As(err, &dns) || errors.As(err, &cert) ||
		(errors.As(err, &header) && header.Conn != nil) || errors.Is(err, http.ErrSchemeMismatch) ||
		errors.As(err, &authority) || errors.As(err, &hostname) || errors.As(err, &invalid) || errors.As(err, &roots)
}

func (ex *exchange) settle(resp connect.AnyResponse, err error) (connect.AnyResponse, error) {
	ex.mu.Lock()
	answered, bound, mark, status := ex.answered, len(ex.echo) == 1 && ex.echo[0] == ex.id, ex.mark, ex.status
	unsent := ex.unsent
	ex.mu.Unlock()
	if err == nil {
		// A success this client did not see bound, for whatever reason (an answer the
		// HTTP client never recorded included), is not one it can believe.
		if !answered || !bound {
			return nil, connect.NewError(connect.CodeDataLoss, &unboundError{message: "the call may have run"})
		}
		return resp, nil
	}
	if answered && status == http.StatusOK {
		if code := connect.CodeOf(err); code != connect.CodeCanceled && code != connect.CodeDeadlineExceeded {
			// A Connect error answer is never a 200, so an error on one is this client's own
			// failure to read the daemon's answer (connect-go reads a body it cannot unmarshal
			// as InvalidArgument, which would tell the caller its request was bad). The call
			// may have run, so nothing marks it (finding hunt-quality-92).
			message := err.Error()
			var ce *connect.Error
			if errors.As(err, &ce) {
				message = ce.Message()
			}
			if !bound {
				return nil, connect.NewError(connect.CodeDataLoss, &unboundError{message: "the answer could not be read: " + message})
			}
			return nil, connect.NewError(connect.CodeDataLoss, fmt.Errorf("%w: %s", errUnreadableAnswer, message))
		}
	}
	if !answered {
		if !unsent {
			return resp, err // nothing proves the request was not sent
		}
		mark = sandbox.RefusalEnvironment.String()
	} else if !bound {
		message := err.Error()
		var ce *connect.Error
		if errors.As(err, &ce) {
			message = ce.Message()
		}
		return nil, connect.NewError(connect.CodeOf(err), &unboundError{message: message})
	}
	var ce *connect.Error
	if errors.As(err, &ce) && slices.Contains(ce.Details(), nil) {
		// connect-go reads a JSON null in an error's details list as a nil detail, whose
		// Value panics (finding release-88). An answer that holds one is not a Connect
		// error this client can read, so it is read as connect-go reads any unreadable
		// error body (the code from the HTTP status), and nothing in it is believed: no
		// detail, no header mark, so the call reads "may have run".
		return nil, connect.NewError(codeForHTTPStatus(status), fmt.Errorf("%w (HTTP status %d)", errNullDetail, status))
	}
	if mark != "" && errors.As(err, &ce) {
		if _, _, marked := notDispatchedDetail(ce); !marked {
			if reason, ok := refusalWireByName(mark); ok {
				if d, derr := connect.NewErrorDetail(&plimsollv1.NotDispatched{Reason: reason}); derr == nil {
					ce.AddDetail(d)
				}
			}
		}
	}
	return resp, err
}

// errUnreadableAnswer is the error of a daemon's 200 answer this client could not read.
var errUnreadableAnswer = errors.New("client: the daemon's answer could not be read, and the call may have run")

// errNullDetail is the error of an answer whose details list holds a JSON null.
var errNullDetail = errors.New("client: the answer's error details hold a null, so nothing it says about the call is believed")

// codeForHTTPStatus is connect-go's code for an error answer without a readable Connect
// error body (its unexported httpToCode, v1.20.0 protocol.go), so an answer this client
// refuses to read reads as one connect-go could not read.
func codeForHTTPStatus(status int) connect.Code {
	switch status {
	case 400:
		return connect.CodeInternal
	case 401:
		return connect.CodeUnauthenticated
	case 403:
		return connect.CodePermissionDenied
	case 404:
		return connect.CodeUnimplemented
	case 429, 502, 503, 504:
		return connect.CodeUnavailable
	default:
		return connect.CodeUnknown
	}
}

type unboundError struct{ message string }

func (e *unboundError) Error() string {
	return e.message + " (" + ErrAnswerNotBound.Error() + ": a daemon older than protocol 3, or an intermediary that answered with another request's answer or dropped the header; what it says about the call is ignored)"
}

func (e *unboundError) Unwrap() error { return ErrAnswerNotBound }

// refusalWireByName is the wire reason a header mark names; an unknown name marks nothing.
func refusalWireByName(name string) (plimsollv1.NotDispatchedReason, bool) {
	for v := range plimsollv1.NotDispatchedReason_name {
		r := plimsollv1.NotDispatchedReason(v)
		if got := wireenum.RefusalFromWire(r); got != sandbox.RefusalUnknown && got.String() == name {
			return r, true
		}
	}
	return 0, false
}
