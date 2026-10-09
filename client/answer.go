package client

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"sync"

	"connectrpc.com/connect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
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
	resp, err := b.next.Do(r)
	if ex, ok := r.Context().Value(exchangeKey{}).(*exchange); ok {
		ex.mu.Lock()
		if resp != nil {
			ex.answered = true
			ex.echo = resp.Header.Values(protocol.RequestIDHeader)
			ex.mark = resp.Header.Get(protocol.NotDispatchedHeader)
		} else {
			ex.unsent = failedBeforeSending(err)
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
	answered, bound, mark := ex.answered, len(ex.echo) == 1 && ex.echo[0] == ex.id, ex.mark
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
	if mark != "" && errors.As(err, &ce) {
		if _, marked := notDispatchedDetail(ce); !marked {
			if reason, ok := refusalWireByName(mark); ok {
				if d, derr := connect.NewErrorDetail(&plimsollv1.NotDispatched{Reason: reason}); derr == nil {
					ce.AddDetail(d)
				}
			}
		}
	}
	return resp, err
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
		if got := refusalFromWire(r); got != sandbox.RefusalUnknown && got.String() == name {
			return r, true
		}
	}
	return 0, false
}
