package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1/plimsollv1connect"
	"github.com/plimsollmark/plimsoll/internal/answertest"
	"github.com/plimsollmark/plimsoll/internal/rpc"
	"github.com/plimsollmark/plimsoll/protocol"
	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandboxtest"
)

func serveHandler(t *testing.T, h http.Handler) string {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv.URL
}

func boundDaemon(t *testing.T, opts ...connect.HandlerOption) (*rpc.SandboxService, string) {
	t.Helper()
	svc := rpc.NewSandboxService(sandboxtest.Wasm())
	mux := http.NewServeMux()
	mux.Handle(rpc.NewHandler(svc, opts...))
	return svc, serveHandler(t, mux)
}

// Each case exercises Do, settle and the public error restoration through an
// actual HTTP client. Inspect the raw error type as well as the refusal mark.
func TestTransportFailuresBeforeSendingAreMarkedEnvironment(t *testing.T) {
	clear := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(clear.Close)
	untrusted := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(untrusted.Close)
	for _, tc := range []struct {
		name, url string
		check     func(error) bool
	}{
		{"refused connection", "http://127.0.0.1:1", func(err error) bool {
			var op *net.OpError
			return errors.As(err, &op) && op.Op == "dial"
		}},
		{"TLS to cleartext", strings.Replace(clear.URL, "http:", "https:", 1), func(err error) bool {
			return errors.Is(err, http.ErrSchemeMismatch)
		}},
		{"untrusted certificate", untrusted.URL, func(err error) bool {
			var cert *tls.CertificateVerificationError
			var authority x509.UnknownAuthorityError
			return errors.As(err, &cert) && errors.As(err, &authority)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			httpClient := &http.Client{Transport: &http.Transport{}, Timeout: 5 * time.Second}
			t.Cleanup(httpClient.CloseIdleConnections)
			var raw error
			r := newRemote(t, tc.url, WithHTTPClient(answerHTTPFunc(func(req *http.Request) (*http.Response, error) {
				resp, err := httpClient.Do(req)
				raw = err
				return resp, err
			})))
			_, err := r.RunJavaScript(context.Background(), sandbox.Request{Code: "1"})
			if raw == nil || !tc.check(raw) {
				t.Fatalf("raw error = %T %v, want the transport identity for %s", raw, raw, tc.name)
			}
			if reason, ok := sandbox.NotDispatchedReason(err); !ok || reason != sandbox.RefusalEnvironment {
				t.Fatalf("err = %v, want marked environment", err)
			}
			if connect.CodeOf(err) != connect.CodeUnavailable || !tc.check(err) {
				t.Fatalf("err = %v, want Unavailable keeping its transport identity", err)
			}
		})
	}
}

type answerHTTPFunc func(*http.Request) (*http.Response, error)

func (f answerHTTPFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }

func TestTransportFailureMarksUseOnlyPreSendTypes(t *testing.T) {
	conn, peer := net.Pipe()
	t.Cleanup(func() { _ = conn.Close(); _ = peer.Close() })
	for _, tc := range []struct {
		name string
		err  error
		mark bool
	}{
		{"DNS", &net.DNSError{Err: "failure", Name: "daemon.invalid"}, true},
		{"initial TLS header", tls.RecordHeaderError{Conn: conn}, true},
		{"hostname", x509.HostnameError{Certificate: &x509.Certificate{}, Host: "daemon.invalid"}, true},
		{"certificate validity", x509.CertificateInvalidError{Cert: &x509.Certificate{}}, true},
		{"system roots", x509.SystemRootsError{Err: errors.New("failure")}, true},
		{"read", &net.OpError{Op: "read", Err: io.EOF}, false},
		{"later TLS header", tls.RecordHeaderError{Msg: "invalid record"}, false},
		{"EOF", io.EOF, false},
		{"message only", errors.New("dial: connection refused; tls: certificate verification failed"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := fmt.Errorf("wrapped: %w", tc.err)
			r := newRemote(t, "http://127.0.0.1", WithHTTPClient(answerHTTPFunc(func(*http.Request) (*http.Response, error) {
				return nil, err
			})))
			_, got := r.Describe(context.Background())
			if reason, marked := sandbox.NotDispatchedReason(got); marked != tc.mark || (marked && reason != sandbox.RefusalEnvironment) {
				t.Fatalf("err = %v, mark = %v (%v), want environment mark %v", got, marked, reason, tc.mark)
			}
			if tc.mark && !errors.Is(got, tc.err) {
				t.Fatalf("the transport cause was lost: %v", got)
			}
		})
	}
}

func TestAnAnsweredTransportFailureIsNotMarkedEnvironment(t *testing.T) {
	r := newRemote(t, "http://127.0.0.1", WithHTTPClient(answerHTTPFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{Header: http.Header{protocol.RequestIDHeader: req.Header.Values(protocol.RequestIDHeader)}},
			&net.OpError{Op: "dial", Err: errors.New("failure after an answer")}
	})))
	_, err := r.Describe(context.Background())
	if _, marked := sandbox.NotDispatchedReason(err); marked {
		t.Fatalf("an answered exchange is marked by its error type: %v", err)
	}
}

// A refusal captured from one request and served for a later one that the daemon ran
// must not read "nothing ran": a caller would run it again.
func TestReplayedRefusalIsNotBelieved(t *testing.T) {
	svc, up := boundDaemon(t)
	c := newRemote(t, answertest.Replay(t, up))
	ctx := context.Background()

	_, err := c.RunJavaScript(ctx, sandbox.Request{Code: "1", MinimumIsolation: sandbox.IsolationVM})
	if r, ok := sandbox.NotDispatchedReason(err); !ok || r != sandbox.RefusalIsolation {
		t.Fatalf("the refusal's own answer: %v, want marked isolation", err)
	}
	before, _ := svc.RunCounts()
	_, err = c.RunJavaScript(ctx, sandbox.Request{Code: "console.log(42)"})
	if after, _ := svc.RunCounts(); after != before+1 {
		t.Fatalf("the daemon ran %d runs, want 1: the proxy must forward the request it answers wrongly", after-before)
	}
	if r, ok := sandbox.NotDispatchedReason(err); ok {
		t.Fatalf("a replayed refusal reads as not dispatched (%v) for a request that ran: %v", r, err)
	}
	if !errors.Is(err, ErrAnswerNotBound) {
		t.Fatalf("err = %v, want ErrAnswerNotBound", err)
	}
}

// A success captured for one request and served for an identical later one passes the
// record check, which binds content, not the request; the echo catches it.
func TestReplayedSuccessIsDataLoss(t *testing.T) {
	svc, up := boundDaemon(t)
	c := newRemote(t, answertest.Replay(t, up))
	ctx := context.Background()
	req := sandbox.Request{Code: "console.log(42)"}

	if _, err := c.RunJavaScript(ctx, req); err != nil {
		t.Fatal(err)
	}
	_, err := c.RunJavaScript(ctx, req)
	if total, _ := svc.RunCounts(); total != 2 {
		t.Fatalf("the daemon ran %d runs, want 2", total)
	}
	if connect.CodeOf(err) != connect.CodeDataLoss || !errors.Is(err, ErrAnswerNotBound) {
		t.Fatalf("err = %v, want DataLoss wrapping ErrAnswerNotBound", err)
	}
	if _, ok := sandbox.NotDispatchedReason(err); ok {
		t.Fatalf("a replayed success reads as not dispatched: %v", err)
	}
}

// connect-go refuses a body over its read cap before any handler runs and attaches no
// detail; the daemon's header says nothing ran (finding 3).
func TestEarlyRefusalIsMarkedRequest(t *testing.T) {
	svc, url := boundDaemon(t, connect.WithReadMaxBytes(256))
	c := newRemote(t, url)
	_, err := c.RunJavaScript(context.Background(), sandbox.Request{Code: "console.log('" + strings.Repeat("x", 1024) + "')"})
	if r, ok := sandbox.NotDispatchedReason(err); !ok || r != sandbox.RefusalRequest {
		t.Fatalf("err = %v, want marked request", err)
	}
	if !errors.Is(err, sandbox.ErrAtCapacity) {
		t.Fatalf("err = %v, want the code's sentinel kept", err)
	}
	if total, _ := svc.RunCounts(); total != 0 {
		t.Fatalf("the daemon ran %d runs", total)
	}
}

// A procedure the daemon does not serve is net/http's plain 404, whose headers
// connect-go drops; the client reads the mark from the raw answer.
func TestUnknownProcedureIsMarkedUnsupported(t *testing.T) {
	c := newRemote(t, serveHandler(t, rpc.BindAnswers(http.NotFoundHandler())))
	_, err := c.Describe(context.Background())
	if r, ok := sandbox.NotDispatchedReason(err); !ok || r != sandbox.RefusalUnsupported {
		t.Fatalf("err = %v, want marked unsupported", err)
	}
	if !errors.Is(err, sandbox.ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
}

// A refusal plimsoll's own middleware writes carries its detail, which outranks the
// header's generic reason: credentials are permission, not request.
func TestDetailOutranksHeaderMark(t *testing.T) {
	svc := rpc.NewSandboxService(sandboxtest.Wasm())
	verifier := fakeVerifier{token: "tok", scopes: []string{rpc.ScopeCodeRun}}
	path, h := rpc.NewHandler(svc, connect.WithInterceptors(rpc.AuthInterceptor(verifier)))
	mux := http.NewServeMux()
	mux.Handle(path, rpc.AuthenticateHTTP(verifier, h))
	c := newRemote(t, serveHandler(t, rpc.BindAnswers(mux)), WithToken("wrong"))
	_, err := c.Describe(context.Background())
	if r, ok := sandbox.NotDispatchedReason(err); !ok || r != sandbox.RefusalPermission {
		t.Fatalf("err = %v, want marked permission", err)
	}
}

// A daemon that does not echo (older than protocol 3) is believed in nothing: its
// success is DataLoss and its marked refusal is unmarked.
func TestDaemonWithoutEchoIsNotBelieved(t *testing.T) {
	svc := rpc.NewSandboxService(sandboxtest.Wasm())
	mux := http.NewServeMux()
	mux.Handle(plimsollv1connect.NewSandboxServiceHandler(svc))
	c := newRemote(t, serveHandler(t, mux))
	ctx := context.Background()

	if _, err := c.Describe(ctx); connect.CodeOf(err) != connect.CodeDataLoss || !errors.Is(err, ErrAnswerNotBound) {
		t.Fatalf("Describe: %v, want DataLoss wrapping ErrAnswerNotBound", err)
	}
	_, err := c.RunJavaScript(ctx, sandbox.Request{Code: "1", MinimumIsolation: sandbox.IsolationVM})
	if _, ok := sandbox.NotDispatchedReason(err); ok {
		t.Fatalf("an unbound refusal reads as not dispatched: %v", err)
	}
	if connect.CodeOf(err) != connect.CodeFailedPrecondition || !errors.Is(err, ErrAnswerNotBound) {
		t.Fatalf("err = %v, want its code kept and ErrAnswerNotBound", err)
	}
}

// Each call carries its own ID: two calls never share one.
func TestEveryCallSendsAFreshID(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]int{}
	path, h := rpc.NewHandler(rpc.NewSandboxService(sandboxtest.Wasm()))
	mux := http.NewServeMux()
	mux.Handle(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.Header.Get(protocol.RequestIDHeader)]++
		mu.Unlock()
		h.ServeHTTP(w, r)
	}))
	c := newRemote(t, serveHandler(t, mux))
	for range 3 {
		if _, err := c.Describe(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if len(seen) != 3 {
		t.Fatalf("IDs seen: %v, want 3 distinct", seen)
	}
	for id := range seen {
		if len(id) != 32 || strings.Trim(id, "0123456789abcdef") != "" {
			t.Fatalf("ID %q is not 32 lowercase hex digits", id)
		}
	}
}
