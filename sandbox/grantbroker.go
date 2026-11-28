package sandbox

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"time"
)

// HostAPISocketEnv names the environment variable the injected host client reads
// for the Unix socket it sends its calls to.
const HostAPISocketEnv = "HOST_API_SOCKET"

// GrantBroker is one granted run's host-API broker for a provider outside this
// package: the shared enforcement core (the frozen grant, the credential minted
// for this run, the exact-route check, the budgets, the upstream request and the
// metadata-only call trace) behind the HTTP framing the docker provider's socket
// serves, which the injected client speaks. Serve it on connections that carry
// only what the guest sent: everything arriving on them is checked here, and the
// credential never leaves this process.
type GrantBroker struct {
	core *brokerSession
}

// NewGrantBroker mints the run's credential (bounded by timeout) and returns the
// broker. The caller closes it when the run ends. routes is the session's route
// budget for a call in a session (see RouteBudget), nil for a run.
func NewGrantBroker(ctx context.Context, grant *HostAPIGrant, timeout time.Duration, routes *RouteBudget) (*GrantBroker, error) {
	if grant == nil {
		return nil, errors.New("host api broker: grant is nil")
	}
	core, err := brokerSessionForGrant(ctx, grant, timeout, routes)
	if err != nil {
		return nil, err
	}
	return &GrantBroker{core: core}, nil
}

// Serve serves the broker on l in the background, with the docker socket's server
// settings, and returns the server so the caller can close it.
func (b *GrantBroker) Serve(l net.Listener) *http.Server {
	srv := newBrokerServer(b.core)
	go func() { _ = srv.Serve(l) }()
	return srv
}

// Trace is the run's call trace so far: route templates, statuses and sizes, never
// a path, body or credential. Nil when the run made no call.
func (b *GrantBroker) Trace() *CallTrace { return b.core.traceSnapshot() }

// End ends the run's authority: a call in flight is cut off upstream, a later one
// is refused, and End waits briefly for calls in flight, so Trace after it holds
// every call that reached the API. Call it before reading the run's final trace.
func (b *GrantBroker) End() { b.core.End() }

// Close ends the run's authority and releases the broker's idle upstream connections.
func (b *GrantBroker) Close() { b.core.Close() }

// HostClientSnippet returns code with the injected host client (and the grant's
// preamble) in front of it; the client sends its calls to the socket named by
// HOST_API_SOCKET. Code is returned unchanged for a nil grant.
func HostClientSnippet(code string, grant *HostAPIGrant) string { return withHostSDK(code, grant) }

// HostClientModule returns the same client as a module the project runner preloads
// into every step (the plan's hostSDK); "" for a nil grant.
func HostClientModule(grant *HostAPIGrant) string { return hostSDKModule(grant) }

// httpSink streams a brokered answer to an HTTP response: the status and content type
// once, then each piece flushed as it arrives, with the connection's write deadline
// moved out by the stream's idle limit at every piece, so the server's write timeout
// bounds a stall and never a long answer. The no-retry mark never goes on a streamed
// answer: it is the upstream's.
type httpSink struct{ w http.ResponseWriter }

func (s httpSink) Begin(status int, contentType string) io.Writer {
	if contentType != "" {
		s.w.Header().Set("Content-Type", contentType)
	}
	s.w.Header().Del(brokerNoRetryHeader)
	if status < 100 || status > 599 {
		status = http.StatusBadGateway
	}
	_ = http.NewResponseController(s.w).SetWriteDeadline(time.Now().Add(hostStreamIdleTimeout))
	s.w.WriteHeader(status)
	return streamWriter{s.w}
}

// streamWriter is the writer httpSink.Begin returns: each piece is written, flushed to
// the client at once, and the write deadline moved out again.
type streamWriter struct{ w http.ResponseWriter }

func (s streamWriter) Write(p []byte) (int, error) {
	rc := http.NewResponseController(s.w)
	_ = rc.SetWriteDeadline(time.Now().Add(hostStreamIdleTimeout))
	n, err := s.w.Write(p)
	if err == nil {
		err = rc.Flush()
	}
	return n, err
}

// writeBrokerResponse writes resp as the HTTP answer: the status, the one exposed
// header (Content-Type), and brokerNoRetryHeader when the answer is the broker's own.
func writeBrokerResponse(w http.ResponseWriter, resp brokerResponse) {
	if resp.ContentType != "" {
		w.Header().Set("Content-Type", resp.ContentType)
	}
	if resp.FromBroker {
		w.Header().Set(brokerNoRetryHeader, "false")
	}
	status := resp.Status
	if status < 100 || status > 599 {
		status = http.StatusBadGateway
	}
	w.WriteHeader(status)
	_, _ = w.Write(resp.Body)
}

// newBrokerServer is the HTTP server every socket-framed broker adapter runs: the
// target is taken from RequestURI, exactly as it arrived, because r.URL.Path has
// already lost percent-encoding and cannot prove approve==wire.
func newBrokerServer(core *brokerSession) *http.Server {
	return newBrokerServerFor(func() *brokerSession { return core })
}

// newBrokerServerFor serves whichever core current returns when each request
// arrives: a docker session's socket outlives its calls, and between them (or in a
// call without a grant) current returns nil, which the broker answers 503.
func newBrokerServerFor(current func() *brokerSession) *http.Server {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// RequestURI as it arrived: an absolute-form target ("http://host/x") or a
		// CONNECT authority ("host:443") reaches the core whole and fails its
		// leading-slash check, so a client that names an origin of its own is refused.
		// The body goes to the core as a reader: a JSON body is buffered there under the
		// route's limit, an upload on a route the profile raised is passed through as it
		// arrives, with the connection's read deadline moved out at each piece so the
		// server's read timeout bounds a stall, never a long upload.
		body := readDeadlineReader{r: r.Body, rc: http.NewResponseController(w), idle: hostRequestIdleTimeout}
		resp := current().Call(r.Context(), brokerCall{Method: r.Method, RawTarget: r.RequestURI, Headers: r.Header, Body: body, ContentLength: r.ContentLength, Stream: httpSink{w}})
		if !resp.Streamed {
			drainSmallBody(w, r)
			writeBrokerResponse(w, resp)
		}
	})
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       15 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
}

// brokerDrainBytes is the most of a request body the broker's server reads and discards
// before answering a call that did not read it (a refusal raised before the body: a type
// the route does not take, a budget spent, the broker at capacity). It is net/http's own
// tolerance for an unread body (maxPostHandlerReadBytes, 256 KiB).
const brokerDrainBytes = 256 << 10

// brokerDrainTimeout bounds the whole of that read: a guest that stalls in a small body
// is answered no later than this, and its connection closed
// (TestBrokerDrainGivesUpOnAStalledSmallBody). Its size, from the two ways it can be wrong:
// too short only costs what the drain exists to avoid, a refusal seen as a closed
// connection as for a body past brokerDrainBytes, never a wrong answer, since nothing read
// here goes upstream; too long holds a refusal back from a guest that stalls its own small
// body. It must stay well below hostRequestIdleTimeout (10 s), the stall this socket
// allows between pieces anywhere else; with no deadline of its own the drain waits out the
// one the server set when the request began (ReadTimeout, 10 s; the test measured 10.0 s
// with this deadline removed). 2 s asks a body of brokerDrainBytes to arrive at 128 KiB/s
// (about 1 Mbit/s): the docker broker's comes from the in-sandbox forwarder over a local
// Unix socket, and the egress guard's raw route's from an E2B sandbox over the provider's
// network; neither rate is measured, but 600 loaded runs under gVisor of the 16 KiB body
// of TestDockerProjectGrantCarriesTheCheckersUploads were never cut by it (2026-11-27).
var brokerDrainTimeout = 2 * time.Second

// drainSmallBody reads what is left of a request body of at most brokerDrainBytes
// (declared, or undeclared and ending within it) and discards it, before the answer is
// written. The answer of a refusal raised before the body was read then reaches the
// client: net/http does not drain an unread body itself when the request says
// Connection: close (Python's urllib always does), and a Unix socket closed with unread
// data resets its peer, so the forwarder in the sandbox could cut the guest's connection
// before the answer, and the guest saw a closed connection instead of the 415 and its
// no-retry mark (under gVisor, 32 of 600 loaded runs of
// TestDockerProjectGrantCarriesTheCheckersUploads on two image sets, none of 600 runs
// after this drain under gVisor and runc, 2026-11-27). A declared body over the
// bound is not read: its refusal may still reach the client as a closed connection. The
// bytes read here go nowhere: not upstream, not to the trace. A body the call already
// read to its end costs one read that returns EOF. A writer that takes no read deadline
// (a wrapper that hides the connection) gets no drain at all: the read would then be bounded
// only by the server's own read timeout, not by brokerDrainTimeout (session-files-24).
func drainSmallBody(w http.ResponseWriter, r *http.Request) {
	if r.Body == nil || r.ContentLength == 0 || r.ContentLength > brokerDrainBytes {
		return
	}
	if http.NewResponseController(w).SetReadDeadline(time.Now().Add(brokerDrainTimeout)) != nil {
		return
	}
	_, _ = io.CopyN(io.Discard, r.Body, brokerDrainBytes+1)
}

// hostRequestIdleTimeout bounds the gap between two pieces of a request body on the
// broker's socket: a guest that sends nothing for this long is cut. The server's 10 s
// read timeout, set once per request, would cut a long upload that is still moving.
var hostRequestIdleTimeout = 10 * time.Second

// readDeadlineReader reads a request body with the connection's read deadline moved
// out by idle before each read, so the deadline bounds a stall between pieces rather
// than the whole body. A connection that takes no deadline (a test's recorder) is read
// under the server's own timeout.
type readDeadlineReader struct {
	r    io.Reader
	rc   *http.ResponseController
	idle time.Duration
}

func (d readDeadlineReader) Read(p []byte) (int, error) {
	_ = d.rc.SetReadDeadline(time.Now().Add(d.idle))
	return d.r.Read(p)
}
