package sandbox

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// sseUpstream is a stand-in for a chat API that streams: it writes each piece as a
// server-sent event, flushes it, and waits gap before the next. sent records when each
// piece left, so a test can say whether the first reached the client before the last was
// written. A zero gap and many pieces make a flood; a long gap after the first makes a
// stall.
type sseUpstream struct {
	mu   sync.Mutex
	sent []time.Time
}

func newSSEUpstream(t *testing.T, pieces []string, gap time.Duration, status int) (*httptest.Server, *sseUpstream) {
	t.Helper()
	u := &sseUpstream{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.WriteHeader(status)
		rc := http.NewResponseController(w)
		for i, p := range pieces {
			if i > 0 && gap > 0 {
				select {
				case <-time.After(gap):
				case <-r.Context().Done():
					return
				}
			}
			if _, err := io.WriteString(w, p); err != nil {
				return
			}
			_ = rc.Flush()
			u.mu.Lock()
			u.sent = append(u.sent, time.Now())
			u.mu.Unlock()
		}
	}))
	t.Cleanup(srv.Close)
	return srv, u
}

// socketStream opens one request over the broker's socket and returns the response
// (whose body the caller reads piece by piece) and the connection to close.
func socketStream(t *testing.T, sock, method, target string) (*http.Response, net.Conn) {
	t.Helper()
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, method+" "+target+" HTTP/1.1\r\nHost: api.internal\r\nAccept: text/event-stream\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp, conn
}

// TestBrokerStreamsEventStreamPieceByPiece: a text/event-stream answer reaches the
// client as it is written, not when it ends: the first event arrives before the upstream
// has written the last; the whole stream is delivered; the row says so.
func TestBrokerStreamsEventStreamPieceByPiece(t *testing.T) {
	t.Parallel()
	pieces := []string{"event: message_start\ndata: {}\n\n", "event: content_block_delta\ndata: {\"text\":\"hi\"}\n\n", "event: message_stop\ndata: {}\n\n"}
	upstream, u := newSSEUpstream(t, pieces, 400*time.Millisecond, http.StatusOK)
	grant := &HostAPIGrant{BaseURL: upstream.URL, Allow: []HostRoute{{Method: "POST", Path: "/v1/messages"}}}
	b, err := startDockerBroker(grant, "tok")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	resp, conn := socketStream(t, b.sock, "POST", "/v1/messages")
	defer conn.Close()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") || resp.Header.Get(brokerNoRetryHeader) != "" {
		t.Fatalf("status %d, Content-Type %q, %s %q", resp.StatusCode, resp.Header.Get("Content-Type"), brokerNoRetryHeader, resp.Header.Get(brokerNoRetryHeader))
	}
	buf := make([]byte, 4096)
	n, err := resp.Body.Read(buf)
	if err != nil || n == 0 {
		t.Fatalf("first read: %d, %v", n, err)
	}
	firstAt := time.Now()
	rest, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read the rest: %v", err)
	}
	if got := string(buf[:n]) + string(rest); got != strings.Join(pieces, "") {
		t.Fatalf("body = %q", got)
	}
	u.mu.Lock()
	lastSent := u.sent[len(u.sent)-1]
	u.mu.Unlock()
	if !firstAt.Before(lastSent) {
		t.Fatalf("the first piece arrived at %v, after the last was written at %v: the answer was buffered, not streamed", firstAt, lastSent)
	}
	trace := b.core.traceSnapshot()
	if trace == nil || len(trace.Calls) != 1 || !trace.Calls[0].Delivered || trace.Calls[0].RespBytes != len(strings.Join(pieces, "")) || trace.Calls[0].Status != 200 {
		t.Fatalf("trace = %+v", trace)
	}
}

// TestBrokerStreamIsCutAtTheByteCap: a flood is cut at maxHostResponseBytes; the client
// gets exactly that many bytes and then the end of the body; the row says the answer
// was not delivered whole.
func TestBrokerStreamIsCutAtTheByteCap(t *testing.T) {
	t.Parallel()
	piece := "data: " + strings.Repeat("x", 64<<10) + "\n\n"
	pieces := make([]string, 0, 100)
	for i := 0; i < 100; i++ { // about 6.4 MiB, past the 4 MiB cap
		pieces = append(pieces, piece)
	}
	upstream, _ := newSSEUpstream(t, pieces, 0, http.StatusOK)
	grant := &HostAPIGrant{BaseURL: upstream.URL, Allow: []HostRoute{{Method: "GET", Path: "/v1/stream"}}}
	b, err := startDockerBroker(grant, "tok")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	resp, conn := socketStream(t, b.sock, "GET", "/v1/stream")
	defer conn.Close()
	got, _ := io.ReadAll(resp.Body) // the cut ends the body, with or without an error
	resp.Body.Close()
	if len(got) != maxHostResponseBytes {
		t.Fatalf("client received %d bytes, want exactly the cap %d", len(got), maxHostResponseBytes)
	}
	trace := b.core.traceSnapshot()
	if trace == nil || len(trace.Calls) != 1 || trace.Calls[0].Delivered || trace.Calls[0].RespBytes != maxHostResponseBytes {
		t.Fatalf("trace = %+v", trace)
	}
}

// TestBrokerStreamIsCutWhenIdle: a stream that sends nothing for longer than the idle
// limit is cut there, not at the run's deadline; what arrived before the gap was
// delivered as it came.
func TestBrokerStreamIsCutWhenIdle(t *testing.T) {
	saved := hostStreamIdleTimeout
	hostStreamIdleTimeout = 300 * time.Millisecond
	t.Cleanup(func() { hostStreamIdleTimeout = saved })
	pieces := []string{"event: message_start\ndata: {}\n\n", "event: message_stop\ndata: {}\n\n"}
	upstream, _ := newSSEUpstream(t, pieces, 3*time.Second, http.StatusOK)
	grant := &HostAPIGrant{BaseURL: upstream.URL, Allow: []HostRoute{{Method: "GET", Path: "/v1/stream"}}}
	b, err := startDockerBroker(grant, "tok")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	started := time.Now()
	resp, conn := socketStream(t, b.sock, "GET", "/v1/stream")
	defer conn.Close()
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	took := time.Since(started)
	if string(got) != pieces[0] {
		t.Fatalf("client received %q, want the first piece alone", got)
	}
	if took > 2*time.Second {
		t.Fatalf("the cut took %v; the idle limit is %v", took, hostStreamIdleTimeout)
	}
	trace := b.core.traceSnapshot()
	if trace == nil || len(trace.Calls) != 1 || trace.Calls[0].Delivered || trace.Calls[0].RespBytes != len(pieces[0]) {
		t.Fatalf("trace = %+v", trace)
	}
}

// TestBrokerBuffersAnswersThatAreNotEventStreams: with a sink present, a JSON answer is
// still buffered and capped as always (an over-cap JSON body is a 502, never a cut), so
// the JSON APIs are byte-identical in behavior.
func TestBrokerBuffersAnswersThatAreNotEventStreams(t *testing.T) {
	t.Parallel()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/big" {
			_, _ = io.WriteString(w, `{"pad":"`+strings.Repeat("x", maxHostResponseBytes)+`"}`)
			return
		}
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer upstream.Close()
	grant := &HostAPIGrant{BaseURL: upstream.URL, Allow: []HostRoute{{Method: "GET", Path: "/v1/small"}, {Method: "GET", Path: "/v1/big"}}}
	b, err := startDockerBroker(grant, "tok")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	resp, conn := socketStream(t, b.sock, "GET", "/v1/small")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	conn.Close()
	if resp.StatusCode != http.StatusOK || string(body) != `{"ok":true}` || resp.Header.Get("Content-Length") == "" {
		t.Fatalf("small: %d %q Content-Length %q, want a whole buffered answer", resp.StatusCode, body, resp.Header.Get("Content-Length"))
	}
	resp, conn = socketStream(t, b.sock, "GET", "/v1/big")
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	conn.Close()
	if resp.StatusCode != http.StatusBadGateway || resp.Header.Get(brokerNoRetryHeader) != "false" {
		t.Fatalf("over-cap JSON: %d %q, want 502 with the no-retry mark", resp.StatusCode, resp.Header.Get(brokerNoRetryHeader))
	}
}

// TestBrokerCoreWithoutASinkBuffersAnEventStream: the WASM host function and the JSON
// envelope clients pass no sink, and get the whole stream as one answer, within the cap.
func TestBrokerCoreWithoutASinkBuffersAnEventStream(t *testing.T) {
	t.Parallel()
	pieces := []string{"data: a\n\n", "data: b\n\n"}
	upstream, _ := newSSEUpstream(t, pieces, 0, http.StatusOK)
	grant := &HostAPIGrant{BaseURL: upstream.URL, Allow: []HostRoute{{Method: "GET", Path: "/v1/stream"}}}
	core, err := newBrokerSession(grant, "tok", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	resp := core.Call(context.Background(), brokerCall{Method: "GET", RawTarget: "/v1/stream"})
	if resp.Streamed || resp.Status != 200 || string(resp.Body) != strings.Join(pieces, "") {
		t.Fatalf("response = %+v", resp)
	}
}

// TestEgressGuardStreamsEventStream: the guard's HTTP framing streams too, on the raw
// route, so a client behind the guard sees pieces as they are written.
func TestEgressGuardStreamsEventStream(t *testing.T) {
	t.Parallel()
	pieces := []string{"data: one\n\n", "data: two\n\n", "data: [DONE]\n\n"}
	upstream, u := newSSEUpstream(t, pieces, 400*time.Millisecond, http.StatusOK)
	reg := &guardRegistry{}
	grant := &HostAPIGrant{BaseURL: upstream.URL, Allow: []HostRoute{{Method: "POST", Path: "/v1/chat/completions"}}}
	token, _, cleanup, err := reg.open(context.Background(), grant, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	guard := httptest.NewServer(EgressGuardHTTPHandler(&registryGuard{reg: reg}, "/v1/e2b/guard", 0, 0))
	defer guard.Close()
	req, _ := http.NewRequest(http.MethodPost, guard.URL+"/v1/e2b/guard/raw/v1/chat/completions", strings.NewReader(`{"stream":true}`))
	req.Header.Set(EgressGuardHeader, token)
	resp, err := guard.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get(brokerNoRetryHeader) != "" {
		t.Fatalf("status %d, %s %q", resp.StatusCode, brokerNoRetryHeader, resp.Header.Get(brokerNoRetryHeader))
	}
	buf := make([]byte, 4096)
	n, err := resp.Body.Read(buf)
	if err != nil || n == 0 {
		t.Fatalf("first read: %d, %v", n, err)
	}
	firstAt := time.Now()
	rest, _ := io.ReadAll(resp.Body)
	if got := string(buf[:n]) + string(rest); got != strings.Join(pieces, "") {
		t.Fatalf("body = %q", got)
	}
	u.mu.Lock()
	lastSent := u.sent[len(u.sent)-1]
	u.mu.Unlock()
	if !firstAt.Before(lastSent) {
		t.Fatalf("the first piece arrived at %v, after the last was written at %v: the guard buffered the answer", firstAt, lastSent)
	}
}
