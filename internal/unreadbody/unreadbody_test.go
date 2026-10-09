package unreadbody

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// stall is how long a test waits for a response before calling it held. The server
// in these tests has a 30 s read timeout, as plimsolld's does, so a drained body
// would hold the response far past it.
const stall = 5 * time.Second

func newServer(t *testing.T, h http.Handler) string {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.Config.ReadTimeout = 30 * time.Second
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	srv.Config.Protocols = protocols
	srv.Start()
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}

// refuse answers 401 without reading the body, as an auth check does.
var refuse = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "no", http.StatusUnauthorized)
})

// slowRequest sends the head of a request and the first bytes of its body, then
// holds the rest back, and returns the connection.
func slowRequest(t *testing.T, addr, head, partial string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := io.WriteString(conn, head+"\r\n"+partial); err != nil {
		t.Fatal(err)
	}
	return conn
}

// readResponse reads one response from conn within stall.
func readResponse(t *testing.T, conn net.Conn, br *bufio.Reader) *http.Response {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(stall))
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("no response within %v while the body was held back: %v", stall, err)
	}
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatalf("response body: %v", err)
	}
	_ = resp.Body.Close()
	return resp
}

// expectClosed checks that the server closes the connection within Grace and some
// slack, long before its 30 s read timeout.
func expectClosed(t *testing.T, conn net.Conn, br *bufio.Reader) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(Grace + 2*time.Second))
	if _, err := br.ReadByte(); err == nil {
		t.Fatal("server sent more after the response")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("server still held the connection after the grace period")
	}
}

func TestRefusalDoesNotWaitForAHeldBackBody(t *testing.T) {
	cases := map[string]struct {
		head, partial string
		handler       http.Handler
	}{
		"content-length": {
			head:    "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n",
			partial: "{}",
			handler: refuse,
		},
		"chunked": {
			head:    "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n",
			partial: "2\r\n{}\r\n",
			handler: refuse,
		},
		"handler closes the body first": {
			head:    "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n",
			partial: "{}",
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = r.Body.Close()
				http.Error(w, "no", http.StatusUnauthorized)
			}),
		},
		"handler writes nothing": {
			head:    "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n",
			partial: "{}",
			handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		},
		"handler reads part": {
			head:    "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n",
			partial: "{}",
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = r.Body.Read(make([]byte, 2))
				http.Error(w, "no", http.StatusBadRequest)
			}),
		},
		"wrapped twice": {
			head:    "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n",
			partial: "{}",
			handler: Handler(refuse),
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			addr := newServer(t, Handler(tc.handler))
			conn := slowRequest(t, addr, tc.head, tc.partial)
			br := bufio.NewReader(conn)
			resp := readResponse(t, conn, br)
			if !resp.Close {
				t.Errorf("response does not close the connection; header %v", resp.Header)
			}
			expectClosed(t, conn, br)
		})
	}
}

// The control: without the wrapper the same refusal waits for the body. If Go's
// server ever stops draining, this fails and the wrapper can go.
func TestUnwrappedRefusalWaitsForTheBody(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out the stall window")
	}
	addr := newServer(t, refuse)
	conn := slowRequest(t, addr, "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n", "{}")
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := http.ReadResponse(bufio.NewReader(conn), nil); err == nil {
		t.Fatal("the unwrapped refusal answered before the body arrived; Go no longer drains, so unreadbody is unneeded")
	}
}

func TestReadBodyKeepsTheConnection(t *testing.T) {
	addr := newServer(t, Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		_, _ = w.Write(b)
	})))
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	br := bufio.NewReader(conn)
	for i := range 2 {
		if _, err := io.WriteString(conn, "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{}"); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		if resp := readResponse(t, conn, br); resp.Close || resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status %d, close %v; a fully read body must keep the connection", i, resp.StatusCode, resp.Close)
		}
	}
}

// HTTP/2 resets the stream of an unread body, so the refusal never waited there;
// this keeps that true.
func TestHTTP2RefusalDoesNotWaitForAHeldBackBody(t *testing.T) {
	addr := newServer(t, Handler(refuse))
	tr := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}
	defer tr.CloseIdleConnections()
	pr, pw := io.Pipe()
	defer pw.Close()
	go func() { _, _ = io.WriteString(pw, "{}") }()
	ctx, cancel := context.WithTimeout(context.Background(), stall)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+addr+"/", pr)
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = 100
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		t.Fatalf("no HTTP/2 response while the body was held back: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || resp.ProtoMajor != 2 {
		t.Fatalf("got %s %d, want HTTP/2 401", resp.Proto, resp.StatusCode)
	}
	if strings.EqualFold(resp.Header.Get("Connection"), "close") {
		t.Fatal("an HTTP/2 refusal must not ask to close the connection: Go turns that into a GOAWAY for every stream on it")
	}
}
