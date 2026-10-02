package sandbox

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// sessionBrokerFixture is a docker session's broker socket serving one call's grant,
// with an upstream API that counts the requests reaching it.
func sessionBrokerFixture(t *testing.T, upstream http.HandlerFunc) (*dockerSessionBroker, *brokerSession, func(), *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		upstream(w, r)
	}))
	t.Cleanup(api.Close)
	b, err := startDockerSessionBroker()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	grant := &HostAPIGrant{BaseURL: api.URL, Allow: []HostRoute{{Method: "POST", Path: "/v1/items"}}, Minter: StaticToken("call-token")}
	core, err := brokerSessionForGrant(context.Background(), grant, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return b, core, b.lend(core), &hits
}

// A process a call left running can begin a request through the session's broker
// during a later granted call and send its body slowly. Once that call has ended
// and released its grant, the request must not reach the API with the call's
// credential.
func TestSessionBrokerRefusesARequestThatOutlivesItsCall(t *testing.T) {
	b, _, release, hits := sessionBrokerFixture(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "{}")
	})
	conn, err := net.Dial("unix", b.sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// Headers and half the body during the call.
	if _, err := io.WriteString(conn, "POST /v1/items HTTP/1.1\r\nHost: broker\r\nContent-Length: 10\r\n\r\n12345"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond) // the handler holds the call's grant and waits for the body
	release()                          // the call ends
	if _, err := io.WriteString(conn, "67890"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if n := hits.Load(); n != 0 {
		t.Fatalf("the API received %d request(s) after the call that lent the grant ended; the broker answered %d %q", n, resp.StatusCode, body)
	}
	if resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(string(body), "grant has ended") {
		t.Fatalf("answer %d %q, want 503 grant has ended", resp.StatusCode, body)
	}
}

// A request already upstream when its call ends is cut off, and the call's trace,
// read after the release, holds it.
func TestSessionBrokerReleaseCutsOffAndTracesTheRequestInFlight(t *testing.T) {
	arrived, stop := make(chan struct{}, 1), make(chan struct{})
	b, core, release, _ := sessionBrokerFixture(t, func(w http.ResponseWriter, r *http.Request) {
		arrived <- struct{}{}
		select {
		case <-r.Context().Done():
		case <-stop:
		}
	})
	t.Cleanup(func() { close(stop) }) // runs before the fixture's API closes
	conn, err := net.Dial("unix", b.sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "POST /v1/items HTTP/1.1\r\nHost: broker\r\nContent-Length: 2\r\n\r\n{}"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-arrived:
	case <-time.After(10 * time.Second):
		t.Fatal("the request never reached the API")
	}
	start := time.Now()
	release()
	if took := time.Since(start); took > brokerEndWait {
		t.Fatalf("release took %v: the request upstream was not cut off", took)
	}
	tr := core.traceSnapshot()
	if tr == nil || len(tr.Calls) != 1 || tr.Calls[0].Delivered {
		t.Fatalf("trace after release: %+v; want the one call, undelivered", tr)
	}
}
