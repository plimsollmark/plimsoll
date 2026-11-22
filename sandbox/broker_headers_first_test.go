package sandbox

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// firstPieceAfter is a guest body whose first piece is not JSON and is handed over only
// once the API has been reached (or after a wait): the transport sends the request's
// headers before it reads the body, so the API can act before the broker sees a byte.
type firstPieceAfter struct {
	reached <-chan struct{}
	sent    bool
}

func (f *firstPieceAfter) Read(p []byte) (int, error) {
	if f.sent {
		return 0, io.EOF
	}
	select {
	case <-f.reached:
	// fixed-wait: a bound, not the event: the read waits for the API's handler to start, and goes on after 2 s only so a transport that read the body before sending headers fails the test (the API acted 0 times) instead of hanging it
	case <-time.After(2 * time.Second):
	}
	f.sent = true
	return copy(p, "\x00"), nil
}

// TestBrokerStreamedRefusalAtTheFirstPieceKeepsTheCharge (release-98): a passed-through
// body refused at its first piece was
// refunded and left out of the trace, on the reasoning that the API "got the request's
// headers alone". Go's transport sends the headers before it reads the body, and an API's
// handler runs on the headers: one that acts before reading the body (a quota or audit
// step, a job started from the path) acted on every such call. So a call that reached the
// transport keeps its route charge and has a row, whatever it sent of its body. Real
// transport, real HTTP/1.1 server, a route capped at one call.
func TestBrokerStreamedRefusalAtTheFirstPieceKeepsTheCharge(t *testing.T) {
	t.Parallel()
	var acted atomic.Int32
	reached := make(chan struct{}, 16)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		acted.Add(1) // acts on the headers, then reads the body
		reached <- struct{}{}
		if _, err := io.ReadAll(r.Body); err != nil {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(srv.Close)
	jobs := HostRoute{Method: "POST", Path: "/v1/jobs"}
	g := &HostAPIGrant{
		BaseURL:              srv.URL,
		Allow:                []HostRoute{jobs},
		RouteMaxRequestBytes: map[HostRoute]int64{jobs: 4 << 20}, // above the buffered limit: passed through
		RouteMaxCalls:        map[HostRoute]int{jobs: 1},
	}
	core, err := newBrokerSession(g, "tok", nil) // the production transport
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	json := func() brokerCall {
		return brokerCall{Method: "POST", RawTarget: "/v1/jobs",
			Headers: map[string][]string{"Content-Type": {"application/json"}}}
	}
	refused := json()
	refused.Body, refused.ContentLength = &firstPieceAfter{reached: reached}, 2
	if resp := core.Call(context.Background(), refused); resp.Status != http.StatusBadRequest {
		t.Fatalf("the refused call: %d %q, want 400", resp.Status, resp.Body)
	}
	if n := acted.Load(); n != 1 {
		t.Fatalf("the API acted %d times on the refused call; the test needs it to have acted once (on the headers)", n)
	}
	again := json()
	again.Body, again.ContentLength = strings.NewReader(`{}`), 2
	if resp := core.Call(context.Background(), again); resp.Status != http.StatusTooManyRequests {
		t.Errorf("the next call got %d %q, want 429: the refused call reached the API and must spend the route's one call", resp.Status, resp.Body)
	}
	if n := acted.Load(); n != 1 {
		t.Errorf("the API acted %d times on a route capped at one call", n)
	}
	trace := core.traceSnapshot()
	if len(trace.Calls) != 1 {
		t.Fatalf("trace: %d rows, want 1 for the refused call that reached the API", len(trace.Calls))
	}
	if row := trace.Calls[0]; row.Delivered || row.Route != jobs.Path || row.ReqBytes != 0 {
		t.Errorf("row %+v: want an undelivered POST %s with no body bytes sent", row, jobs.Path)
	}
}
