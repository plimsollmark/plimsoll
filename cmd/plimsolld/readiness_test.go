package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/plimsollmark/plimsoll/internal/rpc"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// countingPreflight is a provider with no cache of its own: every Preflight is counted,
// takes delay, and answers err (settable).
type countingPreflight struct {
	sandbox.Disabled
	delay time.Duration

	calls, inFlight, maxInFlight atomic.Int64
	mu                           sync.Mutex
	err                          error
}

func (p *countingPreflight) Preflight(ctx context.Context) error {
	p.calls.Add(1)
	n := p.inFlight.Add(1)
	defer p.inFlight.Add(-1)
	for {
		m := p.maxInFlight.Load()
		if n <= m || p.maxInFlight.CompareAndSwap(m, n) {
			break
		}
	}
	select {
	// fixed-wait: the fake provider's own check time, ended early by its context; it stands for nothing else
	case <-time.After(p.delay):
	case <-ctx.Done():
		return ctx.Err()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

func (p *countingPreflight) set(err error) {
	p.mu.Lock()
	p.err = err
	p.mu.Unlock()
}

// countingListener counts the connections it accepts.
type countingListener struct {
	net.Listener
	accepted atomic.Int64
}

func (l *countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.accepted.Add(1)
	}
	return c, err
}

// The reviewer's case (hunt-security-2): the daemon's own RPC mux behind its own server,
// no credential, a provider whose Preflight takes 300 ms and has no cache, and 250
// /readyz requests at once over one HTTP/2 connection. Before the daemon's cache, that
// was 250 Preflights at once; now it is one, and every request reads its answer.
func TestReadyzFloodRunsOnePreflight(t *testing.T) {
	sb := &countingPreflight{delay: 300 * time.Millisecond}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := &countingListener{Listener: raw}
	srv := newHTTPServer(ln.Addr().String(), rpcMux(rpc.NewSandboxService(sb), nil, 1, sb), nil)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	tr := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}
	t.Cleanup(tr.CloseIdleConnections)
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	url := "http://" + ln.Addr().String() + "/readyz"
	// One request first, so the connection exists before the flood shares it.
	if resp, err := client.Get("http://" + ln.Addr().String() + "/healthz"); err != nil {
		t.Fatal(err)
	} else {
		_ = resp.Body.Close()
	}

	const n = 250
	var wg sync.WaitGroup
	var ready, other atomic.Int64
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := client.Get(url)
			if err != nil {
				other.Add(1)
				return
			}
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				ready.Add(1)
			} else {
				other.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := sb.calls.Load(); got != 1 {
		t.Errorf("%d concurrent /readyz requests ran %d Preflights, want 1", n, got)
	}
	if got := sb.maxInFlight.Load(); got != 1 {
		t.Errorf("at most %d Preflights were in flight at once, want 1", got)
	}
	if ready.Load() != n || other.Load() != 0 {
		t.Errorf("ready answers %d, others %d; want all %d ready", ready.Load(), other.Load(), n)
	}
	if got := ln.accepted.Load(); got != 1 {
		t.Errorf("the requests used %d connections, want 1", got)
	}
}

// A failed check is never served as ready: within the window its failure stands, even
// once the provider has recovered, and the first request after the window runs a new
// check and reads ready. A recovered provider can therefore read not ready for at most
// readyWindow after the failing check ended, plus the next check's own duration.
func TestReadyCacheNeverServesAFailureAsReady(t *testing.T) {
	sb := &countingPreflight{}
	sb.set(errors.New("gateway unreachable"))
	clock := time.Unix(1_000_000, 0)
	var mu sync.Mutex
	c := newReadyCache(sb)
	c.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	advance := func(d time.Duration) { mu.Lock(); clock = clock.Add(d); mu.Unlock() }

	if err := c.check(context.Background()); err == nil {
		t.Fatal("a failing Preflight read as ready")
	}
	sb.set(nil) // the provider recovers
	advance(readyWindow - time.Millisecond)
	if err := c.check(context.Background()); err == nil {
		t.Fatal("a cached failure was served as ready")
	}
	if got := sb.calls.Load(); got != 1 {
		t.Fatalf("within the window: %d Preflights, want 1 (the failure is cached too)", got)
	}
	advance(time.Millisecond)
	if err := c.check(context.Background()); err != nil {
		t.Fatalf("after the window, a recovered provider still reads not ready: %v", err)
	}
	if got := sb.calls.Load(); got != 2 {
		t.Fatalf("after the window: %d Preflights, want 2", got)
	}
	// And the other way: a provider that fails after a ready answer reads not ready at
	// the first check after the window.
	sb.set(errors.New("runtime gone"))
	advance(readyWindow)
	if err := c.check(context.Background()); err == nil {
		t.Fatal("a provider that failed reads ready after the window")
	}
}

// A request that arrives during a check waits for that check's answer instead of being
// given the previous one, and a request that ends first is not ready while the check
// still finishes, detached, and its answer stands for the next request.
func TestReadyCacheWaitersShareTheCheckInFlight(t *testing.T) {
	sb := &countingPreflight{delay: 200 * time.Millisecond}
	c := newReadyCache(sb)
	short, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := c.check(short); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a request that ended during the check: %v, want its deadline", err)
	}
	if err := c.check(context.Background()); err != nil {
		t.Fatalf("a request waiting on the check in flight: %v", err)
	}
	if got := sb.calls.Load(); got != 1 {
		t.Fatalf("%d Preflights, want 1: the second request waited on the first's check", got)
	}
}

// The readiness check's budget sits above the bound every provider holds its own check
// under (sandbox.PreflightBound), so a slow check is the provider's to report; the cache
// is built with it. The budget is computed from the bound; this fails when a number typed
// in its place parts from it (hunt-quality-58).
func TestTheReadinessBudgetSitsAboveTheProvidersBound(t *testing.T) {
	if readyMargin <= 0 || readyBudget != sandbox.PreflightBound+readyMargin {
		t.Fatalf("the readiness budget is %s; want the providers' bound %s plus the margin %s", readyBudget, sandbox.PreflightBound, readyMargin)
	}
	if c := newReadyCache(panickingPreflight{}); c.budget != readyBudget {
		t.Errorf("the readiness cache gives a check %s, want %s", c.budget, readyBudget)
	}
}

// A provider that panics in Preflight is not ready, and the daemon goes on.
func TestReadyCacheSurvivesAPanickingPreflight(t *testing.T) {
	c := newReadyCache(panickingPreflight{})
	if err := c.check(context.Background()); err == nil {
		t.Fatal("a panicking Preflight read as ready")
	}
}

type panickingPreflight struct{ sandbox.Disabled }

func (panickingPreflight) Preflight(context.Context) error { panic("provider bug") }
