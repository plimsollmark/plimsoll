package rpc

import (
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
)

func TestHostCallStatsFoldsCountsAndBuckets(t *testing.T) {
	var svc SandboxService
	// Two calls to /items/*, one to /orders; the two /items latencies land in
	// different buckets (2ms -> le=0.005, 40ms -> le=0.05).
	svc.hostCalls.observe("hue", &sandbox.CallTrace{Calls: []sandbox.CallRow{
		{Method: "GET", Route: "/items/*", Latency: 2 * time.Millisecond},
		{Method: "GET", Route: "/items/*", Latency: 40 * time.Millisecond},
		{Method: "POST", Route: "/orders", Latency: 300 * time.Millisecond},
	}})
	// A no-grant run must not create series.
	svc.hostCalls.observe("hue", nil)

	series := svc.HostCallStats()
	if len(series) != 2 {
		t.Fatalf("got %d series, want 2 (GET /items/*, POST /orders)", len(series))
	}

	// Sorted by (profile, method, route): GET /items/* before POST /orders.
	items := series[0]
	if items.Method != "GET" || items.Route != "/items/*" || items.Count != 2 {
		t.Fatalf("first series = %+v, want GET /items/* count 2", items)
	}
	if len(items.CumulativeBuckets) != len(HostCallLatencyBounds()) {
		t.Fatalf("bucket count = %d, want %d", len(items.CumulativeBuckets), len(HostCallLatencyBounds()))
	}
	// Cumulative: no observation <= 1ms; one <= 5ms (the 2ms call); both <= 50ms and
	// beyond; final cumulative == Count.
	bounds := HostCallLatencyBounds()
	for i, ub := range bounds {
		got := items.CumulativeBuckets[i]
		var want uint64
		switch {
		case ub < 0.005: // below the 2ms call's bucket
			want = 0
		case ub < 0.05: // includes the 2ms call, not yet the 40ms
			want = 1
		default: // includes both
			want = 2
		}
		if got != want {
			t.Errorf("bucket le=%g: got %d, want %d", ub, got, want)
		}
	}
	if last := items.CumulativeBuckets[len(bounds)-1]; last != items.Count {
		t.Errorf("last finite bucket %d != count %d (all calls fit under 10s)", last, items.Count)
	}

	orders := series[1]
	if orders.Method != "POST" || orders.Route != "/orders" || orders.Count != 1 {
		t.Fatalf("second series = %+v, want POST /orders count 1", orders)
	}
}

func TestHostCallStatsAboveTopBucketOnlyInInf(t *testing.T) {
	var svc SandboxService
	// A 12s latency exceeds the top finite bound (10s): every finite bucket is 0,
	// but Count (the +Inf bucket) is 1.
	svc.hostCalls.observe("p", &sandbox.CallTrace{Calls: []sandbox.CallRow{
		{Method: "GET", Route: "/slow", Latency: 12 * time.Second},
	}})
	series := svc.HostCallStats()
	if len(series) != 1 {
		t.Fatalf("got %d series, want 1", len(series))
	}
	s := series[0]
	if s.Count != 1 {
		t.Fatalf("count = %d, want 1", s.Count)
	}
	for i, c := range s.CumulativeBuckets {
		if c != 0 {
			t.Errorf("finite bucket %d = %d, want 0 (observation is above the top bound)", i, c)
		}
	}
}

func TestHostCallStatsEmptyByDefault(t *testing.T) {
	var svc SandboxService
	if got := svc.HostCallStats(); len(got) != 0 {
		t.Errorf("fresh service HostCallStats = %v, want empty", got)
	}
}
