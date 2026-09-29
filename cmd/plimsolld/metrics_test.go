package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/internal/rpc"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// TestMetricsHandlerServesOnlyMetrics: the metrics listener's handler answers
// /metrics and nothing else, so mounting it cannot expose a probe or the RPC path.
func TestMetricsHandlerServesOnlyMetrics(t *testing.T) {
	h := metricsHandler(rpc.NewSandboxService(sandbox.Disabled{}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "plimsoll_runs_total 0") {
		t.Fatalf("GET /metrics = %d %q, want 200 with the run counter", rec.Code, rec.Body.String())
	}
	for _, path := range []string{"/", "/healthz", "/readyz", "/plimsoll.v1.SandboxService/Run"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s on the metrics handler = %d, want 404", path, rec.Code)
		}
	}
}

func TestWriteHostCallMetricsRender(t *testing.T) {
	// One series: 2 calls, latencies folded so the cumulative buckets rise 0->1->2
	// and the top finite bucket equals Count (all calls under 10s).
	series := []rpc.HostCallSeriesSnapshot{{
		Profile:           "hue",
		Method:            "GET",
		Route:             "/items/*",
		Count:             2,
		SumSec:            0.042,
		CumulativeBuckets: []uint64{0, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2},
	}}
	var buf bytes.Buffer
	writeHostCallMetrics(&buf, series)
	out := buf.String()

	const lbl = `profile="hue",method="GET",route="/items/*"`
	wants := []string{
		"# TYPE plimsoll_host_calls_total counter",
		"plimsoll_host_calls_total{" + lbl + "} 2",
		"# TYPE plimsoll_host_call_latency_seconds histogram",
		// first finite bucket (le=0.001) is 0; the 5ms bucket is 1
		`plimsoll_host_call_latency_seconds_bucket{` + lbl + `,le="0.001"} 0`,
		`plimsoll_host_call_latency_seconds_bucket{` + lbl + `,le="0.005"} 1`,
		// +Inf bucket and _count both equal Count
		`plimsoll_host_call_latency_seconds_bucket{` + lbl + `,le="+Inf"} 2`,
		"plimsoll_host_call_latency_seconds_sum{" + lbl + "} 0.042",
		"plimsoll_host_call_latency_seconds_count{" + lbl + "} 2",
	}
	for _, want := range wants {
		if !strings.Contains(out, want) {
			t.Errorf("metrics output missing line:\n  %s\n--- full output ---\n%s", want, out)
		}
	}
}

func TestWriteHostCallMetricsEmpty(t *testing.T) {
	var buf bytes.Buffer
	writeHostCallMetrics(&buf, nil)
	if buf.Len() != 0 {
		t.Errorf("no series should render nothing, got %q", buf.String())
	}
}

func TestWriteAdviceMetricsRender(t *testing.T) {
	series := []rpc.AdviceSeriesSnapshot{{
		Profile:         "hue",
		Pattern:         "fan_out",
		Severity:        "high",
		Remedy:          "batch",
		AgentFixable:    true,
		Count:           3,
		ExtraCalls:      21,
		AddedLatencySec: 0.75,
		BytesMoved:      4096,
	}}
	var buf bytes.Buffer
	writeAdviceMetrics(&buf, series)
	out := buf.String()

	const lbl = `profile="hue",pattern="fan_out",severity="high",remedy="batch",agent_fixable="true"`
	wants := []string{
		"# TYPE plimsoll_advice_findings_total counter",
		"plimsoll_advice_findings_total{" + lbl + "} 3",
		"plimsoll_advice_extra_calls_total{" + lbl + "} 21",
		"plimsoll_advice_added_latency_seconds_total{" + lbl + "} 0.75",
		"plimsoll_advice_bytes_moved_total{" + lbl + "} 4096",
	}
	for _, want := range wants {
		if !strings.Contains(out, want) {
			t.Errorf("advice metrics missing line:\n  %s\n--- full output ---\n%s", want, out)
		}
	}
}

func TestWriteAdviceMetricsEmpty(t *testing.T) {
	var buf bytes.Buffer
	writeAdviceMetrics(&buf, nil)
	if buf.Len() != 0 {
		t.Errorf("no series should render nothing, got %q", buf.String())
	}
}

func TestEscapeLabelValue(t *testing.T) {
	// backslash, quote, and newline are the three the exposition format requires.
	in := "a\"b\\c\nd"
	if got, want := escapeLabelValue(in), `a\"b\\c\nd`; got != want {
		t.Errorf("escapeLabelValue(%q) = %q, want %q", in, got, want)
	}
	// A route template with a quote must not break the label set.
	got := hostCallLabels(rpc.HostCallSeriesSnapshot{Profile: "p", Method: "GET", Route: `/a"b`}, "")
	if want := `profile="p",method="GET",route="/a\"b"`; got != want {
		t.Errorf("hostCallLabels route quote = %q, want %q", got, want)
	}
}
