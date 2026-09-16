package insights

import (
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// trace builds a CallTrace from rows, assigning 1-based Seq in argument order (the
// broker records Seq in completion order, which is what the detectors read).
func trace(rows ...sandbox.CallRow) *sandbox.CallTrace {
	for i := range rows {
		rows[i].Seq = i + 1
	}
	return &sandbox.CallTrace{Calls: rows}
}

// fanoutRows returns n successful (delivered, 200) GET calls to route, each with a
// DISTINCT response size and a fixed latency. The distinct sizes keep the rows neutral
// for the repeated-read detector on a fixed route; on a wildcard route that detector
// never fires anyway (see TestRepeatedReadIgnoresWildcardRoutes).
func fanoutRows(route string, n int, lat time.Duration) []sandbox.CallRow {
	rows := make([]sandbox.CallRow, n)
	for i := range rows {
		rows[i] = sandbox.CallRow{Method: "GET", Route: route, Status: 200, Delivered: true, RespBytes: 100 + i, Latency: lat}
	}
	return rows
}

func find(fs []Finding, p PatternID) (Finding, bool) {
	for _, f := range fs {
		if f.Pattern == p {
			return f, true
		}
	}
	return Finding{}, false
}

func TestFanOutDetected(t *testing.T) {
	tr := trace(fanoutRows("/items/*", 12, 5*time.Millisecond)...)
	got := Analyze(tr, nil)

	f, ok := find(got, PatternFanOut)
	if !ok {
		t.Fatalf("fan-out not detected in %d findings", len(got))
	}
	if f.Remedy != RemedyBatch || f.Route != "/items/*" || f.Method != "GET" {
		t.Errorf("fan-out finding = %+v, want batch on GET /items/*", f)
	}
	if f.Severity != SeverityLow { // 12 calls < 25 -> low
		t.Errorf("severity = %s, want low for 12 calls", f.Severity)
	}
	if f.Cost.ExtraCalls != 11 {
		t.Errorf("ExtraCalls = %d, want 11", f.Cost.ExtraCalls)
	}
	// 12 calls at 5ms, minus one call's latency = 55ms saved if batched.
	if want := 55 * time.Millisecond; f.Cost.AddedLatency != want {
		t.Errorf("AddedLatency = %s, want %s", f.Cost.AddedLatency, want)
	}

	// One observation, one finding: the same twelve reads must not also be reported
	// under a second pattern with the same numbers (that double counted the audit
	// totals until 2026-09-16), and a wildcard route is never a repeated read.
	if len(got) != 1 {
		t.Errorf("expected exactly one finding for one route group, got %d: %+v", len(got), got)
	}
	if _, ok := find(got, PatternRepeatedRead); ok {
		t.Error("a wildcard route must not trigger repeated-read")
	}
	// The remedy is stated as a condition, not a promise: the trace cannot show that
	// the collection route returns the same items.
	if !strings.Contains(f.Detail, "if it returns the same items") {
		t.Errorf("fan-out detail should state the condition on the replacement: %q", f.Detail)
	}
}

func TestFanOutSeverityScales(t *testing.T) {
	if got := Analyze(trace(fanoutRows("/items/*", 30, time.Millisecond)...), nil); severityOf(got, PatternFanOut) != SeverityMedium {
		t.Errorf("30 calls: fan-out severity = %s, want medium", severityOf(got, PatternFanOut))
	}
	if got := Analyze(trace(fanoutRows("/items/*", 120, time.Millisecond)...), nil); severityOf(got, PatternFanOut) != SeverityHigh {
		t.Errorf("120 calls: fan-out severity = %s, want high", severityOf(got, PatternFanOut))
	}
}

func TestFanOutBelowThresholdIsClean(t *testing.T) {
	// 5 calls is under fanOutMinCalls (6): no findings at all.
	if got := Analyze(trace(fanoutRows("/items/*", 5, time.Millisecond)...), nil); len(got) != 0 {
		t.Errorf("5 calls produced %d findings, want none: %+v", len(got), got)
	}
}

// TestFailedCallsAreNotCounted: a call the guest got no successful answer to retrieved
// nothing a batch or a cache could replace, so it never counts toward a pattern. The
// failures are named in the finding's sentence so the telemetry is not lost.
func TestFailedCallsAreNotCounted(t *testing.T) {
	allow := []sandbox.HostRoute{{Method: "GET", Path: "/items"}}

	// Eight delivered 404s: nothing was retrieved, so there is nothing to batch and no
	// suggestion to hand the caller.
	var notFound []sandbox.CallRow
	for i := 0; i < 8; i++ {
		notFound = append(notFound, sandbox.CallRow{Method: "GET", Route: "/items/*", Status: 404, Delivered: true, RespBytes: 30 + i, Latency: time.Millisecond})
	}
	if got := Analyze(trace(notFound...), allow); len(got) != 0 {
		t.Errorf("eight 404s produced findings, want none: %+v", got)
	}

	// Eight successes plus four 500s: the fan-out counts the eight and names the four.
	mixed := fanoutRows("/items/*", 8, time.Millisecond)
	for i := 0; i < 4; i++ {
		mixed = append(mixed, sandbox.CallRow{Method: "GET", Route: "/items/*", Status: 500, Delivered: true, RespBytes: 12, Latency: time.Millisecond})
	}
	got := Analyze(trace(mixed...), allow)
	f, ok := find(got, PatternFanOut)
	if !ok || len(got) != 1 {
		t.Fatalf("mixed trace: want exactly one fan-out, got %+v", got)
	}
	if f.Cost.ExtraCalls != 7 || f.Cost.BytesMoved != 8*100+(0+1+2+3+4+5+6+7) {
		t.Errorf("fan-out counted failed calls: ExtraCalls=%d BytesMoved=%d, want 7 and the eight successes' bytes", f.Cost.ExtraCalls, f.Cost.BytesMoved)
	}
	if !strings.Contains(f.Detail, "8 successful GET /items/* calls") || !strings.Contains(f.Detail, "4 more calls to this route did not succeed and are not counted") {
		t.Errorf("detail should count the successes and name the failures: %q", f.Detail)
	}

	// Four reads of a fixed route that the upstream never answered (status 0, no bytes)
	// are not four copies of an unchanged resource; they are four failures.
	var unanswered []sandbox.CallRow
	for i := 0; i < 4; i++ {
		unanswered = append(unanswered, sandbox.CallRow{Method: "GET", Route: "/v1/config", Status: 0, Delivered: false, RespBytes: 0, Latency: 50 * time.Millisecond})
	}
	if got := Analyze(trace(unanswered...), nil); len(got) != 0 {
		t.Errorf("unanswered reads produced findings, want none: %+v", got)
	}
}

// TestUndeliveredResponsesAreNotSuccesses: the broker records the upstream status even
// when it refuses to deliver the body (oversized, unreadable), so a 200 alone is not a
// success. Zero bytes cannot stand in for the distinction either, because an empty
// successful response is valid; Delivered is the field that settles it.
func TestUndeliveredResponsesAreNotSuccesses(t *testing.T) {
	var capped []sandbox.CallRow
	for i := 0; i < 8; i++ {
		capped = append(capped, sandbox.CallRow{Method: "GET", Route: "/items/*", Status: 200, Delivered: false, RespBytes: 0, Latency: time.Millisecond})
	}
	if got := Analyze(trace(capped...), []sandbox.HostRoute{{Method: "GET", Path: "/items"}}); len(got) != 0 {
		t.Errorf("eight undelivered 200s produced findings, want none: %+v", got)
	}

	// Six delivered successes among six undelivered 200s: the fan-out counts six.
	mixed := fanoutRows("/items/*", 6, time.Millisecond)
	mixed = append(mixed, capped[:6]...)
	got := Analyze(trace(mixed...), nil)
	f, ok := find(got, PatternFanOut)
	if !ok || f.Cost.ExtraCalls != 5 || !strings.Contains(f.Detail, "6 more calls to this route did not succeed") {
		t.Errorf("mixed delivered/undelivered: got %+v, want a fan-out over the six delivered calls naming six failures", got)
	}

	// An empty delivered 2xx IS a success: four of them on a fixed route are a repeated
	// read of a (possibly empty) resource, exactly as four non-empty ones would be.
	var empty []sandbox.CallRow
	for i := 0; i < 4; i++ {
		empty = append(empty, sandbox.CallRow{Method: "GET", Route: "/v1/flags", Status: 204, Delivered: true, RespBytes: 0, Latency: time.Millisecond})
	}
	if _, ok := find(Analyze(trace(empty...), nil), PatternRepeatedRead); !ok {
		t.Error("four delivered empty 2xx reads of a fixed route should still be a repeated read")
	}
}

// TestIncompleteTraceIsQualified: past the row cap the broker counts calls in Dropped
// instead of storing them, so a finding's count is a floor and its sentence says so.
func TestIncompleteTraceIsQualified(t *testing.T) {
	tr := trace(fanoutRows("/items/*", 12, time.Millisecond)...)
	tr.Dropped = 300
	f, ok := find(Analyze(tr, nil), PatternFanOut)
	if !ok {
		t.Fatal("fan-out not detected on a partial trace")
	}
	if f.Cost.ExtraCalls != 11 || !strings.Contains(f.Detail, "at least 12 successful") {
		t.Errorf("partial trace: ExtraCalls=%d detail=%q, want 11 and an 'at least 12' sentence", f.Cost.ExtraCalls, f.Detail)
	}
	full, _ := find(Analyze(trace(fanoutRows("/items/*", 12, time.Millisecond)...), nil), PatternFanOut)
	if strings.Contains(full.Detail, "at least") {
		t.Errorf("a complete trace must not hedge its count: %q", full.Detail)
	}
}

func TestRepeatedReadsDetected(t *testing.T) {
	// Six reads of one fixed collection, all the same size: cacheable, not fan-out
	// (no wildcard) and not aggregate-in-code (dominant route is not per-item).
	rows := make([]sandbox.CallRow, 6)
	for i := range rows {
		rows[i] = sandbox.CallRow{Method: "GET", Route: "/v1/config", Status: 200, Delivered: true, RespBytes: 512, Latency: 10 * time.Millisecond}
	}
	got := Analyze(trace(rows...), nil)

	f, ok := find(got, PatternRepeatedRead)
	if !ok {
		t.Fatalf("repeated-read not detected: %+v", got)
	}
	if f.Remedy != RemedyCache || f.Route != "/v1/config" {
		t.Errorf("repeated-read finding = %+v, want cache on /v1/config", f)
	}
	if f.Cost.ExtraCalls != 5 {
		t.Errorf("ExtraCalls = %d, want 5", f.Cost.ExtraCalls)
	}
	if !strings.Contains(f.Detail, "512 bytes") {
		t.Errorf("detail should name the unchanged response size: %q", f.Detail)
	}
	// The detail must claim only what the trace holds: the same request (a fixed
	// route) and the same size, never the same content, and it states the cache
	// remedy as conditional on the data really being unchanged.
	if !strings.Contains(f.Detail, "not proof") || strings.Contains(f.Detail, "identical response") || !strings.Contains(f.Detail, "only if the data was in fact unchanged") {
		t.Errorf("detail overstates the size evidence: %q", f.Detail)
	}
	if _, ok := find(got, PatternFanOut); ok {
		t.Error("a non-wildcard route must not trigger fan-out")
	}
	if len(got) != 1 {
		t.Errorf("expected exactly one finding, got %d: %+v", len(got), got)
	}
}

// TestRepeatedReadIgnoresWildcardRoutes is the advisor example's case: twelve
// per-item reads of /items/* where eight responses happen to be the same size. The
// trace holds the template and the size, not the item, so it cannot tell one item
// fetched eight times from eight same-size items; the detector must not claim it can.
// The route is fan-out's, and the batch remedy holds either way.
func TestRepeatedReadIgnoresWildcardRoutes(t *testing.T) {
	rows := make([]sandbox.CallRow, 12)
	for i := range rows {
		size := 40
		if i < 8 {
			size = 41
		}
		rows[i] = sandbox.CallRow{Method: "GET", Route: "/items/*", Status: 200, Delivered: true, RespBytes: size, Latency: time.Millisecond}
	}
	got := Analyze(trace(rows...), nil)
	if f, ok := find(got, PatternRepeatedRead); ok {
		t.Errorf("same-size reads of a wildcard route must not be a repeated read: %+v", f)
	}
	if _, ok := find(got, PatternFanOut); !ok {
		t.Error("the same-size per-item reads are still a fan-out")
	}
}

func TestRepeatedReadHeuristicSeverityCap(t *testing.T) {
	// 200 identical reads would be "high" by raw count, but the size proxy is a
	// heuristic so repeated-read is capped at medium.
	rows := make([]sandbox.CallRow, 200)
	for i := range rows {
		rows[i] = sandbox.CallRow{Method: "GET", Route: "/v1/config", Status: 200, Delivered: true, RespBytes: 8, Latency: time.Millisecond}
	}
	if got := severityOf(Analyze(trace(rows...), nil), PatternRepeatedRead); got != SeverityMedium {
		t.Errorf("repeated-read severity = %s, want it capped at medium", got)
	}
}

// TestMultiRouteLatencyIsNotAFinding: several slow calls across several routes used to
// trip a "sequential calls" detector. The trace holds one latency per call and a
// completion-order sequence number, never a start time, so it cannot tell four serial
// calls from four that already overlapped; the detector was deleted on 2026-09-16 and
// this shape must produce nothing.
func TestMultiRouteLatencyIsNotAFinding(t *testing.T) {
	rows := []sandbox.CallRow{
		{Method: "GET", Route: "/a", Status: 200, Delivered: true, RespBytes: 10, Latency: 200 * time.Millisecond},
		{Method: "GET", Route: "/b", Status: 200, Delivered: true, RespBytes: 11, Latency: 200 * time.Millisecond},
		{Method: "GET", Route: "/c", Status: 200, Delivered: true, RespBytes: 12, Latency: 200 * time.Millisecond},
		{Method: "GET", Route: "/a", Status: 200, Delivered: true, RespBytes: 13, Latency: 200 * time.Millisecond},
	}
	if got := Analyze(trace(rows...), nil); len(got) != 0 {
		t.Errorf("multi-route latency produced findings, want none: %+v", got)
	}
}

func TestRouterSuggestsCollectionRoute(t *testing.T) {
	allow := []sandbox.HostRoute{
		{Method: "GET", Path: "/items/*"},
		{Method: "GET", Path: "/items"}, // the batch/collection sibling
	}
	got := Analyze(trace(fanoutRows("/items/*", 8, time.Millisecond)...), allow)
	f, _ := find(got, PatternFanOut)
	if f.Suggested == nil {
		t.Fatal("router should suggest the collection route when the profile grants it")
	}
	if f.Suggested.Method != "GET" || f.Suggested.Path != "/items" {
		t.Errorf("Suggested = %+v, want GET /items", *f.Suggested)
	}

	// No Allow list -> no suggestion (Phase 2 reads nil as "API change needed").
	f2, _ := find(Analyze(trace(fanoutRows("/items/*", 8, time.Millisecond)...), nil), PatternFanOut)
	if f2.Suggested != nil {
		t.Errorf("without an Allow list Suggested must be nil, got %+v", *f2.Suggested)
	}

	// Collection sibling absent from the grant -> no suggestion (agent cannot fix it).
	f3, _ := find(Analyze(trace(fanoutRows("/items/*", 8, time.Millisecond)...), allow[:1]), PatternFanOut)
	if f3.Suggested != nil {
		t.Errorf("no granted sibling should mean no suggestion, got %+v", *f3.Suggested)
	}
}

func TestRouterUsesCatalogForUngrantedBatchRoute(t *testing.T) {
	// The profile grants only the per-item route; the batch collection exists in the API
	// (catalog) but is not granted.
	allow := []sandbox.HostRoute{{Method: "GET", Path: "/items/*"}}
	catalog := []sandbox.HostRoute{
		{Method: "GET", Path: "/items/*"},
		{Method: "GET", Path: "/items"}, // the batch sibling the API offers but the grant omits
	}
	f, _ := find(AnalyzeWithCatalog(trace(fanoutRows("/items/*", 8, time.Millisecond)...), allow, catalog), PatternFanOut)
	if f.Suggested != nil {
		t.Errorf("an ungranted route must not be a caller Suggested, got %+v", *f.Suggested)
	}
	if f.CatalogMatch == nil {
		t.Fatal("router should name the ungranted batch route from the catalog")
	}
	if f.CatalogMatch.Method != "GET" || f.CatalogMatch.Path != "/items" {
		t.Errorf("CatalogMatch = %+v, want GET /items", *f.CatalogMatch)
	}

	// A GRANTED sibling always wins: it stays a caller-fixable Suggested, never CatalogMatch.
	grantedAllow := []sandbox.HostRoute{{Method: "GET", Path: "/items/*"}, {Method: "GET", Path: "/items"}}
	g, _ := find(AnalyzeWithCatalog(trace(fanoutRows("/items/*", 8, time.Millisecond)...), grantedAllow, catalog), PatternFanOut)
	if g.Suggested == nil || g.CatalogMatch != nil {
		t.Errorf("granted sibling should be Suggested (not CatalogMatch): Suggested=%v CatalogMatch=%v", g.Suggested, g.CatalogMatch)
	}

	// No catalog and no granted sibling -> neither is set (the API itself needs a change).
	n, _ := find(Analyze(trace(fanoutRows("/items/*", 8, time.Millisecond)...), allow), PatternFanOut)
	if n.Suggested != nil || n.CatalogMatch != nil {
		t.Errorf("without a catalog or granted sibling both must be nil: %+v / %+v", n.Suggested, n.CatalogMatch)
	}
}

func TestRouterIgnoresNonTrailingWildcard(t *testing.T) {
	// /v1/lights/*/state has a middle wildcard: no simple collection sibling, so even
	// with a plausible Allow list the router suggests nothing (GET, so the verb rule
	// below is not what stops it).
	allow := []sandbox.HostRoute{{Method: "GET", Path: "/v1/lights/*/state"}, {Method: "GET", Path: "/v1/lights"}}
	rows := make([]sandbox.CallRow, 8)
	for i := range rows {
		rows[i] = sandbox.CallRow{Method: "GET", Route: "/v1/lights/*/state", Status: 200, Delivered: true, RespBytes: i, Latency: time.Millisecond}
	}
	f, ok := find(Analyze(trace(rows...), allow), PatternFanOut)
	if !ok {
		t.Fatal("fan-out on a middle-wildcard route should still fire")
	}
	if f.Suggested != nil {
		t.Errorf("non-trailing wildcard must not get a suggestion, got %+v", *f.Suggested)
	}
}

// TestRouterSuggestsReadsOnly: a per-item write fanned out is still a fan-out, but a
// collection write's semantics cannot be read off its path (replace the collection?
// create? apply to a set?), so the router never names it, granted or catalogued. The
// caller is never told to perform a write nobody verified; the finding stays operator
// only, and its sentence says why.
func TestRouterSuggestsReadsOnly(t *testing.T) {
	allow := []sandbox.HostRoute{{Method: "PUT", Path: "/items/*"}, {Method: "PUT", Path: "/items"}}
	catalog := []sandbox.HostRoute{{Method: "PUT", Path: "/items/*"}, {Method: "PUT", Path: "/items"}}
	rows := make([]sandbox.CallRow, 6)
	for i := range rows {
		rows[i] = sandbox.CallRow{Method: "PUT", Route: "/items/*", Status: 200, Delivered: true, ReqBytes: 40, RespBytes: 10 + i, Latency: time.Millisecond}
	}
	f, ok := find(AnalyzeWithCatalog(trace(rows...), allow, catalog), PatternFanOut)
	if !ok {
		t.Fatal("fan-out on a PUT per-item route should still fire")
	}
	if f.Suggested != nil || f.CatalogMatch != nil {
		t.Errorf("a write fan-out must get no replacement route: Suggested=%v CatalogMatch=%v", f.Suggested, f.CatalogMatch)
	}
	if !strings.Contains(f.Detail, "no replacement route is guessed") {
		t.Errorf("write fan-out detail should say why nothing is suggested: %q", f.Detail)
	}
}

func TestNilAndEmptyTrace(t *testing.T) {
	if got := Analyze(nil, nil); got != nil {
		t.Errorf("nil trace = %+v, want nil", got)
	}
	if got := Analyze(&sandbox.CallTrace{}, nil); got != nil {
		t.Errorf("empty trace = %+v, want nil", got)
	}
}

func TestFindingsSortedBySeverityThenPattern(t *testing.T) {
	// A big fan-out (high) plus a small repeated-read burst (low) on separate routes;
	// findings must come back most-severe first.
	rows := fanoutRows("/items/*", 120, time.Millisecond)
	for i := 0; i < 4; i++ {
		rows = append(rows, sandbox.CallRow{Method: "GET", Route: "/v1/config", Status: 200, Delivered: true, RespBytes: 4, Latency: time.Millisecond})
	}
	got := Analyze(trace(rows...), nil)
	if len(got) < 2 {
		t.Fatalf("expected several findings, got %d: %+v", len(got), got)
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].Severity < got[i].Severity {
			t.Errorf("findings not sorted by descending severity: %s before %s", got[i-1].Severity, got[i].Severity)
		}
	}
	if got[0].Severity != SeverityHigh {
		t.Errorf("most severe finding = %s, want high", got[0].Severity)
	}
}

// TestFindingsAreMetadataOnly is the redaction proof at the insights boundary: even
// though the detectors read a trace, every finding string is built only from the
// route template, the HTTP verb, and numbers — a concrete id that a hostile guest
// might try to smuggle can never appear (the trace never carries one, and Detail
// echoes no other input).
func TestFindingsAreMetadataOnly(t *testing.T) {
	const secretID = "hunter2-4242"
	// The trace only ever holds templates; the detectors have no field that could
	// carry secretID. Build a mixed trace that trips several detectors.
	rows := fanoutRows("/items/*", 30, 30*time.Millisecond)
	for i := 0; i < 4; i++ {
		rows = append(rows, sandbox.CallRow{Method: "GET", Route: "/v1/rooms", Status: 200, Delivered: true, RespBytes: 9, Latency: 300 * time.Millisecond})
	}
	got := Analyze(trace(rows...), []sandbox.HostRoute{{Method: "GET", Path: "/items"}})
	if len(got) < 2 {
		t.Fatalf("expected a fan-out and a repeated read, got %+v", got)
	}
	for _, f := range got {
		if strings.Contains(f.Detail, secretID) {
			t.Errorf("finding leaked a would-be id: %q", f.Detail)
		}
		// Every finding must reference only its own trusted template.
		if !strings.Contains(f.Detail, f.Route) {
			t.Errorf("detail %q should name its route template %q", f.Detail, f.Route)
		}
		if strings.ContainsAny(f.Route, "?#") || strings.Contains(f.Route, secretID) {
			t.Errorf("route field carried a non-template value: %q", f.Route)
		}
	}
}

func TestAnalyzeIsDeterministic(t *testing.T) {
	build := func() *sandbox.CallTrace {
		rows := fanoutRows("/items/*", 40, time.Millisecond)
		for i := 0; i < 5; i++ {
			rows = append(rows, sandbox.CallRow{Method: "GET", Route: "/v1/config", Status: 200, Delivered: true, RespBytes: 7, Latency: time.Millisecond})
		}
		return trace(rows...)
	}
	a := Analyze(build(), nil)
	b := Analyze(build(), nil)
	if len(a) != len(b) {
		t.Fatalf("nondeterministic finding count: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].Pattern != b[i].Pattern || a[i].Route != b[i].Route || a[i].Detail != b[i].Detail {
			t.Errorf("finding %d differs between runs: %+v vs %+v", i, a[i], b[i])
		}
	}
}

func severityOf(fs []Finding, p PatternID) Severity {
	f, ok := find(fs, p)
	if !ok {
		return SeverityInfo
	}
	return f.Severity
}
