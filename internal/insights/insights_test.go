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
	got := Analyze(tr, Routes{})

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
	if got := Analyze(trace(fanoutRows("/items/*", 30, time.Millisecond)...), Routes{}); severityOf(got, PatternFanOut) != SeverityMedium {
		t.Errorf("30 calls: fan-out severity = %s, want medium", severityOf(got, PatternFanOut))
	}
	if got := Analyze(trace(fanoutRows("/items/*", 120, time.Millisecond)...), Routes{}); severityOf(got, PatternFanOut) != SeverityHigh {
		t.Errorf("120 calls: fan-out severity = %s, want high", severityOf(got, PatternFanOut))
	}
}

func TestFanOutBelowThresholdIsClean(t *testing.T) {
	// 5 calls is under fanOutMinCalls (6): no findings at all.
	if got := Analyze(trace(fanoutRows("/items/*", 5, time.Millisecond)...), Routes{}); len(got) != 0 {
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
	if got := Analyze(trace(notFound...), Routes{Allow: allow}); len(got) != 0 {
		t.Errorf("eight 404s produced findings, want none: %+v", got)
	}

	// Eight successes plus four 500s: the fan-out counts the eight and names the four.
	mixed := fanoutRows("/items/*", 8, time.Millisecond)
	for i := 0; i < 4; i++ {
		mixed = append(mixed, sandbox.CallRow{Method: "GET", Route: "/items/*", Status: 500, Delivered: true, RespBytes: 12, Latency: time.Millisecond})
	}
	got := Analyze(trace(mixed...), Routes{Allow: allow})
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
	if got := Analyze(trace(unanswered...), Routes{}); len(got) != 0 {
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
	if got := Analyze(trace(capped...), Routes{Allow: []sandbox.HostRoute{{Method: "GET", Path: "/items"}}}); len(got) != 0 {
		t.Errorf("eight undelivered 200s produced findings, want none: %+v", got)
	}

	// Six delivered successes among six undelivered 200s: the fan-out counts six.
	mixed := fanoutRows("/items/*", 6, time.Millisecond)
	mixed = append(mixed, capped[:6]...)
	got := Analyze(trace(mixed...), Routes{})
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
	if _, ok := find(Analyze(trace(empty...), Routes{}), PatternRepeatedRead); !ok {
		t.Error("four delivered empty 2xx reads of a fixed route should still be a repeated read")
	}
}

// TestIncompleteTraceIsQualified: past the row cap the broker counts calls in Dropped
// instead of storing them, so a finding's count is a floor and its sentence says so.
func TestIncompleteTraceIsQualified(t *testing.T) {
	tr := trace(fanoutRows("/items/*", 12, time.Millisecond)...)
	tr.Dropped = 300
	f, ok := find(Analyze(tr, Routes{}), PatternFanOut)
	if !ok {
		t.Fatal("fan-out not detected on a partial trace")
	}
	if f.Cost.ExtraCalls != 11 || !strings.Contains(f.Detail, "at least 12 successful") {
		t.Errorf("partial trace: ExtraCalls=%d detail=%q, want 11 and an 'at least 12' sentence", f.Cost.ExtraCalls, f.Detail)
	}
	full, _ := find(Analyze(trace(fanoutRows("/items/*", 12, time.Millisecond)...), Routes{}), PatternFanOut)
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
	got := Analyze(trace(rows...), Routes{})

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

// TestRepeatedReadIgnoresCallsWithBodies: a GET may carry a body (host.call("GET",
// path, body)), and the trace holds its size, not its bytes, so six same-size GETs with
// bodies to one fixed route are not known to be one request repeated (a search route
// read with six different queries looks exactly like this). Only the bodiless calls
// count, and here there are too few of them.
func TestRepeatedReadIgnoresCallsWithBodies(t *testing.T) {
	var rows []sandbox.CallRow
	for i := 0; i < 6; i++ {
		rows = append(rows, sandbox.CallRow{Method: "GET", Route: "/v1/search", Status: 200, Delivered: true, ReqBytes: 24, RespBytes: 512, Latency: time.Millisecond})
	}
	if f, ok := find(Analyze(trace(rows...), Routes{}), PatternRepeatedRead); ok {
		t.Errorf("same-size GETs with bodies must not be a repeated read: %+v", f)
	}
	for i := 0; i < repeatMinCalls; i++ {
		rows = append(rows, sandbox.CallRow{Method: "GET", Route: "/v1/search", Status: 200, Delivered: true, RespBytes: 512, Latency: time.Millisecond})
	}
	f, ok := find(Analyze(trace(rows...), Routes{}), PatternRepeatedRead)
	if !ok || f.Cost.ExtraCalls != repeatMinCalls-1 {
		t.Errorf("the bodiless calls alone are the repeat: got %+v, want ExtraCalls %d", f, repeatMinCalls-1)
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
	got := Analyze(trace(rows...), Routes{})
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
	if got := severityOf(Analyze(trace(rows...), Routes{}), PatternRepeatedRead); got != SeverityMedium {
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
	if got := Analyze(trace(rows...), Routes{}); len(got) != 0 {
		t.Errorf("multi-route latency produced findings, want none: %+v", got)
	}
}

// TestRouterSuggestsOnlyADeclaredBatchRoute: a granted collection route reaches the
// caller only when the profile declares it as the per-item route's batch form. Found by
// its path alone it is an operator's candidate, since a path cannot say whether the
// route pages, returns fewer fields or covers another scope.
func TestRouterSuggestsOnlyADeclaredBatchRoute(t *testing.T) {
	allow := []sandbox.HostRoute{{Method: "GET", Path: "/items/*"}, {Method: "GET", Path: "/items"}}
	rows := fanoutRows("/items/*", 8, time.Millisecond)

	guessed, _ := find(Analyze(trace(rows...), Routes{Allow: allow}), PatternFanOut)
	if guessed.Suggested != nil || guessed.GrantRoute != nil {
		t.Errorf("an undeclared route reached the caller: Suggested=%v GrantRoute=%v", guessed.Suggested, guessed.GrantRoute)
	}
	if guessed.Candidate == nil || *guessed.Candidate != (Route{Method: "GET", Path: "/items"}) {
		t.Fatalf("Candidate = %v, want GET /items", guessed.Candidate)
	}
	if !strings.Contains(guessed.Detail, "GET /items is granted") || !strings.Contains(guessed.Detail, "does not declare it in batch_of") || !strings.Contains(guessed.Detail, "not offered to the agent") {
		t.Errorf("a candidate's sentence must say it is undeclared and withheld: %q", guessed.Detail)
	}

	declared := Routes{Allow: allow, BatchOf: map[sandbox.HostRoute]sandbox.HostRoute{
		{Method: "GET", Path: "/items/*"}: {Method: "GET", Path: "/items"},
	}}
	f, _ := find(Analyze(trace(rows...), declared), PatternFanOut)
	if f.Suggested == nil || *f.Suggested != (Route{Method: "GET", Path: "/items"}) || f.GrantRoute != nil || f.Candidate != nil {
		t.Fatalf("a declared, granted batch route: Suggested=%v GrantRoute=%v Candidate=%v, want only Suggested GET /items", f.Suggested, f.GrantRoute, f.Candidate)
	}
	if !strings.Contains(f.Detail, "declares GET /items as this route's batch form and grants it") || !strings.Contains(f.Detail, "has not checked") {
		t.Errorf("a suggestion's sentence must name the declaration as the operator's: %q", f.Detail)
	}
}

// A declared batch route the profile does not grant is the operator's one-line fix;
// the caller is never told about a route it cannot call.
func TestRouterNamesADeclaredUngrantedRouteToTheOperator(t *testing.T) {
	routes := Routes{
		Allow: []sandbox.HostRoute{{Method: "GET", Path: "/items/*"}},
		BatchOf: map[sandbox.HostRoute]sandbox.HostRoute{
			{Method: "GET", Path: "/items/*"}: {Method: "GET", Path: "/items:batchGet"},
		},
	}
	f, _ := find(Analyze(trace(fanoutRows("/items/*", 8, time.Millisecond)...), routes), PatternFanOut)
	if f.Suggested != nil || f.Candidate != nil || f.GrantRoute == nil || *f.GrantRoute != (Route{Method: "GET", Path: "/items:batchGet"}) {
		t.Fatalf("Suggested=%v GrantRoute=%v Candidate=%v, want only GrantRoute GET /items:batchGet", f.Suggested, f.GrantRoute, f.Candidate)
	}
	if !strings.Contains(f.Detail, "but does not grant it") {
		t.Errorf("detail should say the declared route is not granted: %q", f.Detail)
	}
}

// The catalog only ever yields a candidate: it lists what the API exposes, not what
// serves what.
func TestRouterTakesACandidateFromTheCatalog(t *testing.T) {
	routes := Routes{
		Allow:   []sandbox.HostRoute{{Method: "GET", Path: "/items/*"}},
		Catalog: []sandbox.HostRoute{{Method: "GET", Path: "/items/*"}, {Method: "GET", Path: "/items"}},
	}
	f, _ := find(Analyze(trace(fanoutRows("/items/*", 8, time.Millisecond)...), routes), PatternFanOut)
	if f.Suggested != nil || f.GrantRoute != nil || f.Candidate == nil || *f.Candidate != (Route{Method: "GET", Path: "/items"}) {
		t.Fatalf("Suggested=%v GrantRoute=%v Candidate=%v, want only Candidate GET /items", f.Suggested, f.GrantRoute, f.Candidate)
	}
	if !strings.Contains(f.Detail, "is in the API's catalog but not granted") {
		t.Errorf("detail should say where the candidate came from: %q", f.Detail)
	}

	// Nothing granted, catalogued or declared: no route is known.
	n, _ := find(Analyze(trace(fanoutRows("/items/*", 8, time.Millisecond)...), Routes{Allow: routes.Allow}), PatternFanOut)
	if n.Suggested != nil || n.GrantRoute != nil || n.Candidate != nil {
		t.Errorf("with no route known all must be nil: %v / %v / %v", n.Suggested, n.GrantRoute, n.Candidate)
	}
}

func TestRouterIgnoresNonTrailingWildcard(t *testing.T) {
	// /v1/lights/*/state has a middle wildcard: its path suggests no collection, so even
	// with a plausible Allow list the router names nothing (GET, so the verb rule below
	// is not what stops it). A declaration covers it, since it does not rest on the path.
	allow := []sandbox.HostRoute{{Method: "GET", Path: "/v1/lights/*/state"}, {Method: "GET", Path: "/v1/lights"}}
	rows := make([]sandbox.CallRow, 8)
	for i := range rows {
		rows[i] = sandbox.CallRow{Method: "GET", Route: "/v1/lights/*/state", Status: 200, Delivered: true, RespBytes: i, Latency: time.Millisecond}
	}
	f, ok := find(Analyze(trace(rows...), Routes{Allow: allow}), PatternFanOut)
	if !ok {
		t.Fatal("fan-out on a middle-wildcard route should still fire")
	}
	if f.Suggested != nil || f.Candidate != nil {
		t.Errorf("non-trailing wildcard must not get a route from its path: Suggested=%v Candidate=%v", f.Suggested, f.Candidate)
	}
	declared := Routes{Allow: allow, BatchOf: map[sandbox.HostRoute]sandbox.HostRoute{
		{Method: "GET", Path: "/v1/lights/*/state"}: {Method: "GET", Path: "/v1/lights"},
	}}
	if g, _ := find(Analyze(trace(rows...), declared), PatternFanOut); g.Suggested == nil || g.Suggested.Path != "/v1/lights" {
		t.Errorf("a declared batch route for a middle-wildcard route should be suggested, got %v", g.Suggested)
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
	// An embedder can hand Analyze a write relation directly (grants.Load refuses one);
	// the router still names nothing for a write.
	batchOf := map[sandbox.HostRoute]sandbox.HostRoute{{Method: "PUT", Path: "/items/*"}: {Method: "PUT", Path: "/items"}}
	f, ok := find(Analyze(trace(rows...), Routes{Allow: allow, Catalog: catalog, BatchOf: batchOf}), PatternFanOut)
	if !ok {
		t.Fatal("fan-out on a PUT per-item route should still fire")
	}
	if f.Suggested != nil || f.GrantRoute != nil || f.Candidate != nil {
		t.Errorf("a write fan-out must get no replacement route: Suggested=%v GrantRoute=%v Candidate=%v", f.Suggested, f.GrantRoute, f.Candidate)
	}
	if !strings.Contains(f.Detail, "no replacement route is guessed") {
		t.Errorf("write fan-out detail should say why nothing is suggested: %q", f.Detail)
	}
}

func TestNilAndEmptyTrace(t *testing.T) {
	if got := Analyze(nil, Routes{}); got != nil {
		t.Errorf("nil trace = %+v, want nil", got)
	}
	if got := Analyze(&sandbox.CallTrace{}, Routes{}); got != nil {
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
	got := Analyze(trace(rows...), Routes{})
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
	got := Analyze(trace(rows...), Routes{Allow: []sandbox.HostRoute{{Method: "GET", Path: "/items"}}})
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
	a := Analyze(build(), Routes{})
	b := Analyze(build(), Routes{})
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
