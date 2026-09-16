package insights

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// Detector thresholds. They are deliberately modest so a genuinely wasteful pattern
// trips them while an ordinary handful of calls does not; the per-run trace is
// already bounded by the broker's call budget, so these only classify, never gate.
// Both count SUCCESSFUL calls only (see succeeded).
const (
	fanOutMinCalls = 6 // successful per-item calls to one wildcard route before it is fan-out
	repeatMinCalls = 4 // successful same-size reads of one fixed route before reuse is worth suggesting
)

// Analyze runs the deterministic detectors over a bounded, metadata-only CallTrace
// and returns findings sorted most-severe first (then by pattern, then route) so the
// output is stable across runs. It never mutates the trace and reads only the
// metadata the broker already recorded, so hostile guest code cannot steer it beyond
// that metadata.
//
// Each finding stands on its own (method, route) group of successful calls, so two
// findings never describe the same rows and their costs sum without double counting.
// Calls that did not succeed are named in a finding's sentence and never counted; a
// trace that hit its row cap is reported with "at least".
//
// allow, when non-nil, lets the router annotate a GET fan-out finding with the
// collection route the profile already exposes; pass nil to skip route suggestion. A
// nil or empty trace yields no findings.
func Analyze(trace *sandbox.CallTrace, allow []sandbox.HostRoute) []Finding {
	return AnalyzeWithCatalog(trace, allow, nil)
}

// AnalyzeWithCatalog is Analyze plus a catalog of every route the host API exposes (for
// plimsoll, generated from its OpenAPI spec by plimsoll-specgen). When a read fan-out's
// collection route is NOT granted but the catalog shows the API offers it, the finding
// is annotated with CatalogMatch — an operator action ("grant this route to enable the
// batch") that never reaches the caller. The caller-facing Suggested split (a granted
// sibling) is unchanged: a granted route always wins over a merely-cataloged one. Pass a
// nil catalog to skip this; the result is then identical to Analyze.
func AnalyzeWithCatalog(trace *sandbox.CallTrace, allow, catalog []sandbox.HostRoute) []Finding {
	if trace == nil || len(trace.Calls) == 0 {
		return nil
	}
	groups := sortedGroups(trace.Calls)
	partial := trace.Dropped > 0

	var findings []Finding
	findings = append(findings, detectFanOut(groups, partial)...)
	findings = append(findings, detectRepeatedReads(groups, partial)...)
	for i := range findings {
		annotateRoute(&findings[i], allow, catalog)
	}
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return findings[i].Severity > findings[j].Severity
		}
		if findings[i].Pattern != findings[j].Pattern {
			return findings[i].Pattern < findings[j].Pattern
		}
		return findings[i].Route < findings[j].Route
	})
	return findings
}

// succeeded reports whether the guest actually got a successful answer to a recorded
// call: the broker delivered the upstream response (rather than substituting its own
// error for an unanswered, oversized, or unreadable one) AND that response was 2xx.
// A delivered 4xx/5xx is a failed call; an undelivered 200 is one too, and zero
// response bytes cannot stand in for the distinction, since an empty 2xx is valid.
// Only successful calls count toward a pattern, because only they retrieved anything
// a batch or a cached copy could have replaced; a run of failures is a different
// story, and the finding sentence names them rather than inferring from them.
func succeeded(c sandbox.CallRow) bool {
	return c.Delivered && c.Status >= 200 && c.Status < 300
}

// sizeStat aggregates the successful calls in one group that share a response size.
// The repeated-read detector reads an unchanged size across reads of one fixed route
// as evidence (not proof) that the data did not change between them.
type sizeStat struct {
	count    int
	totalLat time.Duration
	bytes    int
}

// group aggregates a run's calls sharing (method, route template). Every number
// except failed is over successful calls only.
type group struct {
	method   string
	route    string
	count    int // successful calls
	failed   int // calls that did not succeed; named in the finding, never counted
	totalLat time.Duration
	maxLat   time.Duration
	bytes    int
	sizes    map[int]*sizeStat // response bytes -> stat, successful calls only
}

// sortedGroups folds the calls into per-(method,route) groups, returned in a stable
// (method, route) order so every detector and the final finding order are
// deterministic regardless of map iteration.
func sortedGroups(calls []sandbox.CallRow) []*group {
	byKey := make(map[string]*group)
	for _, c := range calls {
		key := c.Method + " " + c.Route
		g := byKey[key]
		if g == nil {
			g = &group{method: c.Method, route: c.Route, sizes: make(map[int]*sizeStat)}
			byKey[key] = g
		}
		if !succeeded(c) {
			g.failed++
			continue
		}
		g.count++
		g.totalLat += c.Latency
		if c.Latency > g.maxLat {
			g.maxLat = c.Latency
		}
		g.bytes += c.ReqBytes + c.RespBytes
		s := g.sizes[c.RespBytes]
		if s == nil {
			s = &sizeStat{}
			g.sizes[c.RespBytes] = s
		}
		s.count++
		s.totalLat += c.Latency
		s.bytes += c.ReqBytes + c.RespBytes
	}
	out := make([]*group, 0, len(byKey))
	for _, g := range byKey {
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].method != out[j].method {
			return out[i].method < out[j].method
		}
		return out[i].route < out[j].route
	})
	return out
}

// detectFanOut flags each wildcard (per-item) route hit successfully enough times
// that one request might cover them — the "512 GET /items/:id" N+1. The trace holds
// the template, not the wildcard segment, so the detector cannot say whether the
// calls named distinct items or one item repeatedly; the batch remedy covers both,
// and the detail says only what was measured and states the remedy as a condition.
func detectFanOut(groups []*group, partial bool) []Finding {
	var out []Finding
	for _, g := range groups {
		if !isWildcard(g.route) || g.count < fanOutMinCalls {
			continue
		}
		out = append(out, Finding{
			Pattern:  PatternFanOut,
			Severity: severityForCount(g.count),
			Method:   g.method,
			Route:    g.route,
			Remedy:   RemedyBatch,
			Cost: Cost{
				ExtraCalls:   g.count - 1,
				AddedLatency: g.totalLat - g.maxLat,
				BytesMoved:   g.bytes,
			},
			Detail: fmt.Sprintf("This run made %s successful %s %s calls to one per-item route (the trace holds the template, not the item); %s%s",
				countPhrase(g.count, partial), g.method, g.route, batchClause(g.method), failedClause(g.failed)),
		})
	}
	return out
}

// batchClause states the batch remedy as a condition. For a read, a collection route
// is a plausible one-call replacement, but only if it returns the same items, which
// the trace cannot show. For a write, a collection route's semantics cannot be
// inferred from its path at all (replace the collection? create? apply to a set?), so
// the sentence promises nothing and the router (annotateRoute) never guesses one.
func batchClause(method string) string {
	if isReadMethod(method) {
		return "a collection or batch read would cover them in one request if it returns the same items."
	}
	return "only a batch endpoint the API defines with the same write semantics could cover them in one request, so no replacement route is guessed."
}

// countPhrase renders a counted number, prefixed with "at least" when the trace hit
// its row cap: the dropped calls are unknown, so the count is a floor, not a total.
func countPhrase(n int, partial bool) string {
	if partial {
		return fmt.Sprintf("at least %d", n)
	}
	return fmt.Sprintf("%d", n)
}

// failedClause names the calls to a route that did not succeed. They are reported so
// the failure telemetry is not lost, and never counted, so a run of errors cannot be
// read as records retrieved.
func failedClause(failed int) string {
	if failed == 0 {
		return ""
	}
	return fmt.Sprintf(" %d more calls to this route did not succeed and are not counted.", failed)
}

// detectRepeatedReads flags one fixed (no-wildcard) read route requested successfully
// and repeatedly with same-size responses. Only a fixed route qualifies, because only
// there does the trace establish that the calls were the same request: the broker
// admits a route without a wildcard solely for the byte-exact approved path, with no
// query, so N calls to it are N copies of one request. An unchanged response size
// across them is then evidence, not proof, that the data did not change; the trace
// holds sizes, not content, which is why severity is capped at medium and the remedy
// is stated as a condition.
//
// A wildcard route is deliberately skipped, whatever its sizes. There the same
// template covers every item, and equal sizes cannot distinguish one item fetched N
// times from N distinct items that happen to be the same size (the advisor example's
// twelve inventory rows include eight of one size). That route is fan-out's, whose
// batch remedy holds either way.
func detectRepeatedReads(groups []*group, partial bool) []Finding {
	var out []Finding
	for _, g := range groups {
		if !isReadMethod(g.method) || isWildcard(g.route) {
			continue
		}
		for _, size := range sortedSizes(g.sizes) {
			s := g.sizes[size]
			if s.count < repeatMinCalls {
				continue
			}
			sev := severityForCount(s.count)
			if sev > SeverityMedium {
				sev = SeverityMedium
			}
			out = append(out, Finding{
				Pattern:  PatternRepeatedRead,
				Severity: sev,
				Method:   g.method,
				Route:    g.route,
				Remedy:   RemedyCache,
				Cost: Cost{
					ExtraCalls: s.count - 1,
					// If cached, one call remains; saved ~ total minus one average call.
					AddedLatency: s.totalLat - s.totalLat/time.Duration(s.count),
					BytesMoved:   s.bytes,
				},
				Detail: fmt.Sprintf("This run repeated the same %s %s request %s times (the route has no wildcard segment) and every counted response was %d bytes; the trace holds sizes, not content, so equal size is evidence the data did not change, not proof, and reading once and reusing the result would remove the repeats only if the data was in fact unchanged.%s",
					g.method, g.route, countPhrase(s.count, partial), size, failedClause(g.failed)),
			})
		}
	}
	return out
}

// annotateRoute is the small router: for a GET fan-out on a trailing-wildcard per-item
// route (/items/*), it looks for the collection route (/items). If the profile's Allow
// list already grants it, that is a caller-fixable Suggested route. Otherwise, if the
// endpoint catalog shows the API exposes it (but the profile does not grant it), that is
// an operator-fixable CatalogMatch (widen the allow list). Only the trailing-wildcard
// shape is handled; anything else leaves both nil, which later phases read as "no better
// endpoint exists — the API itself needs a change."
//
// Only a read is routed. A collection GET is a plausible one-call replacement for many
// per-item GETs (the finding states the condition: it must return the same items). A
// collection PUT, POST, DELETE or PATCH has semantics its path does not reveal, and
// telling an agent to call one on the strength of a path shape would be an instruction
// to perform a write nobody verified, so a write fan-out gets neither Suggested nor
// CatalogMatch until an explicit operation relationship exists.
func annotateRoute(f *Finding, allow, catalog []sandbox.HostRoute) {
	if f.Pattern != PatternFanOut || !isReadMethod(f.Method) {
		return
	}
	collection, ok := trailingWildcardParent(f.Route)
	if !ok {
		return
	}
	// A granted sibling always wins: the agent can switch to it now.
	for _, r := range allow {
		if strings.EqualFold(r.Method, f.Method) && r.Path == collection {
			f.Suggested = &Route{Method: strings.ToUpper(r.Method), Path: r.Path}
			return
		}
	}
	// Otherwise, if the API is known to expose the collection route but it is not
	// granted, the fix is an operator action. Never surfaced to the caller (it cannot
	// call it).
	for _, r := range catalog {
		if strings.EqualFold(r.Method, f.Method) && r.Path == collection {
			f.CatalogMatch = &Route{Method: strings.ToUpper(r.Method), Path: r.Path}
			return
		}
	}
}

// severityForCount ranks a count-driven pattern: a big fan-out is high, a modest one
// is low.
func severityForCount(n int) Severity {
	switch {
	case n >= 100:
		return SeverityHigh
	case n >= 25:
		return SeverityMedium
	default:
		return SeverityLow
	}
}

// isWildcard reports whether a route template has a "*" wildcard segment (a per-item
// endpoint). Templates use whole-segment wildcards only, so a segment compare is exact.
func isWildcard(route string) bool {
	for _, seg := range strings.Split(route, "/") {
		if seg == "*" {
			return true
		}
	}
	return false
}

// trailingWildcardParent returns the collection route for a route ending in a "*"
// segment (/items/* -> /items). It reports false for a non-trailing wildcard
// (/lights/*/on) or no wildcard, since those have no simple collection sibling.
func trailingWildcardParent(route string) (string, bool) {
	segs := strings.Split(route, "/")
	if len(segs) < 2 || segs[len(segs)-1] != "*" {
		return "", false
	}
	return strings.Join(segs[:len(segs)-1], "/"), true
}

func isReadMethod(method string) bool {
	return strings.EqualFold(method, "GET")
}

// sortedSizes returns a group's response-size keys ascending, so repeated-read
// findings emit in a deterministic order.
func sortedSizes(sizes map[int]*sizeStat) []int {
	out := make([]int, 0, len(sizes))
	for k := range sizes {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}
