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
const (
	fanOutMinCalls    = 6 // per-item calls to one wildcard route before it is fan-out
	aggregateMinReads = 6 // reads in a write-free run before it looks like a client-side reduce
	repeatMinCalls    = 4 // identical-shape reads before caching is worth suggesting
	seqMinCalls       = 4 // calls before the sequential heuristic considers a run
)

// seqMinTotalLatency is the summed upstream latency a multi-route run must exceed
// before the (low-confidence) sequential detector fires.
const seqMinTotalLatency = 500 * time.Millisecond

// Analyze runs the deterministic detectors over a bounded, metadata-only CallTrace
// and returns findings sorted most-severe first (then by pattern, then route) so the
// output is stable across runs. It never mutates the trace and reads only the
// metadata the broker already recorded, so hostile guest code cannot steer it beyond
// that metadata.
//
// allow, when non-nil, lets the router annotate a fan-out finding with a batch route
// the profile already exposes; pass nil to skip route suggestion. A nil or empty
// trace yields no findings.
func Analyze(trace *sandbox.CallTrace, allow []sandbox.HostRoute) []Finding {
	return AnalyzeWithCatalog(trace, allow, nil)
}

// AnalyzeWithCatalog is Analyze plus a catalog of every route the host API exposes (for
// plimsoll, generated from its OpenAPI spec by plimsoll-specgen). When a fan-out's
// batch route is NOT granted but the catalog shows the API offers it, the finding is
// annotated with CatalogMatch — an operator action ("grant this route to enable the
// batch") that never reaches the caller. The caller-facing Suggested split (a granted
// sibling) is unchanged: a granted route always wins over a merely-cataloged one. Pass a
// nil catalog to skip this; the result is then identical to Analyze.
func AnalyzeWithCatalog(trace *sandbox.CallTrace, allow, catalog []sandbox.HostRoute) []Finding {
	if trace == nil || len(trace.Calls) == 0 {
		return nil
	}
	groups := sortedGroups(trace.Calls)

	var findings []Finding
	findings = append(findings, detectFanOut(groups)...)
	if f, ok := detectAggregateInCode(trace.Calls, groups); ok {
		findings = append(findings, f)
	}
	findings = append(findings, detectRepeatedReads(groups)...)
	if f, ok := detectSequential(trace.Calls); ok {
		findings = append(findings, f)
	}
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

// sizeStat aggregates the calls in one group that share a response size (the
// arg-shape proxy for the repeated-read heuristic).
type sizeStat struct {
	count    int
	totalLat time.Duration
	bytes    int
}

// group aggregates a run's calls sharing (method, route template).
type group struct {
	method   string
	route    string
	count    int
	totalLat time.Duration
	maxLat   time.Duration
	bytes    int
	lastSeq  int
	sizes    map[int]*sizeStat // response bytes -> stat
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
		g.count++
		g.totalLat += c.Latency
		if c.Latency > g.maxLat {
			g.maxLat = c.Latency
		}
		g.bytes += c.ReqBytes + c.RespBytes
		if c.Seq > g.lastSeq {
			g.lastSeq = c.Seq
		}
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

// detectFanOut flags each wildcard (per-item) route hit enough times that one batch
// request would cover them — the "512 GET /items/:id" N+1.
func detectFanOut(groups []*group) []Finding {
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
			Detail: fmt.Sprintf("This run made %d %s %s calls that differ only by the wildcard segment; a batch endpoint would collapse them into one request.",
				g.count, g.method, g.route),
		})
	}
	return out
}

// detectAggregateInCode flags a read-heavy run with no write after its last read: the
// client pulled distinct rows (a wildcard per-item route dominates the reads) and
// reduced them in code, where a server-side aggregate would return the result in one
// call. Requiring a wildcard dominant route keeps this off repeated reads of one
// fixed collection (that is the repeated-read pattern instead).
func detectAggregateInCode(calls []sandbox.CallRow, groups []*group) (Finding, bool) {
	var reads int
	var readLat, maxReadLat time.Duration
	var readBytes int
	lastReadSeq := 0
	var dominant *group
	for _, g := range groups {
		if !isReadMethod(g.method) {
			continue
		}
		reads += g.count
		readLat += g.totalLat
		readBytes += g.bytes
		if g.maxLat > maxReadLat {
			maxReadLat = g.maxLat
		}
		if g.lastSeq > lastReadSeq {
			lastReadSeq = g.lastSeq
		}
		if dominant == nil || g.count > dominant.count {
			dominant = g // groups are (method,route)-sorted, so ties resolve stably
		}
	}
	if reads < aggregateMinReads || dominant == nil || !isWildcard(dominant.route) {
		return Finding{}, false
	}
	// A write after the final read means the run was read-modify-write, not a pure
	// reduce; only a write-free tail is aggregate-in-code.
	for _, c := range calls {
		if !isReadMethod(c.Method) && c.Seq > lastReadSeq {
			return Finding{}, false
		}
	}
	return Finding{
		Pattern:  PatternAggregateInCode,
		Severity: severityForCount(reads),
		Method:   dominant.method,
		Route:    dominant.route,
		Remedy:   RemedyAggregate,
		Cost: Cost{
			ExtraCalls:   reads - 1,
			AddedLatency: readLat - maxReadLat,
			BytesMoved:   readBytes,
		},
		Detail: fmt.Sprintf("This run made %d read calls (mostly %s %s) with no writes, then reduced the rows in code; a server-side aggregate endpoint would return the result in one call.",
			reads, dominant.method, dominant.route),
	}, true
}

// detectRepeatedReads flags the same read repeated with an identical response shape.
// The trace holds no id, so an identical response SIZE within one (method,route)
// group is the arg-shape proxy — a heuristic, so severity is capped at medium.
func detectRepeatedReads(groups []*group) []Finding {
	var out []Finding
	for _, g := range groups {
		if !isReadMethod(g.method) {
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
				Detail: fmt.Sprintf("This run made %d %s %s calls returning an identical %d-byte response; caching the first result would remove the repeats.",
					s.count, g.method, g.route, size),
			})
		}
	}
	return out
}

// detectSequential is the low-confidence heuristic: a run whose summed upstream
// latency spans several routes and is large. The trace cannot prove the calls were
// serialized or independent, so severity is fixed at low and the detail is hedged.
// The remedy is only actionable where the guest can issue calls concurrently: the
// Docker and E2B clients can, while the WASM client wraps a synchronous host call,
// so under that provider the calls were serialized by construction. The finding
// never reaches a caller (it has no Suggested route); an operator reading it should
// know which provider produced it.
func detectSequential(calls []sandbox.CallRow) (Finding, bool) {
	if len(calls) < seqMinCalls {
		return Finding{}, false
	}
	var total time.Duration
	var bytes int
	routes := make(map[string]struct{})
	var slowest sandbox.CallRow
	for _, c := range calls {
		total += c.Latency
		bytes += c.ReqBytes + c.RespBytes
		routes[c.Method+" "+c.Route] = struct{}{}
		if c.Latency > slowest.Latency {
			slowest = c
		}
	}
	if total < seqMinTotalLatency || len(routes) < 2 {
		return Finding{}, false
	}
	return Finding{
		Pattern:  PatternSequential,
		Severity: SeverityLow,
		Method:   slowest.Method,
		Route:    slowest.Route,
		Remedy:   RemedyParallel,
		Cost: Cost{
			ExtraCalls:   0,
			AddedLatency: total - slowest.Latency, // fully parallel, wall time ~ slowest call
			BytesMoved:   bytes,
		},
		Detail: fmt.Sprintf("This run's %d host calls across %d routes spent %s in aggregate upstream latency; if they have no data dependency, issuing them concurrently could cut the wait to about %s.",
			len(calls), len(routes), total.Round(time.Millisecond), slowest.Latency.Round(time.Millisecond)),
	}, true
}

// annotateRoute is the small router: for a fan-out on a trailing-wildcard per-item
// route (/items/*), it looks for the collection route (/items). If the profile's Allow
// list already grants it, that is a caller-fixable Suggested route. Otherwise, if the
// endpoint catalog shows the API exposes it (but the profile does not grant it), that is
// an operator-fixable CatalogMatch (widen the allow list). Only the trailing-wildcard
// shape is handled; anything else leaves both nil, which later phases read as "no better
// endpoint exists — the API itself needs a change."
func annotateRoute(f *Finding, allow, catalog []sandbox.HostRoute) {
	if f.Pattern != PatternFanOut {
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
	// Otherwise, if the API is known to expose the batch route but it is not granted, the
	// fix is an operator action. Never surfaced to the caller (it cannot call it).
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
