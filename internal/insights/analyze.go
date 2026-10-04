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

// Routes is what a profile says about the host API's routes. The router reads it to
// name a batch route for a read fan-out; the detectors never read it.
type Routes struct {
	Allow   []sandbox.HostRoute // the routes the grant allows
	Catalog []sandbox.HostRoute // every route the API exposes (a superset of Allow); optional
	// BatchOf maps a per-item route to the batch route the operator declares serves it
	// (the profile's batch_of); optional. Methods are upper case.
	BatchOf map[sandbox.HostRoute]sandbox.HostRoute
}

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
// routes lets the router annotate a read fan-out with a batch route (Suggested,
// GrantRoute or Candidate; see Finding). The zero Routes names none. A nil or empty
// trace yields no findings.
func Analyze(trace *sandbox.CallTrace, routes Routes) []Finding {
	if trace == nil || len(trace.Calls) == 0 {
		return nil
	}
	groups := sortedGroups(trace.Calls)
	partial := trace.Dropped > 0

	var findings []Finding
	findings = append(findings, detectFanOut(groups, partial)...)
	findings = append(findings, detectRepeatedReads(groups, partial)...)
	for i := range findings {
		annotateRoute(&findings[i], routes)
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
	sizes    map[int]*sizeStat // response bytes -> stat, successful calls that sent no body only
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
		if c.ReqBytes > 0 {
			// The trace holds a body's size, not its bytes, so two calls with bodies are
			// not known to be the same request; only bodiless calls feed repeated reads.
			continue
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
// and repeatedly with same-size responses. Only a fixed route qualifies, and only calls
// that sent no body, because only there does the trace establish that the calls were
// the same request: the broker admits a route without a wildcard solely for the
// byte-exact approved path, with no query, and a GET can still carry a body
// (host.call("GET", path, body)) the trace records only the size of, so N bodiless
// calls to it are N copies of one request. An unchanged response size
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

// annotateRoute is the small router. For a read fan-out it names a batch route, and
// says on what basis:
//
//   - The profile's batch_of declares one for this route: Suggested when Allow grants
//     it, GrantRoute (add it to Allow) when it does not. A declaration covers any route
//     shape, since the operator, not the path, says what serves what.
//   - Otherwise, for a trailing-wildcard route (/items/*) whose collection (/items) the
//     profile grants or its catalog lists: Candidate, for the operator to check. A path
//     says nothing about pagination, returned fields or scope, so a route found this way
//     never reaches the caller.
//
// Anything else leaves all three nil: no route is known (which is not the same as the
// API lacking one). Only a read is routed: telling an agent to call a collection write
// would be an instruction to perform a write nobody verified, and batch_of refuses one.
//
// The sentence it appends names the basis, so the operator surfaces and the caller read
// the same claim.
func annotateRoute(f *Finding, routes Routes) {
	if f.Pattern != PatternFanOut || !isReadMethod(f.Method) {
		return
	}
	if batch, ok := routes.BatchOf[sandbox.HostRoute{Method: strings.ToUpper(f.Method), Path: f.Route}]; ok {
		r := &Route{Method: strings.ToUpper(batch.Method), Path: batch.Path}
		if hasRoute(routes.Allow, batch) {
			f.Suggested = r
			f.Detail += fmt.Sprintf(" The profile declares %s %s as this route's batch form and grants it; the declaration is the operator's, and plimsoll has not checked that it returns the same items.", r.Method, r.Path)
		} else {
			f.GrantRoute = r
			f.Detail += fmt.Sprintf(" The profile declares %s %s as this route's batch form but does not grant it.", r.Method, r.Path)
		}
		return
	}
	collection, ok := trailingWildcardParent(f.Route)
	if !ok {
		return
	}
	candidate := sandbox.HostRoute{Method: strings.ToUpper(f.Method), Path: collection}
	var where string
	switch {
	case hasRoute(routes.Allow, candidate):
		where = "is granted"
	case hasRoute(routes.Catalog, candidate):
		where = "is in the API's catalog but not granted"
	default:
		return
	}
	f.Candidate = &Route{Method: candidate.Method, Path: candidate.Path}
	f.Detail += fmt.Sprintf(" %s %s %s and its path makes it this route's collection, but the profile does not declare it in batch_of, so whether it returns the same items (all pages, the same fields, the same scope) is unknown and it is not offered to the agent.", candidate.Method, candidate.Path, where)
}

// hasRoute reports whether routes holds r, the method compared without case.
func hasRoute(routes []sandbox.HostRoute, r sandbox.HostRoute) bool {
	for _, x := range routes {
		if strings.EqualFold(x.Method, r.Method) && x.Path == r.Path {
			return true
		}
	}
	return false
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
