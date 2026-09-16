package insights

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// Prospector Phase 3: AI remediation prompts. Prompt turns a Finding plus the
// profile's declared routes into a paste-ready prompt for the customer's OWN AI to
// design the API change the finding points at. It is the API-change branch of the
// advice router: it is meant for findings the agent cannot fix by making a different
// call (Finding.Suggested nil), where the fix is a new server-side capability rather
// than a route the profile already exposes.
//
// Two decisions are explicit and load-bearing:
//
//   - plimsoll emits the prompt TEXT and never calls an LLM itself. Acting on the
//     prompt (feeding it to a model, adopting the design) is entirely the customer's
//     choice; this function is a string builder, nothing more.
//   - The prompt is grounded strictly in the metadata plimsoll holds: the finding's
//     route TEMPLATE, its HTTP verb, its counts and timings, and the profile's Allow
//     list (also templates). No request/response body, concrete id, query value, or
//     credential is reachable from here, so none can appear in the output. The same
//     redaction invariant the trace and the detectors carry holds at this boundary.
//
// ok is false only for an unrecognized remedy class, so a future pattern cannot leak
// a generic or empty prompt through a caller that forgot to switch on it.
func Prompt(f Finding, allow []sandbox.HostRoute) (string, bool) {
	spec, ok := remedyPrompts[f.Remedy]
	if !ok {
		return "", false
	}

	var b strings.Builder
	b.WriteString(promptHeader)
	b.WriteString("\n\nObserved in one run:\n  ")
	b.WriteString(f.Detail)
	b.WriteString("\n")
	if cl := costLine(f.Cost); cl != "" {
		b.WriteString(cl)
	}
	b.WriteString("\nThe API currently exposes these routes (the only routes the agent is ")
	b.WriteString("permitted to call; a \"*\" segment is a wildcard matching one path segment):\n")
	b.WriteString(routesBlock(allow, f))
	b.WriteString("\n\nTask: ")
	b.WriteString(spec.task)
	b.WriteString("\n\nOutput:\n")
	b.WriteString(spec.output)
	b.WriteString("\n\n")
	b.WriteString(promptFooter)
	return b.String(), true
}

const promptHeader = "You are an API designer. An AI agent used the API below and hit an " +
	"efficiency problem that the API's current shape forces on every caller. Propose the " +
	"smallest API change that removes it."

const promptFooter = "Constraints: design only from the route shapes listed above. Do not " +
	"invent fields, resources, or identifiers those routes do not imply. Where a route shows " +
	"a \"*\" wildcard, treat it as an opaque per-item key and name the real parameter in your " +
	"design."

// promptSpec is the remedy-specific body of a prompt: the design task and the output
// format asked of the customer's AI. Everything else (the observed pattern, the cost,
// the declared routes, the grounding constraint) is common across remedy classes.
type promptSpec struct {
	task   string
	output string
}

// openAPIOutput is the output contract for the endpoint-design remedies. It asks for
// a shape, not example values, so the customer's AI cannot be steered into echoing a
// concrete payload back into the design.
const openAPIOutput = "  1. An OpenAPI 3.1 operation stub for the new endpoint: path, method, parameters, and responses.\n" +
	"  2. The request and response JSON schema (field names and types only; no example values).\n" +
	"  3. A one-paragraph rationale explaining how it removes the waste observed above."

// cacheOutput is the output contract for the cache remedy, whose fix is response
// headers and conditional-request behavior rather than a new operation.
const cacheOutput = "  1. The exact HTTP response headers to add (Cache-Control with a recommended max-age, and an ETag).\n" +
	"  2. The conditional-request behavior to honor (If-None-Match returning 304 Not Modified when unchanged).\n" +
	"  3. A one-paragraph rationale explaining how it removes the repeated reads observed above."

// remedyPrompts holds one template per RemedyClass, matching the detector vocabulary
// in finding.go. Every task string is a fixed, trusted sentence: it interpolates
// nothing from the trace, so it cannot carry guest-controlled text.
var remedyPrompts = map[RemedyClass]promptSpec{
	RemedyBatch: {
		task: "Design a single batch endpoint that accepts a set of item keys (or a query that " +
			"selects them) and returns all matching items in one response, so the many per-item " +
			"round trips collapse into one request.",
		output: openAPIOutput,
	},
	RemedyAggregate: {
		task: "Design a single endpoint that computes, server-side, the aggregate the client " +
			"currently derives in code (for example a sum, count, min/max, or group-by over the " +
			"collection) and returns the result directly, so the client no longer fetches every " +
			"row to reduce it locally.",
		output: openAPIOutput,
	},
	RemedyFilter: {
		task: "Design a filter or selection parameter on the collection endpoint so the client " +
			"can request only the subset it needs, instead of fetching the full collection and " +
			"filtering in code.",
		output: openAPIOutput,
	},
	RemedyCache: {
		task: "Add HTTP caching to this read so repeated identical requests need not re-fetch " +
			"unchanged data: choose a Cache-Control policy and add ETag / If-None-Match " +
			"conditional-request support.",
		output: cacheOutput,
	},
	RemedyParallel: {
		task: "Design a compound endpoint that returns, in one response, the several independent " +
			"resources the client currently fetches across separate routes, so the round trips it " +
			"waits on serially collapse into one request.",
		output: openAPIOutput,
	},
}

// costLine renders a Finding's attributed waste as one factual sentence, or "" when
// the cost carries no positive number. Only the trace's own integers and durations
// reach it, so nothing guest-controlled can appear.
func costLine(c Cost) string {
	var parts []string
	if c.ExtraCalls > 0 {
		parts = append(parts, fmt.Sprintf("%d more calls than an ideal shape needs", c.ExtraCalls))
	}
	if c.AddedLatency > 0 {
		parts = append(parts, fmt.Sprintf("about %s of extra upstream latency", c.AddedLatency.Round(time.Millisecond)))
	}
	if c.BytesMoved > 0 {
		parts = append(parts, humanBytes(c.BytesMoved)+" moved over the wire")
	}
	if len(parts) == 0 {
		return ""
	}
	return "  Cost attributed to the pattern: " + strings.Join(parts, ", ") + ".\n"
}

// routesBlock lists the declared routes the design must live alongside, deduplicated
// and sorted for a deterministic prompt. Every entry is a (method, template) pair
// from the profile's Allow list; when Prompt is called without an Allow list it falls
// back to the finding's own template so the block is never empty.
func routesBlock(allow []sandbox.HostRoute, f Finding) string {
	type route struct{ method, path string }
	seen := make(map[route]struct{})
	var routes []route
	add := func(method, path string) {
		r := route{strings.ToUpper(method), path}
		if _, dup := seen[r]; dup {
			return
		}
		seen[r] = struct{}{}
		routes = append(routes, r)
	}
	for _, r := range allow {
		add(r.Method, r.Path)
	}
	if len(routes) == 0 {
		add(f.Method, f.Route)
	}
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].method != routes[j].method {
			return routes[i].method < routes[j].method
		}
		return routes[i].path < routes[j].path
	})
	var b strings.Builder
	for i, r := range routes {
		if i > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "  - %s %s", r.method, r.path)
	}
	return b.String()
}

// humanBytes renders a byte count in the largest unit that keeps it readable. The
// input is already bounded by the broker's per-call caps.
func humanBytes(n int) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d bytes", n)
	}
}
