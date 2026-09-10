// Package specgen derives a plimsoll host-API grant description from an OpenAPI
// 3.x document. It is the Sluice "spec-import" path: today an operator hand-writes
// three things that must stay in sync — the grant's `allow` route list, the typed
// JS `preamble` SDK, and the model-facing tool description a gateway shows the agent.
// specgen emits all three from the ONE spec, plus an optional `health_check`
// backpressure probe when the spec designates a concrete health/readiness/capacity
// GET. A consumer can delete the hand-maintained copies and let drift become impossible
// (see the worked example in docs/examples/specgen).
//
// It is metadata-only and offline: it reads the spec's paths, methods, operationIds,
// path parameters, and summaries, and emits text. It never fetches the spec's server,
// never embeds a credential, and produces byte-identical output for a given input, so
// generation can run in a build step and the artifacts can be committed and diffed.
package specgen

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// Options configures generation.
type Options struct {
	// Global is the JS global the generic host client is exposed as (the grant's
	// Global; the typed SDK attaches its named methods to it). Defaults to "host".
	Global string
}

// Operation is one generated method: an OpenAPI operation reduced to what the three
// artifacts need. Everything here is trusted spec metadata, never request content.
type Operation struct {
	ID      string   // operationId -> the JS method name
	Method  string   // GET, PUT, POST, DELETE, PATCH
	Path    string   // the spec path template, e.g. /lights/{id}
	Route   string   // the allowlist template, e.g. /lights/* (path params -> "*")
	Params  []string // path parameter names, in path order -> the JS method args
	HasBody bool     // the operation declares a requestBody (adds a trailing body arg)
	Summary string   // the operation summary, for the model-facing description
}

// SkippedOp records an operation the generator could not represent as a grant, so the
// omission is reported rather than silent. The cause is a verb the host-API broker does
// not enforce: it allows GET/PUT/POST/DELETE/PATCH, so a spec's HEAD/OPTIONS/TRACE
// operation is reported here instead of emitted as an allow route the validator rejects.
type SkippedOp struct {
	Method string
	Path   string
	Reason string
}

// Result is the generated grant description: the core artifacts, optional health probe,
// and the parsed operations they were built from.
type Result struct {
	Title       string
	Version     string
	Global      string
	Allow       []sandbox.HostRoute // deduped, sorted; the grant's allow list
	Operations  []Operation         // sorted by (path, method)
	Skipped     []SkippedOp         // operations dropped as unrepresentable (with reason)
	Preamble    string              // typed JS SDK; goes in HostAPIGrant.Preamble
	Description string              // model-facing text a gateway shows the agent
	// HealthCheck, when non-empty, is the "GET /path" line for the grant profile's
	// health_check backpressure probe, derived from the spec: the operation explicitly
	// marked x-plimsoll-health-check, or (failing that) the single best-ranked
	// well-known health/readiness/capacity endpoint. Empty when the spec declares none,
	// or when several equally-ranked candidates made the choice ambiguous (see HealthNote).
	HealthCheck string
	// HealthNote explains a non-fatal ambiguity: candidate health routes were found but
	// none could be auto-selected, so the operator must disambiguate. Empty otherwise.
	HealthNote string
}

// AllowStrings renders Allow as the "METHOD /path" lines a grants profile's `allow`
// array expects, in the same deduped/sorted order.
func (r *Result) AllowStrings() []string {
	out := make([]string, 0, len(r.Allow))
	for _, a := range r.Allow {
		out = append(out, a.Method+" "+a.Path)
	}
	return out
}

// --- minimal OpenAPI 3.x subset (JSON) ---
//
// Only the fields the three artifacts need. Unknown fields are ignored, so a real
// spec parses fine; a $ref inside these fields is not followed (requestBody presence
// is all we read from it, and path params are taken from the path template itself).

type oaDoc struct {
	OpenAPI string                `json:"openapi"`
	Info    oaInfo                `json:"info"`
	Paths   map[string]oaPathItem `json:"paths"`
}

type oaInfo struct {
	Title   string `json:"title"`
	Version string `json:"version"`
}

type oaPathItem struct {
	Get     *oaOperation `json:"get"`
	Put     *oaOperation `json:"put"`
	Post    *oaOperation `json:"post"`
	Delete  *oaOperation `json:"delete"`
	Patch   *oaOperation `json:"patch"`
	Head    *oaOperation `json:"head"`
	Options *oaOperation `json:"options"`
	Trace   *oaOperation `json:"trace"`
}

type oaOperation struct {
	OperationID string          `json:"operationId"`
	Summary     string          `json:"summary"`
	RequestBody json.RawMessage `json:"requestBody"`
	// HealthCheck is the `x-plimsoll-health-check` OpenAPI extension: an explicit
	// operator marker designating THIS operation as the grant's backpressure health
	// probe. It overrides the endpoint-name heuristic and must resolve to a concrete GET.
	HealthCheck *bool `json:"x-plimsoll-health-check"`
}

// healthCand is one heuristic health-route candidate: a concrete GET whose last path
// segment is a well-known health/readiness/capacity name, tagged with its priority rank.
type healthCand struct {
	rank int
	line string // "GET /path"
}

// healthSegmentRanks lists well-known health-endpoint path segments in DESCENDING
// priority for the backpressure RECOVERY probe. The probe answers "is the upstream ready
// to take traffic again," so a capacity/readiness signal outranks a bare liveness or
// ping (a process can be live but still shedding). Matched case-insensitively against the
// last segment of a concrete GET route, so /capacity, /v1/status and /-/healthz all
// qualify but /lights/{id} never can. An explicit x-plimsoll-health-check marker
// bypasses this list entirely.
var healthSegmentRanks = [][]string{
	{"capacity", "headroom", "status"},
	{"ready", "readyz", "readiness"},
	{"health", "healthz", "healthcheck"},
	{"live", "livez", "liveness", "ping", "heartbeat"},
}

// healthRank returns the priority rank of a path segment among the well-known health
// names, or (-1,false) if it is not one.
func healthRank(seg string) (int, bool) {
	seg = strings.ToLower(seg)
	for i, names := range healthSegmentRanks {
		for _, n := range names {
			if seg == n {
				return i, true
			}
		}
	}
	return -1, false
}

// lastSegment returns the final non-empty path segment (trailing slash ignored).
func lastSegment(path string) string {
	segs := strings.Split(strings.TrimSuffix(path, "/"), "/")
	return segs[len(segs)-1]
}

// pickHealthByRank chooses the single best-ranked heuristic candidate. It returns the
// route when exactly one candidate holds the top priority, or a note (and no route) when
// several tie there — never a guess. Fail-soft: health_check is optional, so an ambiguous
// heuristic is a note the operator can act on, not a generation error (an explicit marker
// is the fail-closed override for that case).
func pickHealthByRank(cands []healthCand) (route, note string) {
	if len(cands) == 0 {
		return "", ""
	}
	minRank := cands[0].rank
	for _, c := range cands {
		if c.rank < minRank {
			minRank = c.rank
		}
	}
	var best []string
	for _, c := range cands {
		if c.rank == minRank {
			best = append(best, c.line)
		}
	}
	sort.Strings(best)
	if len(best) == 1 {
		return best[0], ""
	}
	return "", fmt.Sprintf("%d candidate health routes share the top priority (%s); none auto-selected — mark one with the x-plimsoll-health-check OpenAPI extension, or set the profile's health_check by hand", len(best), strings.Join(best, ", "))
}

// methodOrder fixes iteration and output order so generation is deterministic. Only
// the five verbs the host-API broker enforces are `supported`; HEAD/OPTIONS/TRACE are
// parsed so they can be reported as skipped rather than silently ignored.
var methodOrder = []struct {
	name      string
	supported bool
	get       func(oaPathItem) *oaOperation
}{
	{"GET", true, func(p oaPathItem) *oaOperation { return p.Get }},
	{"PUT", true, func(p oaPathItem) *oaOperation { return p.Put }},
	{"POST", true, func(p oaPathItem) *oaOperation { return p.Post }},
	{"DELETE", true, func(p oaPathItem) *oaOperation { return p.Delete }},
	{"PATCH", true, func(p oaPathItem) *oaOperation { return p.Patch }},
	{"HEAD", false, func(p oaPathItem) *oaOperation { return p.Head }},
	{"OPTIONS", false, func(p oaPathItem) *oaOperation { return p.Options }},
	{"TRACE", false, func(p oaPathItem) *oaOperation { return p.Trace }},
}

// Generate parses an OpenAPI 3.x JSON document and returns the derived grant artifacts.
// It fails closed: a spec that would produce an ambiguous or unsafe surface (a path
// param that is not a whole segment, a missing operationId, a duplicate JS method
// name) is an error, not a silently degraded grant.
func Generate(spec []byte, opts Options) (*Result, error) {
	global := opts.Global
	if global == "" {
		global = "host"
	}

	var doc oaDoc
	if err := json.Unmarshal(spec, &doc); err != nil {
		return nil, fmt.Errorf("specgen: invalid JSON: %w", err)
	}
	if !strings.HasPrefix(doc.OpenAPI, "3.") {
		return nil, fmt.Errorf("specgen: unsupported openapi version %q (need 3.x)", doc.OpenAPI)
	}
	if len(doc.Paths) == 0 {
		return nil, fmt.Errorf("specgen: spec declares no paths")
	}

	paths := make([]string, 0, len(doc.Paths))
	for p := range doc.Paths {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	var ops []Operation
	var skipped []SkippedOp
	seenMethod := map[string]bool{}   // JS method-name collision guard
	routeSet := map[string]struct{}{} // dedupe method+route
	var allow []sandbox.HostRoute
	var explicitHealth []string  // ops marked x-plimsoll-health-check ("GET /path")
	var healthCands []healthCand // heuristic candidates (concrete GET on a health-named segment)

	for _, path := range paths {
		item := doc.Paths[path]
		route, params, err := deriveRoute(path)
		if err != nil {
			return nil, err
		}
		for _, m := range methodOrder {
			op := m.get(item)
			if op == nil {
				continue
			}
			// An explicit health-check marker is checked before the verb-support gate so a
			// marker on an unenforceable verb (HEAD/OPTIONS/TRACE) fails closed too: the
			// backpressure probe MUST be a concrete GET, so anything else is operator error.
			if op.HealthCheck != nil && *op.HealthCheck {
				if m.name != "GET" {
					return nil, fmt.Errorf("specgen: %s %s is marked x-plimsoll-health-check, but a health_check probe must be GET", m.name, path)
				}
				if len(params) != 0 {
					return nil, fmt.Errorf("specgen: GET %s is marked x-plimsoll-health-check, but a health_check must be a concrete path (no path parameters)", path)
				}
				explicitHealth = append(explicitHealth, "GET "+path)
			}
			if !m.supported {
				// Represent nothing we can't enforce: emitting a HEAD/OPTIONS/TRACE allow
				// entry would be rejected by the grant validator, and a client method for it
				// could never succeed. Report it instead of dropping it silently.
				skipped = append(skipped, SkippedOp{Method: m.name, Path: path, Reason: "host-API grants enforce only GET/PUT/POST/DELETE/PATCH"})
				continue
			}
			if op.OperationID == "" {
				return nil, fmt.Errorf("specgen: %s %s has no operationId (needed for a stable method name)", m.name, path)
			}
			name := jsIdent(op.OperationID)
			if seenMethod[name] {
				return nil, fmt.Errorf("specgen: operationId %q collides with another method name %q", op.OperationID, name)
			}
			seenMethod[name] = true

			ops = append(ops, Operation{
				ID:      name,
				Method:  m.name,
				Path:    path,
				Route:   route,
				Params:  params,
				HasBody: len(op.RequestBody) > 0 && bodyAllowed(m.name),
				Summary: strings.TrimSpace(op.Summary),
			})
			key := m.name + " " + route
			if _, ok := routeSet[key]; !ok {
				routeSet[key] = struct{}{}
				allow = append(allow, sandbox.HostRoute{Method: m.name, Path: route})
			}
			// A concrete GET (no path params) on a well-known health-named segment is a
			// heuristic candidate for the backpressure probe. Concreteness is required: the
			// health_check must be a literal path the broker can call without an argument.
			if m.name == "GET" && len(params) == 0 {
				if rank, ok := healthRank(lastSegment(path)); ok {
					healthCands = append(healthCands, healthCand{rank: rank, line: "GET " + path})
				}
			}
		}
	}
	if len(ops) == 0 {
		return nil, fmt.Errorf("specgen: spec declares paths but no supported operations (GET/PUT/POST/DELETE/PATCH)")
	}

	sort.Slice(allow, func(i, j int) bool {
		if allow[i].Path != allow[j].Path {
			return allow[i].Path < allow[j].Path
		}
		return allow[i].Method < allow[j].Method
	})

	// Resolve the backpressure health route: an explicit marker wins (and more than one
	// is fail-closed operator error); otherwise the best-ranked well-known endpoint, or a
	// soft note when candidates tie.
	var health, healthNote string
	switch len(explicitHealth) {
	case 0:
		health, healthNote = pickHealthByRank(healthCands)
	case 1:
		health = explicitHealth[0]
	default:
		sort.Strings(explicitHealth)
		return nil, fmt.Errorf("specgen: %d operations are marked x-plimsoll-health-check (%s); a run has a single health probe, so mark exactly one", len(explicitHealth), strings.Join(explicitHealth, ", "))
	}

	r := &Result{
		Title:       strings.TrimSpace(doc.Info.Title),
		Version:     strings.TrimSpace(doc.Info.Version),
		Global:      global,
		Allow:       allow,
		Operations:  ops,
		Skipped:     skipped,
		HealthCheck: health,
		HealthNote:  healthNote,
	}
	r.Preamble = buildPreamble(r)
	r.Description = buildDescription(r)
	return r, nil
}

// bodyAllowed reports whether a body arg makes sense for the verb. The generic client
// sends a body on PUT/POST/PATCH; GET/DELETE bodies are dropped.
func bodyAllowed(method string) bool {
	switch method {
	case "PUT", "POST", "PATCH":
		return true
	default:
		return false
	}
}

// deriveRoute turns a spec path template into an allowlist template and the ordered
// list of path parameter names. Each "{param}" MUST be a whole path segment, so it
// maps cleanly to the broker's segment-wise "*" wildcard; a param that is only part
// of a segment (e.g. "/files/{name}.json") is rejected rather than over-permitted.
func deriveRoute(path string) (route string, params []string, err error) {
	if !strings.HasPrefix(path, "/") {
		return "", nil, fmt.Errorf("specgen: path %q must start with /", path)
	}
	segs := strings.Split(path, "/")
	for i, s := range segs {
		if i == 0 {
			continue // leading empty segment before the first /
		}
		open := strings.Contains(s, "{")
		close := strings.Contains(s, "}")
		if !open && !close {
			continue // literal segment
		}
		if !(strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") && strings.Count(s, "{") == 1 && strings.Count(s, "}") == 1) {
			return "", nil, fmt.Errorf("specgen: path %q: parameter must be a whole segment (got %q); mixed literal+param segments are not supported", path, s)
		}
		name := s[1 : len(s)-1]
		if name == "" {
			return "", nil, fmt.Errorf("specgen: path %q has an empty {} parameter", path)
		}
		params = append(params, name)
		segs[i] = "*"
	}
	return strings.Join(segs, "/"), params, nil
}

// jsIdent sanitizes an identifier so it is a safe JS property/argument name: any char
// outside [A-Za-z0-9_$] becomes "_", and a leading digit is prefixed with "_".
func jsIdent(s string) string {
	if s == "" {
		return "_"
	}
	var b strings.Builder
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '_', r == '$':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			if i == 0 {
				b.WriteByte('_')
			}
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// pathExpr builds the JS expression that reconstructs the concrete request path from
// the operation's path-parameter arguments, e.g. `"/lights/" + id + "/state"`. It
// interpolates params raw (no encodeURIComponent): the injected client rejects any
// percent-encoding or "/" that would break out of the allow-listed template, so a
// hostile argument fails the client gate (and the authoritative broker) rather than
// smuggling a different route.
func pathExpr(op Operation) string {
	// Split the path template on {param} tokens into alternating literal / param pieces.
	var pieces []string
	rest := op.Path
	pi := 0
	for {
		open := strings.IndexByte(rest, '{')
		if open < 0 {
			if rest != "" {
				pieces = append(pieces, jsString(rest))
			}
			break
		}
		if open > 0 {
			pieces = append(pieces, jsString(rest[:open]))
		}
		closeIdx := strings.IndexByte(rest, '}')
		// deriveRoute already validated whole-segment params, so a '{' has a matching '}'.
		pieces = append(pieces, op.Params[pi])
		pi++
		rest = rest[closeIdx+1:]
	}
	if len(pieces) == 0 {
		return jsString(op.Path)
	}
	return strings.Join(pieces, " + ")
}

// jsString renders a Go string as a JSON string literal, which is a valid JS string
// literal with all necessary escaping.
func jsString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// clientCall renders the generic-client call for an operation's verb.
func clientCall(op Operation, recv, path string) string {
	switch op.Method {
	case "GET":
		return fmt.Sprintf("%s.get(%s)", recv, path)
	case "PUT":
		return fmt.Sprintf("%s.put(%s, body)", recv, path)
	case "POST":
		return fmt.Sprintf("%s.post(%s, body)", recv, path)
	case "DELETE":
		return fmt.Sprintf("%s.del(%s)", recv, path)
	case "PATCH":
		return fmt.Sprintf("%s.patch(%s, body)", recv, path)
	default:
		// Only the five supported verbs reach here (HEAD/OPTIONS/TRACE are skipped upstream).
		return fmt.Sprintf("%s.call(%s, %s, body)", recv, jsString(op.Method), path)
	}
}

// buildPreamble emits the typed SDK as an IIFE that attaches named methods to the
// grant's global. It references the global via globalThis[name] so it works for any
// global name (even one that is not a bare identifier), and no-ops if the generic
// client did not load — it never throws at preload time.
func buildPreamble(r *Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "// Generated by plimsoll-specgen from %q", r.Title)
	if r.Version != "" {
		fmt.Fprintf(&b, " v%s", r.Version)
	}
	b.WriteString(". Do not edit by hand.\n")
	fmt.Fprintf(&b, ";(function () {\n  const h = globalThis[%s];\n  if (!h) return;\n", jsString(r.Global))
	for _, op := range r.Operations {
		args := append([]string(nil), op.Params...)
		if op.HasBody {
			args = append(args, "body")
		}
		fmt.Fprintf(&b, "  h[%s] = (%s) => %s;\n", jsString(op.ID), strings.Join(args, ", "), clientCall(op, "h", pathExpr(op)))
	}
	b.WriteString("})();\n")
	return b.String()
}

// buildDescription emits the model-facing text a gateway shows the agent: the ONE
// place the API surface is described, generated so it can never drift from the allow
// list or the SDK. Deterministic and metadata-only.
func buildDescription(r *Result) string {
	var b strings.Builder
	title := r.Title
	if title == "" {
		title = "host API"
	}
	fmt.Fprintf(&b, "%s", title)
	if r.Version != "" {
		fmt.Fprintf(&b, " (v%s)", r.Version)
	}
	b.WriteString(".\n")
	fmt.Fprintf(&b, "Agent code reaches it through the brokered `%s.*` client; only the operations\n", r.Global)
	b.WriteString("below are permitted. Every call is allow-listed and gets a per-run token injected\n")
	b.WriteString("host-side, so the code never handles a credential.\n\n")
	for _, op := range r.Operations {
		args := append([]string(nil), op.Params...)
		if op.HasBody {
			args = append(args, "body")
		}
		fmt.Fprintf(&b, "  %s.%s(%s)  ->  %s %s\n", r.Global, op.ID, strings.Join(args, ", "), op.Method, op.Path)
		if op.Summary != "" {
			fmt.Fprintf(&b, "      %s\n", op.Summary)
		}
	}
	return b.String()
}
