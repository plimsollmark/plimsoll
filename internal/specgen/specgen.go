// Package specgen derives a plimsoll host-API grant description from an OpenAPI
// 3.x document. It is the Sluice "spec-import" path: today an operator hand-writes
// three things that must stay in sync — the grant's `allow` route list, the typed
// JS `preamble` SDK, and the model-facing tool description a gateway shows the agent.
// specgen emits all three from the ONE spec, plus an optional `health_check`
// backpressure probe for the operation the spec explicitly marks with
// x-plimsoll-health-check. A consumer can delete the hand-maintained copies and let
// drift become impossible (see the worked example in docs/examples/specgen).
//
// It is metadata-only and offline: it reads the spec's paths, methods, operationIds,
// path parameters, and summaries, and emits text. It never fetches the spec's server,
// never embeds a credential, and produces byte-identical output for a given input, so
// generation can run in a build step and the artifacts can be committed and diffed.
//
// # Supported subset
//
// A grant is an allowlist of literal path templates, so the generator can only
// represent operations a brokered call can actually make. The subset is enforced at
// parse time rather than documented and hoped for, because the failure mode of
// accepting more is a generated method that looks right and cannot work:
//
//   - Verbs: GET, PUT, POST, DELETE, PATCH. HEAD/OPTIONS/TRACE are reported in
//     Result.Skipped (the broker does not enforce them).
//   - Path parameters must be whole segments ("/lights/{id}", never
//     "/files/{name}.json"), because a segment maps to the broker's "*" wildcard.
//   - Query, header, and cookie parameters cannot be sent: the broker rejects any
//     target carrying a query string, and guest code cannot set headers. An operation
//     that REQUIRES one is reported in Result.Skipped; one that merely offers
//     optional ones is generated with a warning in Result.Warnings.
//   - $ref is not resolved. A $ref path item or parameter is an error: following it
//     is out of scope, and ignoring it would silently drop part of the surface.
//   - Every operation needs an operationId, unique after JS-identifier sanitizing,
//     and it may not collide with the injected client's own methods.
//
// Anything outside the subset is an error or a reported omission, never a quiet
// degradation of the emitted grant.
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
	ID     string // operationId -> the JS method name
	Method string // GET, PUT, POST, DELETE, PATCH
	Path   string // the spec path template, e.g. /lights/{id}
	Route  string // the allowlist template, e.g. /lights/* (path params -> "*")
	// Params are the JS argument names for the path parameters, in path order. They are
	// derived from the spec's parameter names but sanitized and deconflicted (jsArgNames),
	// so they are safe to emit as bindings and are not guaranteed to match the spec text.
	Params  []string
	HasBody bool   // the operation declares a requestBody (adds a trailing body arg)
	Summary string // the operation summary, for the model-facing description
}

// argList is the emitted method's full argument list: the path parameters, plus a
// trailing body argument only when the operation declares a request body. Code and
// description are both rendered from it, so the signature an agent is shown is the
// signature that exists.
func (o Operation) argList() []string {
	args := append([]string(nil), o.Params...)
	if o.HasBody {
		args = append(args, "body")
	}
	return args
}

// SkippedOp records an operation the generator could not represent as a grant, so the
// omission is reported rather than silent. Two causes exist: a verb the host-API broker
// does not enforce (it allows GET/PUT/POST/DELETE/PATCH, so a spec's HEAD/OPTIONS/TRACE
// operation is reported here instead of emitted as an allow route the validator rejects),
// and a required query/header/cookie parameter, which a brokered call has no way to send.
type SkippedOp struct {
	Method string
	Path   string
	Reason string
}

// Result is the generated grant description: the core artifacts, optional health probe,
// and the parsed operations they were built from.
type Result struct {
	Title      string
	Version    string
	Global     string
	Allow      []sandbox.HostRoute // deduped, sorted; the grant's allow list
	Operations []Operation         // sorted by (path, method)
	Skipped    []SkippedOp         // operations dropped as unrepresentable (with reason)
	// Warnings are non-fatal notes about operations that WERE generated but whose
	// emitted method is narrower than the spec describes (today: optional query or
	// header parameters a brokered call cannot send).
	Warnings    []string
	Preamble    string // typed JS SDK; goes in HostAPIGrant.Preamble
	Description string // model-facing text a gateway shows the agent
	// HealthCheck, when non-empty, is the "GET /path" line for the grant profile's
	// health_check backpressure probe: the concrete GET operation the spec marks with
	// x-plimsoll-health-check. It is empty unless the spec marks one, because the probe
	// decides when to resume traffic against a degraded upstream and an endpoint's NAME
	// is not evidence of what it measures (see HealthNote).
	HealthCheck string
	// HealthNote explains why no health route was emitted, so the absence is visible
	// rather than silent. Empty when one was.
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
	// Ref is a path-item $ref. It is parsed only so it can be REJECTED: the generator
	// resolves no references, and an unparsed path item would otherwise contribute no
	// operations and disappear from the generated surface without a word.
	Ref        string        `json:"$ref"`
	Parameters []oaParameter `json:"parameters"` // apply to every operation on the path
	Get        *oaOperation  `json:"get"`
	Put        *oaOperation  `json:"put"`
	Post       *oaOperation  `json:"post"`
	Delete     *oaOperation  `json:"delete"`
	Patch      *oaOperation  `json:"patch"`
	Head       *oaOperation  `json:"head"`
	Options    *oaOperation  `json:"options"`
	Trace      *oaOperation  `json:"trace"`
}

type oaOperation struct {
	OperationID string          `json:"operationId"`
	Summary     string          `json:"summary"`
	RequestBody json.RawMessage `json:"requestBody"`
	Parameters  []oaParameter   `json:"parameters"`
	// HealthCheck is the `x-plimsoll-health-check` OpenAPI extension: an explicit
	// operator marker designating THIS operation as the grant's backpressure health
	// probe. It is the ONLY way to designate one, and must resolve to a concrete GET.
	HealthCheck *bool `json:"x-plimsoll-health-check"`
}

// oaParameter is one declared parameter, read only for its location and whether it is
// required — enough to decide whether a brokered call can express the operation at all.
// Its schema is irrelevant here and deliberately unparsed.
type oaParameter struct {
	Ref      string `json:"$ref"`
	Name     string `json:"name"`
	In       string `json:"in"`
	Required bool   `json:"required"`
}

// classifyParams decides whether a brokered call can express an operation, given the
// path-item and operation parameter lists (operation-level entries override path-level
// ones with the same name and location, per OpenAPI).
//
// A grant authorizes a literal path template and nothing else: the broker rejects any
// target containing "?", and guest code cannot set request headers or cookies. So a
// REQUIRED parameter anywhere but the path makes the operation unexpressable (returned
// as skip), and an OPTIONAL one makes the generated method narrower than the spec
// (returned as warn). err is for input the generator refuses to guess about.
func classifyParams(method, path string, pathLevel, opLevel []oaParameter) (skip, warn string, err error) {
	type key struct{ in, name string }
	merged := map[key]oaParameter{}
	order := []key{}
	for _, list := range [][]oaParameter{pathLevel, opLevel} {
		for _, p := range list {
			if strings.TrimSpace(p.Ref) != "" {
				return "", "", fmt.Errorf("specgen: %s %s declares a $ref parameter; specgen resolves no references, so bundle/dereference the spec before generating", method, path)
			}
			in := strings.ToLower(strings.TrimSpace(p.In))
			name := strings.TrimSpace(p.Name)
			switch in {
			case "path", "query", "header", "cookie":
			default:
				return "", "", fmt.Errorf("specgen: %s %s declares parameter %q with unsupported location %q (want path/query/header/cookie)", method, path, name, p.In)
			}
			k := key{in, name}
			if _, dup := merged[k]; !dup {
				order = append(order, k)
			}
			merged[k] = p
		}
	}

	var required, optional []string
	for _, k := range order {
		if k.in == "path" {
			continue // the path template is authoritative for these
		}
		label := fmt.Sprintf("%s %q", k.in, k.name)
		if merged[k].Required {
			required = append(required, label)
		} else {
			optional = append(optional, label)
		}
	}
	if len(required) > 0 {
		return fmt.Sprintf("requires %s, which a brokered call cannot send: a grant authorizes a literal path, the broker rejects any query string, and guest code sets no headers", strings.Join(required, ", ")), "", nil
	}
	if len(optional) > 0 {
		return "", fmt.Sprintf("%s %s: optional %s cannot be sent through the broker, so the generated method always calls the bare route", method, path, strings.Join(optional, ", ")), nil
	}
	return "", "", nil
}

// noHealthMarkerNote is the note returned when a spec designates no health route. It
// says what the absence costs, because the alternative — guessing from an endpoint's
// NAME — was removed on 2026-09-17: the probe's 2xx is what lets the breaker resume
// traffic against a struggling API, and "/status" or "/capacity" in a path says nothing
// about what the endpoint measures. A wrong probe defeats backoff, which is worse than
// no probe at all (the breaker then simply waits out its cooldown).
const noHealthMarkerNote = "no operation is marked x-plimsoll-health-check, so the profile gets no health_check: " +
	"after an upstream 503 the per-run breaker waits out its full cooldown instead of probing for recovery. " +
	"Mark the one concrete GET that reports whether the API can take traffic again"

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
	var warnings []string
	seenMethod := map[string]bool{}   // JS method-name collision guard
	routeSet := map[string]struct{}{} // dedupe method+route
	var allow []sandbox.HostRoute
	var explicitHealth []string // ops marked x-plimsoll-health-check ("GET /path")

	for _, path := range paths {
		item := doc.Paths[path]
		if strings.TrimSpace(item.Ref) != "" {
			return nil, fmt.Errorf("specgen: path %q is a $ref (%q); specgen resolves no references, so bundle/dereference the spec before generating", path, item.Ref)
		}
		route, rawParams, err := deriveRoute(path)
		if err != nil {
			return nil, err
		}
		for _, m := range methodOrder {
			op := m.get(item)
			if op == nil {
				continue
			}
			// Whether a brokered call can express this operation at all is decided first,
			// so a marker or an allow entry is never emitted for one that cannot run.
			skipReason, warning, err := classifyParams(m.name, path, item.Parameters, op.Parameters)
			if err != nil {
				return nil, err
			}
			// An explicit health-check marker is checked before the verb-support gate so a
			// marker on an unenforceable verb (HEAD/OPTIONS/TRACE) fails closed too: the
			// backpressure probe MUST be a concrete GET, so anything else is operator error.
			if op.HealthCheck != nil && *op.HealthCheck {
				if m.name != "GET" {
					return nil, fmt.Errorf("specgen: %s %s is marked x-plimsoll-health-check, but a health_check probe must be GET", m.name, path)
				}
				if len(rawParams) != 0 {
					return nil, fmt.Errorf("specgen: GET %s is marked x-plimsoll-health-check, but a health_check must be a concrete path (no path parameters)", path)
				}
				if skipReason != "" {
					return nil, fmt.Errorf("specgen: GET %s is marked x-plimsoll-health-check, but it %s", path, skipReason)
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
			if skipReason != "" {
				skipped = append(skipped, SkippedOp{Method: m.name, Path: path, Reason: skipReason})
				continue
			}
			if warning != "" {
				warnings = append(warnings, warning)
			}
			if op.OperationID == "" {
				return nil, fmt.Errorf("specgen: %s %s has no operationId (needed for a stable method name)", m.name, path)
			}
			name := jsIdent(op.OperationID)
			if clientMethods[name] {
				// The typed SDK attaches its methods to the SAME object as the generic
				// client, and its method bodies call that client. A method named after one
				// of its own primitives would replace it and then call itself.
				return nil, fmt.Errorf("specgen: operationId %q yields method name %q, which is one of the injected client's own methods (%s); rename the operation", op.OperationID, name, strings.Join(clientMethodList, ", "))
			}
			if seenMethod[name] {
				return nil, fmt.Errorf("specgen: operationId %q collides with another method name %q", op.OperationID, name)
			}
			seenMethod[name] = true

			hasBody := len(op.RequestBody) > 0 && bodyAllowed(m.name)
			ops = append(ops, Operation{
				ID:      name,
				Method:  m.name,
				Path:    path,
				Route:   route,
				Params:  jsArgNames(rawParams, hasBody),
				HasBody: hasBody,
				Summary: strings.TrimSpace(op.Summary),
			})
			key := m.name + " " + route
			if _, ok := routeSet[key]; !ok {
				routeSet[key] = struct{}{}
				allow = append(allow, sandbox.HostRoute{Method: m.name, Path: route})
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

	// Resolve the backpressure health route. Only an explicit marker designates one,
	// and more than one is fail-closed operator error.
	var health, healthNote string
	switch len(explicitHealth) {
	case 0:
		healthNote = noHealthMarkerNote
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
		Warnings:    warnings,
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

// clientBinding is the local name the generated preamble binds the injected generic
// client to. Nothing else in the emitted function bodies is a free variable, so this is
// the one name a generated argument must never shadow (see jsArgNames).
const clientBinding = "h"

// clientMethodList is the injected generic client's own surface (sandbox/capability.go).
// The typed SDK hangs its methods off the SAME object, so a generated method named after
// one of these would overwrite the primitive its own body then calls.
var clientMethodList = []string{"call", "del", "get", "patch", "post", "put"}

var clientMethods = func() map[string]bool {
	m := make(map[string]bool, len(clientMethodList))
	for _, n := range clientMethodList {
		m[n] = true
	}
	return m
}()

// jsReserved lists the words that cannot be a binding identifier in a strict-mode
// module, which is what the preamble is preloaded as. A path parameter named "default"
// or "new" is legal in a spec and a syntax error in the emitted arrow function, so
// jsArgNames renames rather than emitting code that will not parse.
var jsReserved = func() map[string]bool {
	words := []string{
		"arguments", "await", "break", "case", "catch", "class", "const", "continue",
		"debugger", "default", "delete", "do", "else", "enum", "eval", "export",
		"extends", "false", "finally", "for", "function", "if", "implements", "import",
		"in", "instanceof", "interface", "let", "new", "null", "package", "private",
		"protected", "public", "return", "static", "super", "switch", "this", "throw",
		"true", "try", "typeof", "var", "void", "while", "with", "yield",
	}
	m := make(map[string]bool, len(words))
	for _, w := range words {
		m[w] = true
	}
	return m
}()

// jsArgNames turns a path template's parameter names into the emitted method's argument
// names. Spec parameter names are arbitrary text ("item-id", "h", "default"), while these
// become real bindings in generated code, so each is sanitized and then deconflicted
// against the client binding, the body argument, JS reserved words, and the arguments
// already emitted for this operation. Renaming is safe because the arguments are
// positional and the same list feeds both the code and the description; emitting the raw
// name is not, since it can produce a syntax error or silently shadow the client.
func jsArgNames(raw []string, hasBody bool) []string {
	taken := map[string]bool{clientBinding: true}
	if hasBody {
		taken["body"] = true
	}
	out := make([]string, 0, len(raw))
	for _, r := range raw {
		name := jsIdent(r)
		for jsReserved[name] || taken[name] {
			name += "_"
		}
		taken[name] = true
		out = append(out, name)
	}
	return out
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

// clientCall renders the generic-client call for an operation's verb. A body argument
// is passed only when the operation declared a requestBody: the emitted method has no
// `body` parameter otherwise, and naming one anyway compiles fine and throws a
// ReferenceError the first time an agent calls it. The client reads a missing argument
// as `undefined` and sends no body, which is exactly the bodyless case.
func clientCall(op Operation, recv, path string) string {
	args := path
	if op.HasBody {
		args = path + ", body"
	}
	switch op.Method {
	case "GET":
		return fmt.Sprintf("%s.get(%s)", recv, path)
	case "PUT":
		return fmt.Sprintf("%s.put(%s)", recv, args)
	case "POST":
		return fmt.Sprintf("%s.post(%s)", recv, args)
	case "DELETE":
		return fmt.Sprintf("%s.del(%s)", recv, path)
	case "PATCH":
		return fmt.Sprintf("%s.patch(%s)", recv, args)
	default:
		// Only the five supported verbs reach here (HEAD/OPTIONS/TRACE are skipped upstream).
		return fmt.Sprintf("%s.call(%s, %s)", recv, jsString(op.Method), args)
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
	fmt.Fprintf(&b, ";(function () {\n  const %s = globalThis[%s];\n  if (!%s) return;\n", clientBinding, jsString(r.Global), clientBinding)
	for _, op := range r.Operations {
		fmt.Fprintf(&b, "  %s[%s] = (%s) => %s;\n", clientBinding, jsString(op.ID), strings.Join(op.argList(), ", "), clientCall(op, clientBinding, pathExpr(op)))
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
		fmt.Fprintf(&b, "  %s.%s(%s)  ->  %s %s\n", r.Global, op.ID, strings.Join(op.argList(), ", "), op.Method, op.Path)
		if op.Summary != "" {
			fmt.Fprintf(&b, "      %s\n", op.Summary)
		}
	}
	return b.String()
}
