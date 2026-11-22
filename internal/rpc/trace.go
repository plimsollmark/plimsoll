package rpc

import (
	"log/slog"
	"regexp"

	"github.com/plimsollmark/plimsoll/protocol"
)

// Correlation ids. plimsoll's audit stream is metadata only BY CONSTRUCTION —
// route templates, verbs, counts, timings, never a path or a body. That invariant
// is what lets the daemon decline to keep a second copy of a request the caller
// already logged. The cost of declining is that plimsoll's line alone cannot
// answer "which record did the agent read".
//
// A trace id closes that without widening the record: the caller stamps the id it
// already uses in its own log (an upstream MCP proxy can carry such an id across
// its boundary), plimsoll echoes it onto the run's audit line, and the two
// logs JOIN. The sensitive payload still exists in exactly one place. This is the
// difference between "we record less" and "we record the part that is ours".
//
// The id is caller-controlled, so it is also the only string on the run request
// that could carry a path, a customer identifier, or a token into the very stream
// that promises it holds none. Everything below exists to make that impossible to
// do by accident: a strict charset, a hard length bound, and a fail-closed drop
// (never a silent truncation, which would produce a plausible-looking id that
// joins to nothing).

// traceIDForm is the whole grammar of an accepted correlation id,
// protocol.TraceIDPattern, which the clients check against too. Its bound of 64
// characters (bytes, since every allowed character is ASCII) comfortably fits short
// gateway ids, a 36-char UUID, and a 32-char OTel trace id while keeping a
// cardinality-safe, greppable audit field.
var traceIDForm = regexp.MustCompile(protocol.TraceIDPattern)

// sanitizeTraceID returns the id to record and whether a non-empty id was
// REJECTED. An absent id is the normal case for a caller that does not correlate:
// ("", false). A conforming id passes through: (id, false). A non-conforming one
// is dropped whole and reported: ("", true) — the caller's bad value is never
// logged, echoed, or partially repaired, since a truncated id joins to nothing
// while looking like it should.
//
// The accepted charset is [A-Za-z0-9._:-]. It admits hex, base32, UUIDs, and
// OTel-style ids, and excludes the characters that would let an id read as a URL
// path, a query, JSON, or whitespace-delimited log fields: no '/', '?', '=', '&',
// '%', quotes, spaces, or control bytes. An id that cannot look like a path
// cannot smuggle one.
func sanitizeTraceID(id string) (string, bool) {
	if id == "" {
		return "", false
	}
	if !traceIDForm.MatchString(id) {
		return "", true
	}
	return id, false
}

// traceAttrs renders the caller's correlation id for a run's audit line. It emits
// trace_id only for an id that was supplied AND conformed, and trace_id_rejected
// when one was supplied and did not — so an operator whose join quietly stops
// working can see that it was plimsoll that dropped the id, without the
// offending value ever reaching the log it was rejected from. A run with no id
// logs neither attribute, keeping the line byte-identical for callers that do not
// correlate.
func traceAttrs(raw string) []slog.Attr {
	id, rejected := sanitizeTraceID(raw)
	switch {
	case rejected:
		return []slog.Attr{slog.Bool("trace_id_rejected", true)}
	case id != "":
		return []slog.Attr{slog.String("trace_id", id)}
	default:
		return nil
	}
}
