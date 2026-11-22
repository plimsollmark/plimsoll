// Command wiretables writes the other readers' copies of the protocol's enums and the wire
// rules every client checks from their one source: the enums from
// proto/plimsoll/v1/sandbox.proto (through the generated descriptors); the isolation tiers,
// cell languages, request limits and id grammars from package sandbox; the protocol number,
// header names and correlation id grammar from package protocol; the record versions'
// layouts and the record's bounds from package record; the answer size cap from package
// client. It writes them into the Python client, the TypeScript client and the receipt
// checker of examples/sbom (check.js, which runs in a browser). make generate runs it, and
// the gate's drift check fails when a written file is stale. The three clients once kept
// these by hand and drifted: a session end missing from one, a project outcome another did
// not know (review, 2026-10-23); and the request limits, the record layouts and the
// qualification rule were still copied by hand until 2026-11-18.
//
// The algorithms that use these values (the digests, the checks) stay written by hand in
// each language and are held to shared vectors (record/testdata/golden.json), so two
// implementations checked against the same vectors also catch a bug in the Go one.
//
//	go run ./internal/wiretables
package main

import (
	"bytes"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"

	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/plimsollmark/plimsoll/client"
	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/protocol"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
)

const (
	pythonOut     = "clients/python/src/plimsoll_client/_tables.py"
	typescriptOut = "clients/typescript/src/tables.gen.ts"
	checkerOut    = "examples/sbom/tables.gen.js"
	// The programs a granted call of a code tool writes into its project, and the
	// providers whose Python steps can use them (granted.go).
	grantedPythonOut     = "clients/python/src/plimsoll_client/_granted.py"
	grantedTypescriptOut = "clients/typescript/src/granted.gen.ts"
)

// enum is one protocol enum as the clients read it: each value's wire name, and the
// short name a client uses, in number order. zero is the short name of the unspecified
// value, which means something different in each enum.
type enum struct {
	desc  protoreflect.EnumDescriptor
	short string // the clients' constant prefix: OUTCOME, SESSION_END, REFUSAL
	zero  string
}

func enums() []enum {
	return []enum{
		{plimsollv1.ProjectOutcome(0).Descriptor(), "OUTCOME", "unspecified"},
		// Unspecified is a session that has not ended.
		{plimsollv1.SessionEnd(0).Descriptor(), "SESSION_END", "open"},
		// Unspecified is a refusal whose reason this client cannot name.
		{plimsollv1.NotDispatchedReason(0).Descriptor(), "REFUSAL", "unknown"},
	}
}

// values returns e's wire names and short names, by number, refusing a gap: the clients
// index the short names by number.
func (e enum) values() (wire, short []string, err error) {
	vs := e.desc.Values()
	prefix := commonPrefix(vs)
	for i := range vs.Len() {
		v := vs.ByNumber(protoreflect.EnumNumber(i))
		if v == nil {
			return nil, nil, fmt.Errorf("%s has no value %d: the clients index its names by number", e.desc.FullName(), i)
		}
		wire = append(wire, string(v.Name()))
		name := strings.ToLower(strings.TrimPrefix(string(v.Name()), prefix))
		if i == 0 {
			name = e.zero
		}
		short = append(short, name)
	}
	if len(wire) != vs.Len() {
		return nil, nil, fmt.Errorf("%s: numbers are not 0 to %d", e.desc.FullName(), vs.Len()-1)
	}
	return wire, short, nil
}

// commonPrefix is the enum's value prefix, the unspecified value's name less UNSPECIFIED.
func commonPrefix(vs protoreflect.EnumValueDescriptors) string {
	return strings.TrimSuffix(string(vs.ByNumber(0).Name()), "UNSPECIFIED")
}

// tiers are the isolation tiers weakest first, as the clients compare them.
func tiers() []string {
	var out []string
	for c := sandbox.IsolationNone; c <= sandbox.IsolationVM; c++ {
		out = append(out, c.String())
	}
	return out
}

func languages() []string {
	out := make([]string, len(sandbox.Languages))
	for i, l := range sandbox.Languages {
		out[i] = string(l)
	}
	return out
}

// constant is one wire rule a client checks, with the line that says what it is and where
// it comes from. value is an int, a string, a []string, a map[int][]string (the record
// layouts) or a [][2]rune (code point ranges). A grammar is a Go regular expression
// anchored with ^ and $ whose syntax Python's re and JavaScript's RegExp read the same
// way; a Python reader matches it with fullmatch.
type constant struct {
	name  string
	doc   string
	value any
}

// constants is the table of wire rules every reader gets, in the order they are written.
func constants() []constant {
	floors := tiers()[1:] // a request's floor: every tier but none
	return []constant{
		{"PROTOCOL", "The wire protocol number a client states on every request (protocol.Number).", int(protocol.Number)},
		{"REQUEST_ID_HEADER", "The header carrying a client's ID for one request, which the daemon echoes (protocol.RequestIDHeader).", protocol.RequestIDHeader},
		{"NOT_DISPATCHED_HEADER", "The daemon's mark on an answer written before any handler ran (protocol.NotDispatchedHeader).", protocol.NotDispatchedHeader},
		{"TRACE_ID_PATTERN", "A correlation id's grammar; the daemon drops one outside it (protocol.TraceIDPattern).", protocol.TraceIDPattern},
		{"STALE_OWNER_TEXT", "The text of a session call, close or attach refused because another worker attached (protocol.StaleOwnerText).", protocol.StaleOwnerText},
		{"CHECKPOINT_MISMATCH_TEXT", "The text of an attach refused because its checkpoint is not the session's head (protocol.CheckpointMismatchText).", protocol.CheckpointMismatchText},
		{"FLOORS", "The tiers a request may state as its floor, weakest first: every tier but none.", floors},
		{"RECORD_VERSION", "The record version a live answer carries (record.Version).", record.Version},
		{"RECORD_FIELDS", "Each published record version's digest fields, in order (record.PublishedLayouts).", record.PublishedLayouts()},
		{"LAST_WALL_CLOCK_END_VERSION", "The last record version whose daemons stamped both times from the wall clock; reading such a record that ends before it starts is retired (record.LastWallClockEndVersion).", record.LastWallClockEndVersion},
		{"RETIRED_END_BEFORE_START_TEXT", "The refusal of a version 1 or 2 record that ends before it starts: a retired reading, not a forgery (record.RetiredEndBeforeStartText).", record.RetiredEndBeforeStartText},
		{"UNANSWERED_CODES", "The codes an unanswered call's record may name (record.UnansweredCodes).", record.UnansweredCodes()},
		{"MAX_QUALIFICATION_BYTES", "The most bytes an isolation qualification may take (record.MaxQualificationBytes).", record.MaxQualificationBytes},
		{"QUALIFICATION_FORBIDDEN", "The code points a qualification may not hold, as inclusive ranges (record.QualificationForbidden).", record.QualificationForbidden()},
		{"MAX_DAEMON_VERSION_BYTES", "The most bytes a record's daemon version may take (record.MaxDaemonVersionBytes).", record.MaxDaemonVersionBytes},
		{"DAEMON_VERSION_PATTERN", "A daemon version's grammar, when it is not empty (record.DaemonVersionPattern).", record.DaemonVersionPattern},
		{"INSTANCE_PATTERN", "A typed instance reference's grammar, when it is not empty (sandbox.InstancePattern).", sandbox.InstancePattern},
		{"MAX_CODE_BYTES", "The most bytes of code a snippet or a cell may carry (sandbox.MaxCodeBytes).", sandbox.MaxCodeBytes},
		{"MAX_PROJECT_BYTES", "The most bytes a request's files may hold together (sandbox.MaxProjectBytes).", sandbox.MaxProjectBytes},
		{"MAX_PROJECT_FILES", "The most files a request may write (sandbox.MaxProjectFiles).", sandbox.MaxProjectFiles},
		{"MAX_PROJECT_STEPS", "The most steps a project may run (sandbox.MaxProjectSteps).", sandbox.MaxProjectSteps},
		{"MAX_PROJECT_ARTIFACTS", "The most artifacts a project may ask for (sandbox.MaxProjectArtifacts).", sandbox.MaxProjectArtifacts},
		{"MAX_PROJECT_PATH_BYTES", "The most bytes a file or artifact path may take (sandbox.MaxProjectPathBytes).", sandbox.MaxProjectPathBytes},
		{"MAX_PROJECT_STEP_BYTES", "The most bytes one step's command may take (sandbox.MaxProjectStepBytes).", sandbox.MaxProjectStepBytes},
		{"MAX_MODULE_ROWS", "The most parameter rows a module run may carry (sandbox.MaxModuleRows).", sandbox.MaxModuleRows},
		{"MAX_MODULE_ROW_WIDTH", "The most values one module row may carry (sandbox.MaxModuleRowWidth).", sandbox.MaxModuleRowWidth},
		{"MAX_MODULE_STEPS", "The most steps one module instance may take (sandbox.MaxModuleSteps).", sandbox.MaxModuleSteps},
		{"MAX_MODULE_RESULT_BYTES", "The most bytes a module run's results may take (sandbox.MaxModuleResultBytes).", sandbox.MaxModuleResultBytes},
		{"MODULE_RESULT_HEADER_BYTES", "The bytes a module run's results start with before the rows (sandbox.ModuleResultHeaderBytes).", sandbox.ModuleResultHeaderBytes},
		{"MODULE_ID_PATTERN", "A model id's grammar (sandbox.ModuleIDPattern).", sandbox.ModuleIDPattern},
		{"MAX_SOFTWARE_IDENTITIES", "The most identities an approved software rule may name (sandbox.MaxSoftwareIdentities).", sandbox.MaxSoftwareIdentities},
		{"MAX_SOFTWARE_IDENTITY_BYTES", "The most bytes one software identity may take (sandbox.MaxSoftwareIdentityBytes).", sandbox.MaxSoftwareIdentityBytes},
		{"SOFTWARE_IDENTITY_PATTERN", "The characters a software identity may hold (sandbox.SoftwareIdentityPattern).", sandbox.SoftwareIdentityPattern},
		{"MAX_RESPONSE_BYTES", "The largest answer a client reads (client.MaxResponseBytes).", client.MaxResponseBytes},
		{"CHECKPOINT_VERSION", "The one version of a session checkpoint the clients write and read (client.CheckpointVersion).", client.CheckpointVersion},
		{"DAEMON_NAME_PATTERN", "A daemon name's grammar: the application's own name for a daemon, never a URL (client.DaemonNamePattern).", client.DaemonNamePattern},
		{"SOFTWARE_RULE_ID_PATTERN", "A software rule's ID as a checkpoint states it (client.SoftwareRuleIDPattern).", client.SoftwareRuleIDPattern},
		{"CALL_ALREADY_SENT_TEXT", "What a client says when it refuses a repeat of a call lost across a takeover (client.CallAlreadySentText).", client.CallAlreadySentText},
	}
}

func main() {
	py, ts, js, err := render()
	if err != nil {
		fmt.Fprintln(os.Stderr, "wiretables:", err)
		os.Exit(1)
	}
	gpy, gts, err := renderGranted()
	if err != nil {
		fmt.Fprintln(os.Stderr, "wiretables:", err)
		os.Exit(1)
	}
	for path, b := range map[string][]byte{pythonOut: py, typescriptOut: ts, checkerOut: js, grantedPythonOut: gpy, grantedTypescriptOut: gts} {
		if err := os.WriteFile(path, b, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "wiretables:", err)
			os.Exit(1)
		}
	}
}

func render() (py, ts, js []byte, err error) {
	var p, t, j bytes.Buffer
	p.WriteString(`# Code generated by internal/wiretables (make generate). DO NOT EDIT.
"""The protocol's enums and the wire rules every client checks, from
proto/plimsoll/v1/sandbox.proto and the Go packages that enforce them (protocol, record,
sandbox, client), so this client and the Go and TypeScript ones cannot drift apart."""

from typing import Dict, Tuple
`)
	t.WriteString(`// Code generated by internal/wiretables (make generate). DO NOT EDIT.
// The protocol's enums and the wire rules every client checks, from
// proto/plimsoll/v1/sandbox.proto and the Go packages that enforce them (protocol, record,
// sandbox, client), so this client and the Go and Python ones cannot drift apart.
`)
	j.WriteString(`// Code generated by internal/wiretables (make generate). DO NOT EDIT.
// The protocol's enum names and the wire rules check.js reads, from
// proto/plimsoll/v1/sandbox.proto and the Go packages that enforce them (protocol, record,
// sandbox, client), so the receipt checker and the clients cannot drift apart. The page
// loads it before check.js.
(function (root) {
  'use strict';
  root.PlimsollWireTables = Object.freeze({
`)
	for _, e := range enums() {
		wire, short, err := e.values()
		if err != nil {
			return nil, nil, nil, err
		}
		fmt.Fprintf(&p, "\n# %s, by number.\n%sS: Dict[str, int] = {\n", e.desc.FullName(), e.short)
		fmt.Fprintf(&t, "\n/** %s, by number. */\nexport const %sS: Readonly<Record<string, number>> = {\n", e.desc.FullName(), e.short)
		for i, w := range wire {
			fmt.Fprintf(&p, "    %q: %d,\n", w, i)
			fmt.Fprintf(&t, "  %s: %d,\n", w, i)
		}
		p.WriteString("}\n")
		t.WriteString("};\n")
		fmt.Fprintf(&p, "%s_NAMES: Tuple[str, ...] = (%s)\n", e.short, quoted(short, true))
		fmt.Fprintf(&t, "export const %s_NAMES = [%s] as const;\n", e.short, quoted(short, false))
		fmt.Fprintf(&j, "    // %s's short names, by number.\n    %s_NAMES: Object.freeze([%s]),\n", e.desc.FullName(), e.short, quoted(short, false))
	}
	fmt.Fprintf(&p, "\n# Isolation tiers, weakest first (sandbox.IsolationClass).\nTIERS: Tuple[str, ...] = (%s)\n", quoted(tiers(), true))
	fmt.Fprintf(&t, "\n/** Isolation tiers, weakest first (sandbox.IsolationClass). */\nexport const TIERS = [%s] as const;\n", quoted(tiers(), false))
	fmt.Fprintf(&j, "    // Isolation tiers, weakest first (sandbox.IsolationClass).\n    TIERS: Object.freeze([%s]),\n", quoted(tiers(), false))
	fmt.Fprintf(&p, "\n# The languages plimsoll keeps an interpreter for (sandbox.Languages).\nLANGUAGES: Tuple[str, ...] = (%s)\n", quoted(languages(), true))
	fmt.Fprintf(&t, "\n/** The languages plimsoll keeps an interpreter for (sandbox.Languages). */\nexport const LANGUAGES = [%s] as const;\n", quoted(languages(), false))
	fmt.Fprintf(&j, "    // The languages plimsoll keeps an interpreter for (sandbox.Languages).\n    LANGUAGES: Object.freeze([%s]),\n", quoted(languages(), false))
	for _, c := range constants() {
		pv, pt, err := pythonValue(c.value)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("%s: %w", c.name, err)
		}
		tv, tt := typescriptValue(c.value)
		fmt.Fprintf(&p, "\n# %s\n%s: %s = %s\n", c.doc, c.name, pt, pv)
		if tt != "" {
			fmt.Fprintf(&t, "\n/** %s */\nexport const %s: %s = %s;\n", c.doc, c.name, tt, tv)
		} else {
			fmt.Fprintf(&t, "\n/** %s */\nexport const %s = %s;\n", c.doc, c.name, tv)
		}
		fmt.Fprintf(&j, "    // %s\n    %s: %s,\n", c.doc, c.name, javascriptValue(c.value))
	}
	j.WriteString("  });\n})(globalThis);\n")
	return p.Bytes(), t.Bytes(), j.Bytes(), nil
}

// pythonValue is v as a Python literal and its annotation.
func pythonValue(v any) (literal, annotation string, err error) {
	switch v := v.(type) {
	case int:
		return fmt.Sprint(v), "int", nil
	case string:
		return pythonString(v), "str", nil
	case []string:
		return "(" + quoted(v, true) + ")", "Tuple[str, ...]", nil
	case map[int][]string:
		var parts []string
		for _, k := range slices.Sorted(maps.Keys(v)) {
			parts = append(parts, fmt.Sprintf("    %d: (%s),\n", k, quoted(v[k], true)))
		}
		return "{\n" + strings.Join(parts, "") + "}", "Dict[int, Tuple[str, ...]]", nil
	case [][2]rune:
		var parts []string
		for _, r := range v {
			parts = append(parts, fmt.Sprintf("(0x%04X, 0x%04X)", r[0], r[1]))
		}
		return "(" + strings.Join(parts, ", ") + ",)", "Tuple[Tuple[int, int], ...]", nil
	}
	return "", "", fmt.Errorf("no Python form for %T", v)
}

// pythonString is s as a Python string literal: a raw string for a grammar, so its
// backslashes are the regular expression's own.
func pythonString(s string) string {
	if strings.Contains(s, `\`) {
		if strings.ContainsAny(s, "\"\n") || strings.HasSuffix(s, `\`) {
			panic("wiretables: a grammar a raw Python string cannot hold: " + s)
		}
		return `r"` + s + `"`
	}
	return fmt.Sprintf("%q", s)
}

// typescriptValue is v as a TypeScript literal and its type, or "" to let the literal's
// own type stand.
func typescriptValue(v any) (literal, typ string) {
	switch v := v.(type) {
	case map[int][]string:
		var parts []string
		for _, k := range slices.Sorted(maps.Keys(v)) {
			parts = append(parts, fmt.Sprintf("  %d: [%s],\n", k, quoted(v[k], false)))
		}
		return "{\n" + strings.Join(parts, "") + "}", "Readonly<Record<number, readonly string[]>>"
	case [][2]rune:
		return javascriptValue(v), "readonly (readonly [number, number])[]"
	case []string:
		return "[" + quoted(v, false) + "] as const", ""
	}
	return javascriptValue(v), ""
}

// javascriptValue is v as a JavaScript literal; arrays and objects are frozen.
func javascriptValue(v any) string {
	switch v := v.(type) {
	case int:
		return fmt.Sprint(v)
	case string:
		return javascriptString(v)
	case []string:
		return "Object.freeze([" + quoted(v, false) + "])"
	case map[int][]string:
		var parts []string
		for _, k := range slices.Sorted(maps.Keys(v)) {
			parts = append(parts, fmt.Sprintf("%d: Object.freeze([%s])", k, quoted(v[k], false)))
		}
		return "Object.freeze({" + strings.Join(parts, ", ") + "})"
	case [][2]rune:
		var parts []string
		for _, r := range v {
			parts = append(parts, fmt.Sprintf("[0x%04X, 0x%04X]", r[0], r[1]))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	}
	panic(fmt.Sprintf("wiretables: no JavaScript form for %T", v))
}

// javascriptString is s as a JavaScript string literal. Go's quoting of the ASCII text
// written here is valid JavaScript.
func javascriptString(s string) string {
	for _, c := range s {
		if c < 0x20 || c > 0x7e {
			panic(fmt.Sprintf("wiretables: %q is not printable ASCII", s))
		}
	}
	return fmt.Sprintf("%q", s)
}

// quoted joins names as string literals; a one-element Python tuple keeps its comma.
func quoted(names []string, python bool) string {
	parts := make([]string, len(names))
	for i, n := range names {
		parts[i] = fmt.Sprintf("%q", n)
	}
	s := strings.Join(parts, ", ")
	if python && len(names) == 1 {
		s += ","
	}
	return s
}
