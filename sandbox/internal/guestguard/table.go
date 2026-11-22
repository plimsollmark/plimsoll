// Package guestguard holds the guest guard's table of refused requests (refused.json) and
// turns it into the guard's filter: one classic BPF program per machine, the form
// prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER) installs, written as bytes beside this file
// (filter_<goarch>.bin) and as a C header (guest_filter.h) by
// go run ./sandbox/internal/guestguard/gen. A C or Rust guard embeds those bytes: the C one,
// program/guard.c, starts first in every command the docker provider runs in a container.
//
// The guard refuses, inside a sandbox, the requests by which code makes a private view of
// the system and mounts a folder of its own (namespaces, mounts, a new root), the tracing
// requests that let a tracer rewrite a request after a filter read it under gVisor, every
// request through an entry other than the machine's own, and every request numbered above
// the table's ceiling. The design is private/guest-guard-design-2026-11-19.md.
//
// The table is data so that every reader takes it from one place: the generated filter,
// the tests that run that filter, and later a native helper's guard mode, which reads the
// same bytes.
package guestguard

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"strconv"
)

//go:embed refused.json
var refusedJSON []byte

// Answers a filter gives. EPERM is "Operation not permitted", what a program lacking the
// right gets; ENOSYS is "Function not implemented", what an older kernel answers, on which C
// libraries fall back to an older request; Kill ends the whole process with SIGSYS.
const (
	EPERM  = "EPERM"
	ENOSYS = "ENOSYS"
	Kill   = "KILL"
	Allow  = "ALLOW"
)

// Where the tracing rows apply: the design's decision 137, one line of the table.
const (
	TracingEverywhere = "everywhere"
	TracingNowhere    = "nowhere"
	TracingGVisor     = "gvisor"
)

// Errno numbers, the same on x86-64 and aarch64.
var errnos = map[string]uint32{EPERM: 1, ENOSYS: 38}

// Table is refused.json.
type Table struct {
	About          string            `json:"about"`
	Sources        map[string]string `json:"sources"`
	Ceiling        uint32            `json:"ceiling"`
	CeilingWhy     string            `json:"ceiling_why"`
	TracingRefused string            `json:"tracing_refused"`
	TracingWhy     string            `json:"tracing_refused_why"`
	SelfCheck      SelfCheck         `json:"self_check"`
	Arches         []Arch            `json:"arches"`
	Requests       []Request         `json:"requests"`
}

// SelfCheck is the one answer only the guard's own filter gives (finding guest-guard-13): Request,
// a row of the table refused whole, made with the low 32 bits of its first argument equal to
// Arg0Low, is answered with Errno, an errno no kernel gives for that request. The guard makes it
// before it starts anything and requires that answer: a refusal by another filter (plimsoll's
// shipped profile answers EPERM) or by the kernel (EINVAL) is not the guard's, so a guard whose
// install did nothing cannot pass. Seccomp gives the newest filter's errno when two filters both
// answer with one, so the answer shows through any profile that answers the request with an errno.
type SelfCheck struct {
	Request   string `json:"request"`
	Arg0Low   string `json:"arg0_low"`
	Errno     uint32 `json:"errno"`
	ErrnoName string `json:"errno_name"`
	Why       string `json:"why"`

	arg0 uint32
}

// Arg0 is the parsed Arg0Low.
func (c SelfCheck) Arg0() uint32 { return c.arg0 }

// Arch is one machine the filter is written for.
type Arch struct {
	Name      string `json:"name"`       // the kernel's name: x86_64, aarch64
	GOARCH    string `json:"goarch"`     // Go's name, which names the generated file
	AuditArch string `json:"audit_arch"` // seccomp_data.arch of the machine's own entry
	X32Bit    string `json:"x32_bit"`    // the number bit of a second entry with the same arch value (x86-64's x32), killed; empty when none

	audit, x32 uint32
}

// Request is one refused request.
type Request struct {
	Name    string `json:"name"`
	X86_64  uint32 `json:"x86_64"`
	AArch64 uint32 `json:"aarch64"`
	Answer  string `json:"answer"`
	// WhenArg0Any, when set, refuses the request only when the low 32 bits of its first
	// argument share a bit with this mask (clone's namespace flags); otherwise it is allowed.
	WhenArg0Any string `json:"when_arg0_any,omitempty"`
	// Tracing marks the rows decision 137 is about (TracingRefused says where they apply).
	Tracing bool   `json:"tracing,omitempty"`
	Why     string `json:"why"`
	GVisor  string `json:"gvisor"`

	mask uint32
}

// Number is the request's number on machine a.
func (r Request) Number(a Arch) uint32 {
	if a.Name == "aarch64" {
		return r.AArch64
	}
	return r.X86_64
}

// Mask is the parsed WhenArg0Any, 0 for an unconditional row.
func (r Request) Mask() uint32 { return r.mask }

// Audit is the parsed AuditArch; X32 the parsed X32Bit, 0 for none.
func (a Arch) Audit() uint32 { return a.audit }
func (a Arch) X32() uint32   { return a.x32 }

// Load reads the committed table.
func Load() (*Table, error) { return Parse(refusedJSON) }

// Parse reads and checks a table: unknown fields, a missing number, a number at or above
// 0x40000000 (it would collide with -1 or x32), a number above the ceiling, a name or a
// number listed twice on one machine, and an answer other than EPERM or ENOSYS are refused.
func Parse(b []byte) (*Table, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var t Table
	if err := dec.Decode(&t); err != nil {
		return nil, fmt.Errorf("refused.json: %w", err)
	}
	if t.Ceiling == 0 || t.Ceiling >= 0x40000000 {
		return nil, fmt.Errorf("refused.json: ceiling %d out of range", t.Ceiling)
	}
	switch t.TracingRefused {
	case TracingEverywhere, TracingNowhere, TracingGVisor:
	default:
		return nil, fmt.Errorf("refused.json: tracing_refused %q is not everywhere, nowhere or gvisor", t.TracingRefused)
	}
	if len(t.Arches) == 0 {
		return nil, fmt.Errorf("refused.json: no arches")
	}
	for i := range t.Arches {
		a := &t.Arches[i]
		if a.Name != "x86_64" && a.Name != "aarch64" {
			return nil, fmt.Errorf("refused.json: arch %q has no number column", a.Name)
		}
		v, err := strconv.ParseUint(a.AuditArch, 0, 32)
		if err != nil || v == 0 {
			return nil, fmt.Errorf("refused.json: %s audit_arch %q: %v", a.Name, a.AuditArch, err)
		}
		a.audit = uint32(v)
		if a.X32Bit != "" {
			v, err := strconv.ParseUint(a.X32Bit, 0, 32)
			if err != nil || v == 0 || v&(v-1) != 0 {
				return nil, fmt.Errorf("refused.json: %s x32_bit %q is not one bit", a.Name, a.X32Bit)
			}
			a.x32 = uint32(v)
		}
	}
	names := map[string]bool{}
	for i := range t.Requests {
		r := &t.Requests[i]
		if r.Name == "" || names[r.Name] {
			return nil, fmt.Errorf("refused.json: request %d: name %q empty or listed twice", i, r.Name)
		}
		names[r.Name] = true
		if _, ok := errnos[r.Answer]; !ok {
			return nil, fmt.Errorf("refused.json: %s: answer %q is not EPERM or ENOSYS", r.Name, r.Answer)
		}
		if r.Why == "" {
			return nil, fmt.Errorf("refused.json: %s: no why", r.Name)
		}
		if r.WhenArg0Any != "" {
			v, err := strconv.ParseUint(r.WhenArg0Any, 0, 32)
			if err != nil || v == 0 {
				return nil, fmt.Errorf("refused.json: %s: when_arg0_any %q: %v", r.Name, r.WhenArg0Any, err)
			}
			r.mask = uint32(v)
		}
	}
	if err := t.SelfCheck.parse(t.Requests); err != nil {
		return nil, fmt.Errorf("refused.json: self_check: %w", err)
	}
	for _, a := range t.Arches {
		seen := map[uint32]string{}
		for _, r := range t.Requests {
			n := r.Number(a)
			if n == 0 {
				return nil, fmt.Errorf("refused.json: %s has no %s number", r.Name, a.Name)
			}
			if n > t.Ceiling {
				return nil, fmt.Errorf("refused.json: %s is %d on %s, above the ceiling %d", r.Name, n, a.Name, t.Ceiling)
			}
			if o, dup := seen[n]; dup {
				return nil, fmt.Errorf("refused.json: %s and %s are both %d on %s", o, r.Name, n, a.Name)
			}
			seen[n] = r.Name
		}
	}
	return &t, nil
}

// parse checks c against the table's requests: it names a row that every filter refuses whole
// (no condition on its flags, not a tracing row), a first argument that is not 0, and an errno
// that is neither of the table's own answers and fits seccomp's errno field below the kernel's
// highest errno.
func (c *SelfCheck) parse(rs []Request) error {
	var row *Request
	for i := range rs {
		if rs[i].Name == c.Request {
			row = &rs[i]
		}
	}
	switch {
	case row == nil:
		return fmt.Errorf("request %q is not a row of the table", c.Request)
	case row.mask != 0 || row.Tracing:
		return fmt.Errorf("request %q is not refused whole by every filter", c.Request)
	case c.Errno == 0 || c.Errno > 4095 || c.Errno == errnos[EPERM] || c.Errno == errnos[ENOSYS]:
		return fmt.Errorf("errno %d is not a distinct errno below 4096", c.Errno)
	case c.ErrnoName == "" || c.ErrnoName == EPERM || c.ErrnoName == ENOSYS || c.ErrnoName == Kill || c.ErrnoName == Allow:
		return fmt.Errorf("errno_name %q is empty or one of the table's own answers", c.ErrnoName)
	case c.Why == "":
		return fmt.Errorf("no why")
	}
	v, err := strconv.ParseUint(c.Arg0Low, 0, 32)
	if err != nil || v == 0 {
		return fmt.Errorf("arg0_low %q: %v", c.Arg0Low, err)
	}
	c.arg0 = uint32(v)
	return nil
}

// Variant is one filter to generate: a machine, and whether the tracing rows are in it.
type Variant struct {
	Arch    Arch
	Tracing bool
	Suffix  string // "" or "_gvisor", appended to the file and array names
}

// Variants lists the filters the table makes, by decision 137's line: one per machine,
// with or without the tracing rows, or, for "gvisor", a plain one without them and a
// _gvisor one with them.
func (t *Table) Variants() []Variant {
	var vs []Variant
	for _, a := range t.Arches {
		switch t.TracingRefused {
		case TracingEverywhere:
			vs = append(vs, Variant{Arch: a, Tracing: true})
		case TracingNowhere:
			vs = append(vs, Variant{Arch: a})
		case TracingGVisor:
			vs = append(vs, Variant{Arch: a}, Variant{Arch: a, Tracing: true, Suffix: "_gvisor"})
		}
	}
	return vs
}

// Rows is the table's requests that variant v refuses.
func (t *Table) Rows(v Variant) []Request {
	var rs []Request
	for _, r := range t.Requests {
		if r.Tracing && !v.Tracing {
			continue
		}
		rs = append(rs, r)
	}
	return rs
}

// Decide is what variant v answers for request number nr with first argument arg0 through
// the entry whose seccomp_data.arch is arch, read from the table directly, not from the
// filter: the tests hold the generated filter to it, and the docker check holds a real
// kernel's answers to it. nr is the 32-bit number seccomp_data carries (the kernel drops
// the upper half of a 64-bit number; so does gVisor).
func (t *Table) Decide(v Variant, arch, nr uint32, arg0 uint64) string {
	switch {
	case arch != v.Arch.audit:
		return Kill
	case nr == 0xFFFFFFFF:
		return ENOSYS
	case v.Arch.x32 != 0 && nr&v.Arch.x32 != 0:
		return Kill
	}
	for _, r := range t.Rows(v) {
		if r.Number(v.Arch) != nr {
			continue
		}
		if r.mask != 0 && uint32(arg0)&r.mask == 0 {
			return Allow
		}
		if r.Name == t.SelfCheck.Request && uint32(arg0) == t.SelfCheck.arg0 {
			return t.SelfCheck.ErrnoName
		}
		return r.Answer
	}
	if nr > t.Ceiling {
		return ENOSYS
	}
	return Allow
}
