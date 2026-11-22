// Package settings is plimsolld's one table of settings: every environment variable the
// daemon and the providers it builds read, each declared once (registry.go) with its kind,
// its default and its -h text. Every reader reads a variable through its setting, so a
// variable is read by one rule wherever it is read (sandbox.Build and hardened mode once
// trimmed the same variable differently), plimsolld's -h is rendered from the table
// (Help), and a variable the table lacks is one the daemon does not read (Lookup). A
// kind's rule is the one the variable's first reader applied before the table existed.
//
// The package reads nothing itself: a reader passes its getenv, as sandbox.Build always
// has. Checks that depend on other settings (a burst against a rate, a mode against its
// options) stay with the reader; what one value is (a whole number, a boolean, trimmed or
// as given) is the kind's.
package settings

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Meta is what every setting declares.
type Meta struct {
	// Name is the environment variable.
	Name string
	// Default is what an unset variable reads as (Text, Trimmed, Int, Duration).
	Default string
	// Doc is the setting's -h entry, one line per line; the first is printed beside the
	// name. Leading spaces in a line are kept (an indented sub-item).
	Doc string
	// DocWith names the setting whose -h entry documents this one too ("A / B"); Doc is
	// then empty.
	DocWith string

	section *Section
}

// Var is any setting.
type Var interface{ meta() *Meta }

func (m *Meta) meta() *Meta { return m }

// NameOf is v's variable name.
func NameOf(v Var) string { return v.meta().Name }

// Raw is the variable exactly as set, for a message that quotes what the operator wrote.
func (m *Meta) Raw(getenv func(string) string) string { return getenv(m.Name) }

// Set reports whether the variable is set to anything but spaces.
func (m *Meta) Set(getenv func(string) string) bool { return strings.TrimSpace(getenv(m.Name)) != "" }

// Text is read as given, Default when empty: a value whose reader refuses what it
// cannot use (an image reference, a URL, a path).
type Text struct{ Meta }

// Get is the value as set, or Default.
func (s *Text) Get(getenv func(string) string) string {
	if v := getenv(s.Name); v != "" {
		return v
	}
	return s.Default
}

// Trimmed is read with surrounding spaces removed, Default when that leaves nothing.
type Trimmed struct{ Meta }

// Get is the trimmed value, or Default.
func (s *Trimmed) Get(getenv func(string) string) string {
	if v := strings.TrimSpace(getenv(s.Name)); v != "" {
		return v
	}
	return s.Default
}

// Lower is a name: trimmed and lower-cased, so "WASM" and " docker" select what they say.
type Lower struct{ Meta }

// Get is the trimmed, lower-cased value.
func (s *Lower) Get(getenv func(string) string) string {
	return strings.ToLower(strings.TrimSpace(getenv(s.Name)))
}

// Bool is an opt-in: unset, 0 or false is false, 1 or true is true (any case, spaces
// trimmed), and anything else is an error, so a typo can never silently turn a safety
// setting off.
type Bool struct{ Meta }

// Get parses the value.
func (s *Bool) Get(getenv func(string) string) (bool, error) {
	return ParseBool(s.Name, getenv(s.Name))
}

// ParseBool is Bool's rule for a variable named name whose value is raw.
func ParseBool(name, raw string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "0", "false":
		return false, nil
	case "1", "true":
		return true, nil
	default:
		return false, fmt.Errorf("%s must be one of 0, 1, false, or true", name)
	}
}

// Count is a whole number of at least 0 (spaces trimmed); unset is 0.
type Count struct{ Meta }

// Get parses the value.
func (s *Count) Get(getenv func(string) string) (int, error) {
	raw := strings.TrimSpace(getenv(s.Name))
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%s=%q must be a non-negative integer", s.Name, raw)
	}
	return n, nil
}

// Amount is a finite number of at least 0 (spaces trimmed); unset is 0.
type Amount struct{ Meta }

// Get parses the value.
func (s *Amount) Get(getenv func(string) string) (float64, error) {
	raw := strings.TrimSpace(getenv(s.Name))
	if raw == "" {
		return 0, nil
	}
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil || f < 0 || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, fmt.Errorf("%s=%q must be a finite non-negative number", s.Name, raw)
	}
	return f, nil
}

// Int is a whole number (spaces trimmed), Default when unset; the reader checks its range.
type Int struct{ Meta }

// Get parses the value; unset is Default (0 when Default is empty).
func (s *Int) Get(getenv func(string) string) (int, error) {
	def := 0
	if s.Default != "" {
		def = mustAtoi(s.Name, s.Default)
	}
	return s.GetOr(getenv, def)
}

// GetOr parses the value; unset is def, for a default that depends on another setting.
func (s *Int) GetOr(getenv func(string) string, def int) (int, error) {
	raw := strings.TrimSpace(getenv(s.Name))
	if raw == "" {
		return def, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s=%q must be an integer", s.Name, raw)
	}
	return n, nil
}

// Duration is a Go duration ("30m", "90s"; spaces trimmed), Default when unset.
type Duration struct{ Meta }

// Get parses the value.
func (s *Duration) Get(getenv func(string) string) (time.Duration, error) {
	raw := strings.TrimSpace(getenv(s.Name))
	if raw == "" {
		d, err := time.ParseDuration(s.Default)
		if err != nil {
			panic(fmt.Sprintf("settings: %s has default %q, not a duration", s.Name, s.Default))
		}
		return d, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s=%q must be a duration such as 30m or 90s", s.Name, raw)
	}
	return d, nil
}

// A Size is a setting a policy can require to be set and above zero (hardened mode's
// resource envelope).
type Size interface {
	Var
	// Positive reports whether the variable is set, and whether it reads as a number
	// above zero by its own kind's rule.
	Positive(getenv func(string) string) (set, positive bool)
}

// Positive implements Size.
func (s *Count) Positive(getenv func(string) string) (set, positive bool) {
	n, err := s.Get(getenv)
	return s.Set(getenv), err == nil && n > 0
}

// Positive implements Size.
func (s *Amount) Positive(getenv func(string) string) (set, positive bool) {
	f, err := s.Get(getenv)
	return s.Set(getenv), err == nil && f > 0
}

// Positive implements Size.
func (s *Int) Positive(getenv func(string) string) (set, positive bool) {
	n, err := s.GetOr(getenv, 0)
	return s.Set(getenv), err == nil && n > 0
}

// Unset is a getenv under which every variable is unset, so a setting read through it is
// its declared default: for code that must state a default without an environment (a
// service built without a limiter), so the default has one home, here.
func Unset(string) string { return "" }

// PerKeyConcurrentDefault is SANDBOX_PER_KEY_CONCURRENT's default on a daemon whose
// global concurrency is global: half of it, at least one ("default max/2").
func PerKeyConcurrentDefault(global int) int { return max(global/2, 1) }

func mustAtoi(name, v string) int {
	n, err := strconv.Atoi(v)
	if err != nil {
		panic(fmt.Sprintf("settings: %s has default %q, not a whole number", name, v))
	}
	return n
}

// A Section is one part of -h: an intro printed verbatim, then its settings in the
// order they are declared. A section with a Provider is printed only when the daemon
// has that provider (a daemon-built provider's file decides whether a build has it).
type Section struct {
	Name     string
	Provider string
	Intro    string
	vars     []*Meta
}

// sections is every section in -h order.
var sections []*Section

func section(name, provider, intro string) *Section {
	s := &Section{Name: name, Provider: provider, Intro: intro}
	sections = append(sections, s)
	return s
}

// byName is every setting by its variable's name, and all every setting as declared.
var (
	byName = map[string]*Meta{}
	all    []Var
)

func add[T Var](s *Section, v T) T {
	m := v.meta()
	if _, dup := byName[m.Name]; dup {
		panic("settings: " + m.Name + " declared twice")
	}
	m.section = s
	s.vars = append(s.vars, m)
	byName[m.Name] = m
	all = append(all, v)
	return v
}

func (s *Section) text(m Meta) *Text         { return add(s, &Text{m}) }
func (s *Section) trimmed(m Meta) *Trimmed   { return add(s, &Trimmed{m}) }
func (s *Section) lower(m Meta) *Lower       { return add(s, &Lower{m}) }
func (s *Section) bool(m Meta) *Bool         { return add(s, &Bool{m}) }
func (s *Section) count(m Meta) *Count       { return add(s, &Count{m}) }
func (s *Section) amount(m Meta) *Amount     { return add(s, &Amount{m}) }
func (s *Section) int(m Meta) *Int           { return add(s, &Int{m}) }
func (s *Section) duration(m Meta) *Duration { return add(s, &Duration{m}) }

// Lookup returns the provider whose section declares name ("" for one every build has)
// and whether any section does.
func Lookup(name string) (provider string, ok bool) {
	m, ok := byName[name]
	if !ok {
		return "", false
	}
	return m.section.Provider, true
}

// Names is every declared variable, sorted.
func Names() []string {
	names := make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// nameColumn is where an entry's text starts in -h; a name that does not fit before it
// is printed on a line of its own.
const nameColumn = 29

// Help is plimsolld's -h text: every section, those of providers has does not contain
// left out, with providers (the SANDBOX_PROVIDER values this build has) in place of
// {providers}.
func Help(providers []string, has func(provider string) bool) string {
	var b strings.Builder
	b.WriteString(helpHead)
	for _, s := range sections {
		if s.Provider != "" && !has(s.Provider) {
			continue
		}
		b.WriteString(s.Intro)
		for _, m := range s.vars {
			if m.DocWith != "" {
				continue
			}
			names := []string{m.Name}
			for _, o := range s.vars {
				if o.DocWith == m.Name {
					names = append(names, o.Name)
				}
			}
			lines := strings.Split(strings.ReplaceAll(m.Doc, "{providers}", strings.Join(providers, " | ")), "\n")
			head := "  " + strings.Join(names, " / ")
			if len(head) < nameColumn {
				fmt.Fprintf(&b, "%-*s%s\n", nameColumn, head, lines[0])
				lines = lines[1:]
			} else {
				b.WriteString(head + "\n")
			}
			for _, l := range lines {
				b.WriteString(strings.Repeat(" ", nameColumn) + l + "\n")
			}
		}
	}
	b.WriteString(helpFoot)
	return b.String()
}
