// Package outsidefacts is the one table of the facts about other people's software that
// plimsoll's code rests on, and the scan that finds code resting on such a fact with no row.
//
// A fact here is something plimsoll does not own and cannot make true: the words another
// program prints, the exit code it uses, the shape of its version string, the place it keeps a
// file, the format of what it answers, a number that has to match a number in someone else's
// code, a name a framework keeps private. Code that rests on one works until its owner changes
// it, and then either refuses (fails closed) or goes on wrongly (fails open). Each row of
// facts.json says, for one place in the code: the fact, who owns it and at which version it
// was read, what the code does when the fact is wrong, and which test runs the real thing.
//
// The check (outsidefacts_test.go) runs in the ordinary gate. It fails for code of a scanned
// shape that no row answers, for a row whose file or symbol is gone, and for a test that waits a
// fixed time with no reason beside the wait. rules.md states the rules; `go run
// ./internal/outsidefacts/list` prints every site with its row, and a row to copy for each
// site that has none.
package outsidefacts

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

//go:embed facts.json
var factsJSON []byte

// LocalFile is the name of the table's second file, beside facts.json. It holds the rows for
// code a copy of the repository keeps to itself, and what was measured on a hosted service's
// machines; a copy without such code has no such file.
const LocalFile = "facts.local.json"

// A Row is one place that rests on an outside fact.
type Row struct {
	// ID names the row; unique across the table.
	ID string `json:"id"`
	// File is repository-relative; Symbol is the top-level declaration in it (Func,
	// Type.Method, a var or const), never a line number, which moves. For a file that is not
	// Go, Symbol is a word that occurs in the file.
	File   string `json:"file"`
	Symbol string `json:"symbol"`
	// Shapes are the scanned shapes this row answers at that symbol; empty for a place the scan
	// cannot see (a format read by a decoder, a number, a framework's private name).
	Shapes []string `json:"shapes,omitempty"`
	// Kind is what sort of fact: KindNames lists them.
	Kind string `json:"kind"`
	// Fact is the thing relied on, in one or two sentences.
	Fact string `json:"fact"`
	// Owner is whose fact it is (the program, library or service); Version is the version it
	// was read at, or what pins it.
	Owner   string `json:"owner"`
	Version string `json:"version"`
	// Read says when and how the fact was learned: measured (and by what), or read (and where).
	Read string `json:"read"`
	// Fails is what the code does when the fact is wrong: FailsNames lists the answers.
	// Refusal is the refusal's words, or what happens instead.
	Fails   string `json:"fails"`
	Refusal string `json:"refusal"`
	// RealTest is the test that runs the real thing, as "path::Name" ("path::*" for a file
	// whose tests do so together), or "none: " and why.
	RealTest string `json:"real_test"`
	// Boundary is "allow-list" or "refuse-list" for a place that decides what may pass, else "none".
	Boundary string `json:"boundary"`
	// Number, for a number that must match one elsewhere: "derived" from its owner, "tested"
	// against it, or "copied"; else "none".
	Number string `json:"number"`
	// Value is the fact itself, where it is one string a local stand-in for the other
	// program needs (the file it writes, the words it prints). A stand-in reads it with Value,
	// and a test holds the product's own copy to it, so a changed fact changes the stand-in
	// and fails the product's test until the product is read against it again.
	Value string `json:"value,omitempty"`
	// Hosted marks a fact about a hosted service's machines, which only a call to that service
	// can measure again; what that call is and costs is in the local file.
	Hosted bool `json:"hosted,omitempty"`
	// Finding is the finding that tracks what is wrong here, when something is.
	Finding string `json:"finding,omitempty"`
	// Note is anything else a reader needs.
	Note string `json:"note,omitempty"`
}

// HostedFact is what a copy of the repository records about re-measuring a hosted fact.
type HostedFact struct {
	// Measured is when and how the fact was last measured on the service.
	Measured string `json:"measured"`
	// Remeasure is the command that measures it again; Cost is what that run costs.
	Remeasure string `json:"remeasure"`
	Cost      string `json:"cost"`
}

// A Table is facts.json, with the local file's rows and hosted measurements when there is one.
type Table struct {
	Rows []Row `json:"rows"`
	// Hosted is by row ID; only the local file carries it.
	Hosted map[string]HostedFact `json:"hosted,omitempty"`
	// local counts the rows that came from the local file (they follow the public ones).
	local int
}

// KindNames are the kinds of fact a row can state.
var KindNames = map[string]string{
	"words":         "the words another program prints or puts in an error",
	"exit-code":     "the exit code another program uses",
	"version":       "the shape or meaning of a version string",
	"format":        "the format of what another program or service answers or stores",
	"file-place":    "where another program keeps a file, or what it leaves there",
	"number":        "a number that has to match a number someone else owns",
	"price":         "what a service charges",
	"private-api":   "a name or behavior a library does not promise",
	"behavior":      "what another program does, beyond its words and numbers",
	"provider-name": "a provider treated specially by name",
	"wait":          "a fixed wait in a test, in a file whose marker could not be added",
}

// FailsNames are the answers to "what happens when the fact is wrong".
var FailsNames = map[string]string{
	"closed":         "refuses or errors, saying what is wrong",
	"wrong-error":    "refuses, but with an error that names the wrong cause or none",
	"open":           "goes on: does what it was meant to stop, or passes a check it should fail",
	"not-applicable": "nothing to refuse (a provider-name row, a test's wait)",
}

var idShape = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

// Load reads the table: the embedded facts.json and, when dir holds one, the local file.
// dir is this package's directory in a checkout; "" reads the embedded file alone.
func Load(dir string) (*Table, error) {
	var t Table
	if err := decodeStrict(factsJSON, &t); err != nil {
		return nil, fmt.Errorf("facts.json: %w", err)
	}
	if len(t.Hosted) != 0 {
		return nil, errors.New("facts.json: hosted measurements belong in " + LocalFile)
	}
	if dir == "" {
		return &t, nil
	}
	raw, err := os.ReadFile(filepath.Join(dir, LocalFile))
	if errors.Is(err, os.ErrNotExist) {
		return &t, nil
	}
	if err != nil {
		return nil, err
	}
	var local Table
	if err := decodeStrict(raw, &local); err != nil {
		return nil, fmt.Errorf("%s: %w", LocalFile, err)
	}
	t.Rows = append(t.Rows, local.Rows...)
	t.Hosted, t.local = local.Hosted, len(local.Rows)
	return &t, nil
}

var (
	valuesOnce sync.Once
	values     map[string]string
)

// Value is the value of the published row id: what a local stand-in for another program reads
// in place of a copy of its own. It panics for an id with no value, since a stand-in built on
// a missing fact models nothing.
func Value(id string) string {
	valuesOnce.Do(func() {
		values = map[string]string{}
		t, err := Load("")
		if err != nil {
			panic("outsidefacts: " + err.Error())
		}
		for _, r := range t.Rows {
			if r.Value != "" {
				values[r.ID] = r.Value
			}
		}
	})
	v, ok := values[id]
	if !ok {
		panic("outsidefacts: no row " + id + " with a value in facts.json")
	}
	return v
}

// PublicRows are the rows of facts.json; LocalRows are the local file's.
func (t *Table) PublicRows() []Row { return t.Rows[:len(t.Rows)-t.local] }

// LocalRows are the rows that came from the local file.
func (t *Table) LocalRows() []Row { return t.Rows[len(t.Rows)-t.local:] }

func decodeStrict(raw []byte, into any) error {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("more than one JSON value")
	}
	return nil
}

// Validate checks every row's own fields, and that no two rows share an ID. It reads no file.
func (t *Table) Validate() []error {
	var errs []error
	seen := map[string]bool{}
	shapes := map[string]bool{}
	for _, s := range Shapes {
		shapes[s] = true
	}
	for i, r := range t.Rows {
		bad := func(format string, args ...any) {
			errs = append(errs, fmt.Errorf("row %d (%s): %s", i, r.ID, fmt.Sprintf(format, args...)))
		}
		if !idShape.MatchString(r.ID) {
			bad("id must be lower-case words joined by hyphens")
		}
		if seen[r.ID] {
			bad("id is used twice")
		}
		seen[r.ID] = true
		for name, v := range map[string]string{"file": r.File, "symbol": r.Symbol, "fact": r.Fact, "owner": r.Owner, "version": r.Version, "read": r.Read, "refusal": r.Refusal} {
			if strings.TrimSpace(v) == "" {
				bad("%s is empty", name)
			}
		}
		if _, ok := KindNames[r.Kind]; !ok {
			bad("kind %q is not one of the kinds (KindNames)", r.Kind)
		}
		if _, ok := FailsNames[r.Fails]; !ok {
			bad("fails %q is not closed, wrong-error, open or not-applicable", r.Fails)
		}
		for _, s := range r.Shapes {
			if !shapes[s] {
				bad("shape %q is not a scanned shape (Shapes)", s)
			}
		}
		if r.Boundary != "allow-list" && r.Boundary != "refuse-list" && r.Boundary != "none" {
			bad("boundary %q is not allow-list, refuse-list or none", r.Boundary)
		}
		if r.Number != "derived" && r.Number != "tested" && r.Number != "copied" && r.Number != "none" {
			bad("number %q is not derived, tested, copied or none", r.Number)
		}
		if _, _, ok := splitTest(r.RealTest); !ok && !(strings.HasPrefix(r.RealTest, "none: ") && len(r.RealTest) > len("none: ")) {
			bad("real_test is %q: write path::Name, or \"none: \" and why", r.RealTest)
		}
		if r.Fails == "open" && r.Finding == "" {
			bad("a place that fails open names the finding that tracks it")
		}
	}
	for id := range t.Hosted {
		if !seen[id] {
			errs = append(errs, fmt.Errorf("hosted measurement %q: no row has that id", id))
		}
	}
	return errs
}

// Current checks every row against the tree under root (the repository's top directory): its
// file is there, a Go file declares its symbol (any other file contains it), and the file its
// test names is there and holds the test's name. A table that keeps rows for code that moved
// says nothing about the code that replaced it.
func (t *Table) Current(root string) []error {
	var errs []error
	sources := map[string][]byte{}
	read := func(rel string) ([]byte, bool) {
		if src, ok := sources[rel]; ok {
			return src, src != nil
		}
		src, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			sources[rel] = nil
			return nil, false
		}
		sources[rel] = src
		return src, true
	}
	for _, r := range t.Rows {
		src, ok := read(r.File)
		if !ok {
			errs = append(errs, fmt.Errorf("row %s: file %s is not there; move the row to where the code went, or delete it with the code", r.ID, r.File))
			continue
		}
		if strings.HasSuffix(r.File, ".go") {
			names, err := Symbols(r.File, src)
			if err != nil {
				errs = append(errs, fmt.Errorf("row %s: %w", r.ID, err))
			} else if !names[r.Symbol] {
				errs = append(errs, fmt.Errorf("row %s: %s declares no %s; name the declaration the code is in now (Func, Type.Method, a var or const)", r.ID, r.File, r.Symbol))
			}
		} else if !strings.Contains(string(src), r.Symbol) {
			errs = append(errs, fmt.Errorf("row %s: %s does not contain %q; name a word that marks the place", r.ID, r.File, r.Symbol))
		}
		if path, name, ok := splitTest(r.RealTest); ok {
			if tsrc, ok := read(path); !ok {
				errs = append(errs, fmt.Errorf("row %s: its test file %s is not there", r.ID, path))
			} else if name != "*" && !strings.Contains(string(tsrc), name) {
				errs = append(errs, fmt.Errorf("row %s: %s holds no %s", r.ID, path, name))
			}
		}
	}
	return errs
}

// Unanswering returns the rows that claim to answer a scanned shape at a place where the scan
// (sites) finds none: the code changed and the row stayed.
func (t *Table) Unanswering(sites []Site) []error {
	found := map[string]bool{}
	for _, s := range sites {
		found[s.Key()] = true
	}
	var errs []error
	for _, r := range t.Rows {
		for _, shape := range r.Shapes {
			if !found[Site{File: r.File, Symbol: r.Symbol, Shape: shape}.Key()] {
				errs = append(errs, fmt.Errorf("row %s: the scan finds no %s in %s of %s any more; drop the shape from the row, or the row", r.ID, shape, r.Symbol, r.File))
			}
		}
	}
	return errs
}

// splitTest takes "path::Name" apart.
func splitTest(s string) (path, name string, ok bool) {
	path, name, ok = strings.Cut(s, "::")
	return path, name, ok && path != "" && name != "" && !strings.ContainsAny(s, " \t")
}

// Covers reports whether some row answers the site.
func (t *Table) Covers(s Site) bool {
	for _, r := range t.Rows {
		if r.File != s.File || r.Symbol != s.Symbol {
			continue
		}
		for _, shape := range r.Shapes {
			if shape == s.Shape {
				return true
			}
		}
	}
	return false
}

// Skeleton is a row to copy for a site that has none: its file, symbol and shape filled in.
func Skeleton(s Site) string {
	kind := map[string]string{ShapeErrorText: "words", ShapeOutputText: "words", ShapeExitCode: "exit-code", ShapeVersionParse: "version", ShapeProviderName: "provider-name", ShapePlatformCase: "behavior", ShapeFixedWait: "wait"}[s.Shape]
	row := Row{
		ID: "name-this-row", File: s.File, Symbol: s.Symbol, Shapes: []string{s.Shape}, Kind: kind,
		Fact: "what is relied on", Owner: "whose fact it is", Version: "the version it was read at",
		Read: "when and how it was learned", Fails: "closed", Refusal: "the refusal's words",
		RealTest: "none: why no test runs the real thing", Boundary: "none", Number: "none",
	}
	out, _ := json.MarshalIndent(row, "    ", "  ")
	return "    " + string(out)
}
