// Package withheld is the ship scan: before a call is dispatched, the daemon looks
// for what the operator has declared must never enter a sandbox (a harness's source,
// a hidden answer, a held-out seed) in everything the call carries into one. The
// operator declares it as a withheld set, a JSON file of SHA-256 digests
// (PLIMSOLL_WITHHELD_FILE), so the daemon never holds, logs or returns a withheld
// value. docs/ship-scan.md is the operator's account; this package is transport-free,
// so plimsolld and the plimsoll-withheld builder share every rule.
package withheld

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/plimsollmark/plimsoll/internal/printable"
	"github.com/plimsollmark/plimsoll/internal/settings/configfile"
)

// Mode is what a found entry does to the call.
type Mode string

const (
	// ModeRefuse refuses the call, not dispatched, naming the entry to the caller.
	ModeRefuse Mode = "refuse"
	// ModeAudit runs the call and names the entry on the operator's audit line alone.
	// A refusal tells the caller that a string is withheld, which is an oracle when the
	// caller relays it to the agent whose output was scanned.
	ModeAudit Mode = "audit"
)

func (m Mode) valid() bool { return m == ModeRefuse || m == ModeAudit }

// Kind is how an entry is matched.
type Kind string

const (
	// KindFile matches a whole file, or a snippet's or cell's code: its digest is of the
	// file's normalized form (Normalize), as the builder writes it, or of its bytes as
	// written, as sha256sum gives it (fileEntry).
	KindFile Kind = "file"
	// KindValue matches a string where it occupies whole runs of ASCII letters and
	// digits (Runs): its first byte starts a run and its last byte ends one. It is
	// matched in any ASCII letter case, so its digest is of the value lowercased
	// (ValueDigest), and in each of a part's views (views.go).
	KindValue Kind = "value"
	// KindSource matches a file holding enough of a file's distinctive lines
	// (source.go): a harness file shipped edited, reformatted or bundled.
	KindSource Kind = "source"
)

// Version is the set file's format version. Version 2 holds value digests of the
// lowercased value; a version 1 file is refused, since its digest of a value with an
// upper-case letter would never match.
const Version = 2

const (
	// MinValueBytes and MaxValueBytes bound a value entry's length. Under 4 bytes a
	// value is found in ordinary text by chance; the builder's default floor is
	// higher (DefaultMinValueBytes). Over 256 bytes it is a file's job.
	MinValueBytes = 4
	MaxValueBytes = 256
	// DefaultMinValueBytes is the builder's floor: a random 6-digit number is found as
	// a whole run of digits in about one unrelated number in 900,000.
	DefaultMinValueBytes = 6
	// MaxValueRuns bounds the runs of letters and digits a value may span ("2026-10-27"
	// is 3, a UUID 5). It bounds the scan's work: at most this many hashes per run.
	MaxValueRuns = 8
	// MaxLabelBytes bounds an entry's label.
	MaxLabelBytes = 128
)

// fileConfig is the set file as written.
type fileConfig struct {
	Version       int           `json:"version"`
	Mode          Mode          `json:"mode"`
	ExemptCallers []string      `json:"exempt_callers,omitempty"`
	Entries       []entryConfig `json:"entries"`
}

type entryConfig struct {
	Kind     Kind     `json:"kind"`
	SHA256   string   `json:"sha256,omitempty"`
	Length   int      `json:"length,omitempty"`
	Lines    []string `json:"lines,omitempty"`
	MinLines int      `json:"min_lines,omitempty"`
	Label    string   `json:"label"`
	Mode     Mode     `json:"mode,omitempty"`
}

// entry is what the scan reports. The file's entries of one label and one mode are one
// entry (a value and its forms, such as the builder's + for a space), so a report names
// the label once.
type entry struct {
	label string
	mode  Mode
}

// Set is a loaded withheld set. The zero value is not usable; a nil *Set scans nothing.
type Set struct {
	digest    string
	lines     int // entries in the file
	entries   []entry
	files     map[[sha256.Size]byte]int // file digest, normalized or as written -> entry
	values    map[[sha256.Size]byte]int // value digest -> entry
	lengths   [MaxValueBytes + 1]bool   // the value lengths declared
	maxLength int
	refuses   bool // an entry is in refuse mode
	exempt    map[string]bool
	// Source entries (source.go): each distinct line digest, the source entries that
	// hold it, and each entry's report and threshold.
	sourceLines map[[sha256.Size]byte]int
	lineEntries [][]int
	sources     []sourceEntry
	// fileModes is what lets a user other than the daemon's own or root change the file
	// Load read (configfile), nil when nothing does or the set was parsed from bytes.
	fileModes *configfile.Finding
}

// FileModes is what lets a user other than the daemon's own or root change the set file
// Load read, nil when nothing does; plimsolld refuses it in hardened mode and warns about
// it otherwise.
func (s *Set) FileModes() *configfile.Finding {
	if s == nil {
		return nil
	}
	return s.fileModes
}

// Load reads and validates the set file at path.
func Load(path string) (*Set, error) {
	raw, modes, err := configfile.Read(path)
	if err != nil {
		return nil, fmt.Errorf("withheld: read %s: %w", path, err)
	}
	s, err := Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("withheld: %s: %w", path, err)
	}
	s.fileModes = modes
	return s, nil
}

// Parse validates a set file's bytes. Anything it does not understand is an error:
// a set that loads with a typo in it scans for less than the operator believes.
func Parse(raw []byte) (*Set, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var cfg fileConfig
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("parse: data after the set")
	}
	if cfg.Version != Version {
		return nil, fmt.Errorf("version must be %d", Version)
	}
	if !cfg.Mode.valid() {
		return nil, fmt.Errorf("mode must be %q or %q", ModeRefuse, ModeAudit)
	}
	if len(cfg.Entries) == 0 {
		return nil, errors.New("the set has no entries, so it would scan for nothing")
	}
	sum := sha256.Sum256(raw)
	s := &Set{
		digest:      hex.EncodeToString(sum[:]),
		lines:       len(cfg.Entries),
		files:       map[[sha256.Size]byte]int{},
		values:      map[[sha256.Size]byte]int{},
		exempt:      map[string]bool{},
		sourceLines: map[[sha256.Size]byte]int{},
	}
	reported := map[entry]int{} // label and mode -> index in entries
	for _, id := range cfg.ExemptCallers {
		if id == "" || id == "*" || id != strings.TrimSpace(id) || !utf8.ValidString(id) || strings.ContainsFunc(id, unicode.IsControl) {
			return nil, fmt.Errorf("exempt_callers: %q is not a caller ID (nonempty, not \"*\", no surrounding space or control characters)", id)
		}
		if s.exempt[id] {
			return nil, fmt.Errorf("exempt_callers: %q is listed twice", id)
		}
		s.exempt[id] = true
	}
	for i, e := range cfg.Entries {
		if err := CheckLabel(e.Label); err != nil {
			return nil, fmt.Errorf("entry %d: %w", i, err)
		}
		mode := e.Mode
		if mode == "" {
			mode = cfg.Mode
		}
		if !mode.valid() {
			return nil, fmt.Errorf("entry %d (%s): mode must be empty, %q or %q", i, e.Label, ModeRefuse, ModeAudit)
		}
		r := entry{label: e.Label, mode: mode}
		report := func() int {
			at, ok := reported[r]
			if !ok {
				at = len(s.entries)
				reported[r] = at
				s.entries = append(s.entries, r)
			}
			s.refuses = s.refuses || mode == ModeRefuse
			return at
		}
		if e.Kind == KindSource {
			if e.SHA256 != "" || e.Length != 0 {
				return nil, fmt.Errorf("entry %d (%s): a source entry states lines and min_lines, not a sha256 or a length", i, e.Label)
			}
			if len(e.Lines) < MinSourceLines {
				return nil, fmt.Errorf("entry %d (%s): a source entry holds at least %d lines", i, e.Label, MinSourceLines)
			}
			if e.MinLines < MinSourceLines || e.MinLines > len(e.Lines) {
				return nil, fmt.Errorf("entry %d (%s): min_lines must be %d to the entry's %d lines", i, e.Label, MinSourceLines, len(e.Lines))
			}
			mine := make(map[[sha256.Size]byte]bool, len(e.Lines))
			src := len(s.sources)
			for _, h := range e.Lines {
				d, err := digestOf(h)
				if err != nil {
					return nil, fmt.Errorf("entry %d (%s): lines: %w", i, e.Label, err)
				}
				if mine[d] {
					return nil, fmt.Errorf("entry %d (%s): a line digest is listed twice", i, e.Label)
				}
				mine[d] = true
				at, ok := s.sourceLines[d]
				if !ok {
					at = len(s.lineEntries)
					s.sourceLines[d] = at
					s.lineEntries = append(s.lineEntries, nil)
				}
				s.lineEntries[at] = append(s.lineEntries[at], src)
			}
			s.sources = append(s.sources, sourceEntry{report: report(), minLines: e.MinLines})
			continue
		}
		if len(e.Lines) > 0 || e.MinLines != 0 {
			return nil, fmt.Errorf("entry %d (%s): only a source entry states lines", i, e.Label)
		}
		d, err := digestOf(e.SHA256)
		if err != nil {
			return nil, fmt.Errorf("entry %d (%s): %w", i, e.Label, err)
		}
		var table map[[sha256.Size]byte]int
		switch e.Kind {
		case KindFile:
			if e.Length != 0 {
				return nil, fmt.Errorf("entry %d (%s): a file entry states no length", i, e.Label)
			}
			if blankFile[d] {
				return nil, fmt.Errorf("entry %d (%s): a file entry for empty or blank content would match every such file a caller ships", i, e.Label)
			}
			table = s.files
		case KindValue:
			if e.Length < MinValueBytes || e.Length > MaxValueBytes {
				return nil, fmt.Errorf("entry %d (%s): a value's length must be %d to %d bytes", i, e.Label, MinValueBytes, MaxValueBytes)
			}
			s.lengths[e.Length] = true
			s.maxLength = max(s.maxLength, e.Length)
			table = s.values
		default:
			return nil, fmt.Errorf("entry %d (%s): kind must be %q, %q or %q", i, e.Label, KindFile, KindValue, KindSource)
		}
		if _, dup := table[d]; dup {
			return nil, fmt.Errorf("entry %d (%s): the same %s digest is listed twice", i, e.Label, e.Kind)
		}
		table[d] = report()
	}
	return s, nil
}

// digestOf reads a digest as the set file writes it: 64 lowercase hex characters.
func digestOf(h string) (d [sha256.Size]byte, err error) {
	if len(h) != 2*sha256.Size || strings.ToLower(h) != h {
		return d, errors.New("sha256 must be 64 lowercase hex characters")
	}
	if _, err := hex.Decode(d[:], []byte(h)); err != nil {
		return d, errors.New("sha256 must be 64 lowercase hex characters")
	}
	return d, nil
}

// blankFile holds the digests of content made of whitespace alone: normalized (one
// digest, of empty content, whatever the length) and as written, every string of spaces,
// tabs, carriage returns and newlines up to blankBytes long, as sha256sum gives a blank
// file's digest ("\n", "\r\n", "\n\n"). An entry holding one would match every such file
// a caller ships, such as an __init__.py of one newline. A blank file longer than that,
// hashed by hand, is not refused: its entry finds files of exactly those bytes, which a
// caller rarely ships, and the refusal names the entry.
var blankFile = func() map[[sha256.Size]byte]bool {
	m := map[[sha256.Size]byte]bool{FileDigest(nil): true}
	var add func(prefix []byte)
	add = func(prefix []byte) {
		m[sha256.Sum256(prefix)] = true
		if len(prefix) == blankBytes {
			return
		}
		for _, c := range []byte(" \t\r\n") {
			add(append(prefix, c))
		}
	}
	add(make([]byte, 0, blankBytes))
	return m
}()

// blankBytes is the longest blank content blankFile holds as written: 4 covers two
// Windows line endings, 341 digests.
const blankBytes = 4

// CheckLabel validates an entry's label: [A-Za-z0-9._:/-], 1 to MaxLabelBytes bytes.
// Every report names entries by label, so a label is a token a log line can carry
// as it is.
func CheckLabel(label string) error {
	if label == "" || len(label) > MaxLabelBytes {
		return fmt.Errorf("label must be 1 to %d bytes", MaxLabelBytes)
	}
	for i := 0; i < len(label); i++ {
		if c := label[i]; !word(c) && !strings.ContainsRune("._:/-", rune(c)) {
			return fmt.Errorf("label %q may contain only letters, digits and . _ : / -", label)
		}
	}
	return nil
}

// Digest is the SHA-256 of the set file as loaded, in hex.
func (s *Set) Digest() string { return s.digest }

// Len is the number of entries in the set file.
func (s *Set) Len() int { return s.lines }

// Entry is one entry as a scan reports it: its label and mode. Entries of the set file
// with the same label and mode (a value and its forms) are one Entry.
type Entry struct {
	Label string
	Mode  Mode
}

// Entries lists the set's entries as a scan reports them, in the set's order.
func (s *Set) Entries() []Entry {
	out := make([]Entry, len(s.entries))
	for i, e := range s.entries {
		out[i] = Entry{Label: e.label, Mode: e.mode}
	}
	return out
}

// Refuses reports whether any entry is in refuse mode. Such a set refuses a call whose
// scan is incomplete, since what the scan could not read may hold a refuse-mode entry.
func (s *Set) Refuses() bool { return s.refuses }

// ExemptCount is the number of exempt callers.
func (s *Set) ExemptCount() int { return len(s.exempt) }

// Exempt reports whether caller (an authenticated caller's ID) is on the set's exempt
// list. An empty ID, an unauthenticated call's, is never exempt.
func (s *Set) Exempt(caller string) bool { return caller != "" && s.exempt[caller] }

// CleanWhere makes text safe to print in a Where: printable.Text, the one rule plimsoll
// prints outside text by (each control character, ESC and the C1 range included, so a
// terminal never reads an escape sequence out of a file name, and each line or paragraph
// separator, bidirectional control and byte that is not UTF-8 becomes an escape such as
// \x1b). A name in an image or a directory comes from whoever built it, so the scans clean
// it where they build a Where and Scan cleans every Part's, and every consumer (the
// command's output, the daemon's log) gets text that cannot rewrite a screen or forge a log
// line. The escapes hold no such character, so cleaning twice changes nothing.
func CleanWhere(s string) string { return printable.Text(s) }

// needsEscape is the set CleanWhere escapes.
func needsEscape(r rune) bool { return printable.Escaped(r) }

// Part is one piece of what a call carries into its sandbox.
type Part struct {
	// Where names it in the request's own terms: "code", "files[2].content",
	// "files[2].path", "steps[0]", "artifacts[1]". Never the caller's text.
	Where string
	Data  []byte
	// Whole: the part is a whole file (a file's content, a snippet's or cell's code),
	// so file entries are checked against it too.
	Whole bool
}

// Finding is one entry found in a call.
type Finding struct {
	Label string
	Mode  Mode
	Where []string // in the order the parts were given, each once
}

// Result is what a scan found.
type Result struct {
	// Found holds the entries found, in the set's order, each with where it was found.
	Found []Finding
	// Incomplete holds the parts whose archives the scan could not read whole, each
	// with the bound it reached or what it could not read, in the parts' order. What it read before the bound is
	// scanned, so a find there is in Found.
	Incomplete []Incomplete
}

// Scan looks for every entry in parts, and in the archives they hold (archive.go). It
// stops with ctx's error when ctx ends, checked between parts and between archives and
// their members; the scan is bounded by bytes and counts, never by time, so a call is
// scanned the same on a loaded machine as on an idle one.
func (s *Set) Scan(ctx context.Context, parts []Part) (Result, error) {
	res, _, err := s.scan(ctx, parts)
	return res, err
}

// scan is Scan, and the scanner it used, whose counts a test reads.
func (s *Set) scan(ctx context.Context, parts []Part) (Result, *scanner, error) {
	where := make([][]string, len(s.entries))
	sc := &scanner{set: s, ctx: ctx}
	var res Result
	for _, p := range parts {
		if err := ctx.Err(); err != nil {
			return Result{}, sc, err
		}
		at := CleanWhere(p.Where)
		sc.found = func(i int) {
			if n := len(where[i]); n == 0 || where[i][n-1] != at {
				where[i] = append(where[i], at)
			}
		}
		sc.hit = func(b Bound) {
			for k := len(res.Incomplete) - 1; k >= 0 && res.Incomplete[k].Where == at; k-- {
				if res.Incomplete[k].Bound == b {
					return
				}
			}
			res.Incomplete = append(res.Incomplete, Incomplete{Where: at, Bound: b})
		}
		if p.Whole {
			sc.file(p.Data)
		}
		sc.views(p.Data, 0)
		if sc.stopped {
			return Result{}, sc, ctx.Err()
		}
	}
	for i, ats := range where {
		if len(ats) > 0 {
			res.Found = append(res.Found, Finding{Label: s.entries[i].label, Mode: s.entries[i].mode, Where: ats})
		}
	}
	return res, sc, nil
}

// viewKind is which of a part's views a slice is.
type viewKind int

const (
	viewWritten viewKind = iota
	viewEscapes
	viewBase64
)

// scanViews scans data in its views (views.go): values as written and with its
// escapes decoded, and values and whole files in each base64 blob decoded. It calls
// view, when not nil, with each view (and, for the escapes view, the bytes an escape
// produced), so archives are looked for in every one. It returns the hashes it
// computed for values and blobs: at most MaxValueRuns per run of letters and digits in
// each view, and one per blob for the file entries.
func (s *Set) scanViews(data []byte, found func(int), view func(v []byte, k viewKind, escaped bitset)) (hashes int) {
	values := len(s.values) > 0
	if values {
		hashes += s.scanValues(data, found)
	}
	if view != nil {
		view(data, viewWritten, nil)
	}
	if values || view != nil {
		if u, escaped, ok := unescape(data); ok {
			if values {
				hashes += s.scanValues(u, found)
			}
			if view != nil {
				view(u, viewEscapes, escaped)
			}
		}
	}
	base64Blobs(data, func(blob []byte) {
		if len(s.files) > 0 {
			i, ok, n := s.fileEntry(blob)
			hashes += n
			if ok {
				found(i)
			}
		}
		if values {
			hashes += s.scanValues(blob, found)
		}
		if view != nil {
			view(blob, viewBase64, nil)
		}
	})
	return hashes
}

// scanValues hashes every span of 1 to MaxValueRuns whole runs of letters and digits
// whose length is a declared value length, lowercased, and reports each value found.
// It keeps the starts of the last MaxValueRuns runs and, at each run's end, tries the
// spans ending there: at most MaxValueRuns hashes per run, whatever the set holds. It
// returns the hashes it computed.
func (s *Set) scanValues(data []byte, found func(int)) (hashes int) {
	var starts [MaxValueRuns]int
	var span [MaxValueBytes]byte
	runs := 0
	for i := 0; i < len(data); {
		if !word(data[i]) {
			i++
			continue
		}
		start := i
		for i < len(data) && word(data[i]) {
			i++
		}
		starts[runs%MaxValueRuns] = start
		runs++
		for k := 0; k < MaxValueRuns && k < runs; k++ {
			n := i - starts[(runs-1-k)%MaxValueRuns]
			if n > s.maxLength {
				break
			}
			if !s.lengths[n] {
				continue
			}
			hashes++
			if e, ok := s.values[sha256.Sum256(lower(span[:n], data[i-n:i]))]; ok {
				found(e)
			}
		}
	}
	return hashes
}

// lower writes src into dst (as long as src) with its ASCII letters lowercased.
func lower(dst, src []byte) []byte {
	for i, c := range src {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		dst[i] = c
	}
	return dst
}

// ValueDigest is the digest a value entry holds for v: the SHA-256 of v with its ASCII
// letters lowercased, since a value is matched in any letter case.
func ValueDigest(v []byte) [sha256.Size]byte {
	return sha256.Sum256(lower(make([]byte, len(v)), v))
}

// word is an ASCII letter or digit: what a value's runs are made of.
func word(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// Normalize is a file's form for file entries: every line's trailing spaces, tabs and
// carriage returns dropped, and the newlines at the end dropped, so a copy that
// differs only in line endings or trailing whitespace has the same digest.
func Normalize(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for line := range bytes.SplitAfterSeq(b, []byte("\n")) {
		body, nl := bytes.CutSuffix(line, []byte("\n"))
		out = append(out, bytes.TrimRight(body, " \t\r")...)
		if nl {
			out = append(out, '\n')
		}
	}
	return bytes.TrimRight(out, "\n")
}

// FileDigest is the digest the builder writes in a file entry for content: the SHA-256 of
// Normalize.
func FileDigest(content []byte) [sha256.Size]byte { return sha256.Sum256(Normalize(content)) }

// fileEntry is the file entry content matches, by the digest of its normalized form or of
// its bytes as written, and the hashes it computed (1 or 2). The bytes as written are
// matched because an operator who writes an entry by hand takes a file's digest with
// sha256sum, and nearly every text file ends in a newline Normalize drops: matched on its
// normalized form alone, such an entry loaded without a word and found nothing, not even
// the file it was taken of, shipped byte for byte (the no-leak demo, 2026-11-26). The
// second match adds nothing to an entry the builder wrote: content's own digest equals a
// normalized digest only when content is that normalized form, which Normalize leaves as
// it is, so the first match found it already. When Normalize removed nothing the two
// digests are one, and it is computed once.
func (s *Set) fileEntry(content []byte) (entry int, ok bool, hashes int) {
	n := Normalize(content)
	if entry, ok = s.files[sha256.Sum256(n)]; ok || len(n) == len(content) {
		return entry, ok, 1
	}
	entry, ok = s.files[sha256.Sum256(content)]
	return entry, ok, 2
}

// AsWrittenOnly reports the file entry content matches by its bytes as written and not by
// its normalized form: an entry hashed by hand (sha256sum) rather than by the builder. It
// finds only that copy byte for byte; the same file with other line endings, trailing
// whitespace or no final newline passes it. Nothing in a digest says which form was
// hashed, so only a reader holding the file can tell (plimsoll-withheld check).
func (s *Set) AsWrittenOnly(content []byte) (Entry, bool) {
	n := Normalize(content)
	if len(n) == len(content) {
		return Entry{}, false // one form: the builder's digest and sha256sum's are the same
	}
	if _, ok := s.files[sha256.Sum256(n)]; ok {
		return Entry{}, false
	}
	i, ok := s.files[sha256.Sum256(content)]
	if !ok {
		return Entry{}, false
	}
	return Entry{Label: s.entries[i].label, Mode: s.entries[i].mode}, true
}

// Runs counts the runs of ASCII letters and digits in v.
func Runs(v []byte) int {
	n := 0
	for i := range v {
		if word(v[i]) && (i == 0 || !word(v[i-1])) {
			n++
		}
	}
	return n
}

// CheckValue reports whether v can be a value entry the scan finds: minLength to
// MaxValueBytes bytes, beginning and ending with an ASCII letter or digit, spanning at
// most MaxValueRuns runs. The daemon cannot check this from a digest, so the builder
// does; a value outside it would never be found.
func CheckValue(v []byte, minLength int) error {
	switch {
	case minLength < MinValueBytes:
		return fmt.Errorf("the minimum value length is %d bytes", MinValueBytes)
	case len(v) < minLength:
		return fmt.Errorf("a value must be at least %d bytes (shorter ones are found in unrelated text by chance)", minLength)
	case len(v) > MaxValueBytes:
		return fmt.Errorf("a value must be at most %d bytes (a longer one is a file entry's job)", MaxValueBytes)
	case !word(v[0]) || !word(v[len(v)-1]):
		return errors.New("a value must begin and end with an ASCII letter or digit (it is found where it occupies whole runs of them)")
	case Runs(v) > MaxValueRuns:
		return fmt.Errorf("a value may span at most %d runs of letters and digits", MaxValueRuns)
	}
	return nil
}
