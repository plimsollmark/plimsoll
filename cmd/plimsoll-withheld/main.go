// Command plimsoll-withheld builds a withheld set for plimsolld's ship scan
// (PLIMSOLL_WITHHELD_FILE) from the files and values that must never enter a sandbox,
// and scans a directory against a set offline. It writes digests, never a value, and
// never contacts a daemon. docs/ship-scan.md is the operator's account.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/plimsollmark/plimsoll/internal/withheld"
)

const usage = `Usage:
  plimsoll-withheld build -mode MODE [-exempt ID ...] [-file PATH ...] [-source PATH ...]
                          [-values PATH ...] [-files-mode MODE] [-source-mode MODE]
                          [-values-mode MODE] [-min-length N]
      Write a withheld set to stdout. A -file PATH is a file, or a directory whose
      regular files are each added, matched whole (after line endings and trailing
      whitespace are normalized); each is labeled by its path from PATH's parent
      (-file /srv/harness labels /srv/harness/sim.py as harness/sim.py), since a
      refusal shows the caller the label. Symbolic links are not followed, and an
      empty file is skipped (it would match every empty file). A -source PATH is
      labeled the same way, and each of its files is found when a shipped file holds
      a third of its distinctive lines (24 bytes or longer with spaces removed, not
      a comment; at least 8 of them), so an edited, reformatted or bundled copy is
      found; a file with fewer than 8 such lines is skipped. Its entries are in audit
      mode unless -source-mode says otherwise: in refuse mode a refusal tells the
      caller its file holds enough of the harness's lines, which an agent holding
      some of them could use to test guesses at the rest. A -values PATH holds
      one value per line (a seed, a hidden answer, a key; blank lines and lines
      starting with # are skipped), each found where it occupies whole runs of
      letters and digits, in any letter case, as written, URL-encoded or escaped in
      a string, or inside base64; a value holding a space is also withheld with +
      for the space, as form encoding writes it. MODE is refuse (the
      call is refused and the caller told) or audit (the call runs and only the
      operator's audit line names the find): -mode is the set's, -files-mode and
      -values-mode override it for those entries. -exempt names a caller (from PLIMSOLL_CLIENTS_FILE) that is not
      scanned, such as the judge that ships the hidden cases. -min-length is the
      shortest value accepted (default 6, at least 4).

  plimsoll-withheld scan -set FILE PATH ...
      Scan files, or directories of them, against a set as the daemon would scan a
      call carrying them, inside the archives they hold too (tar, gzip, bzip2, zip),
      and list what was found and any file whose archives passed one of the scan's
      bounds (the daemon refuses such a call when the set has a refuse entry). Exit
      status 1 when anything was found or a bound was reached.

The set holds SHA-256 digests and labels (a file's path, a values file's name and
line), never a value. A short value is still recovered from its digest by trying
every candidate, so a set of short seeds is as sensitive as the seeds.
`

type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error {
	*l = append(*l, v)
	return nil
}

func main() {
	code, err := run(os.Args[1:], os.Stdout, os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "plimsoll-withheld:", err)
		if code == 0 {
			code = 2
		}
	}
	os.Exit(code)
}

func run(args []string, stdout, stderr io.Writer) (int, error) {
	if len(args) == 0 {
		return 2, errors.New("a command is required\n\n" + usage)
	}
	switch args[0] {
	case "build":
		return 0, build(args[1:], stdout, stderr)
	case "scan":
		return scan(args[1:], stdout, stderr)
	case "-h", "-help", "--help", "help":
		fmt.Fprint(stdout, usage)
		return 0, nil
	}
	return 2, fmt.Errorf("unknown command %q\n\n%s", args[0], usage)
}

type setFile struct {
	Version       int      `json:"version"`
	Mode          string   `json:"mode"`
	ExemptCallers []string `json:"exempt_callers,omitempty"`
	Entries       []entry  `json:"entries"`
}

type entry struct {
	Kind     withheld.Kind `json:"kind"`
	SHA256   string        `json:"sha256,omitempty"`
	Length   int           `json:"length,omitempty"`
	Lines    []string      `json:"lines,omitempty"`
	MinLines int           `json:"min_lines,omitempty"`
	Label    string        `json:"label"`
	Mode     string        `json:"mode,omitempty"`
}

func build(args []string, stdout, stderr io.Writer) error {
	fl := flag.NewFlagSet("build", flag.ContinueOnError)
	var files, sources, values, exempt listFlag
	mode := fl.String("mode", "", "the set's mode: refuse or audit")
	filesMode := fl.String("files-mode", "", "mode for -file entries (default: -mode)")
	sourceMode := fl.String("source-mode", string(withheld.ModeAudit), "mode for -source entries")
	valuesMode := fl.String("values-mode", "", "mode for -values entries (default: -mode)")
	minLength := fl.Int("min-length", withheld.DefaultMinValueBytes, "shortest value accepted")
	fl.Var(&files, "file", "a file, or a directory of files, to withhold whole (repeatable)")
	fl.Var(&sources, "source", "a file, or a directory of files, whose lines to withhold (repeatable)")
	fl.Var(&values, "values", "a file of values, one per line (repeatable)")
	fl.Var(&exempt, "exempt", "a caller ID that is not scanned (repeatable)")
	if err := fl.Parse(args); err != nil {
		return err
	}
	if fl.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fl.Arg(0))
	}
	if len(files) == 0 && len(sources) == 0 && len(values) == 0 {
		return errors.New("name at least one -file, -source or -values")
	}
	out := setFile{Version: withheld.Version, Mode: *mode, ExemptCallers: exempt}
	seen := map[string]string{} // kind/digest -> label
	// add adds e unless an entry already holds its digest; quiet is for a value's
	// extra form, which may equal another value without that being worth a line.
	add := func(e entry, quiet bool) {
		key := string(e.Kind) + "/" + e.SHA256 + strings.Join(e.Lines, "")
		if first, dup := seen[key]; dup {
			if !quiet {
				same := "the same content as"
				if e.Kind == withheld.KindValue {
					same = "the same value (in any letter case) as"
				}
				fmt.Fprintf(stderr, "plimsoll-withheld: %s is %s %s; kept once\n", e.Label, same, first)
			}
			return
		}
		seen[key] = e.Label
		out.Entries = append(out.Entries, e)
	}
	for _, root := range files {
		err := eachFile(root, stderr, func(path, name string, content []byte) error {
			if len(withheld.Normalize(content)) == 0 {
				fmt.Fprintf(stderr, "plimsoll-withheld: %s is empty (or only blank lines); skipped, since it would match every empty file\n", path)
				return nil
			}
			d := withheld.FileDigest(content)
			add(entry{Kind: withheld.KindFile, SHA256: hex.EncodeToString(d[:]), Label: label(name), Mode: *filesMode}, false)
			return nil
		})
		if err != nil {
			return err
		}
	}
	for _, root := range sources {
		n := 0
		err := eachFile(root, stderr, func(path, name string, content []byte) error {
			digests := withheld.SourceDigests(content)
			if len(digests) < withheld.MinSourceLines {
				fmt.Fprintf(stderr, "plimsoll-withheld: %s has %d distinctive lines, fewer than the %d a source entry needs; skipped\n", path, len(digests), withheld.MinSourceLines)
				return nil
			}
			lines := make([]string, len(digests))
			for i, d := range digests {
				lines[i] = hex.EncodeToString(d[:])
			}
			// A third of the lines: an edited copy keeps most of them, an unrelated
			// file shares few.
			minLines := withheld.DefaultMinLines(len(lines))
			add(entry{Kind: withheld.KindSource, Lines: lines, MinLines: minLines, Label: label(name), Mode: *sourceMode}, false)
			n++
			return nil
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("%s holds no file with %d distinctive lines", root, withheld.MinSourceLines)
		}
	}
	for _, path := range values {
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sc := bufio.NewScanner(bytes.NewReader(raw))
		sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
		for n := 1; sc.Scan(); n++ {
			v := bytes.TrimSpace(sc.Bytes())
			if len(v) == 0 || v[0] == '#' {
				continue
			}
			// The value is never in an error: it is the secret.
			if err := withheld.CheckValue(v, *minLength); err != nil {
				return fmt.Errorf("%s line %d: %w", path, n, err)
			}
			name := label(fmt.Sprintf("%s:%d", filepath.Base(path), n))
			// The value, and with + for each space (form encoding, which the scan does
			// not decode, since in code + is a plus): one entry to the scan, by label.
			for i, form := range [][]byte{v, bytes.ReplaceAll(v, []byte(" "), []byte("+"))} {
				if i > 0 && bytes.Equal(form, v) {
					break
				}
				sum := withheld.ValueDigest(form)
				add(entry{Kind: withheld.KindValue, SHA256: hex.EncodeToString(sum[:]), Length: len(form), Label: name, Mode: *valuesMode}, i > 0)
			}
		}
		if err := sc.Err(); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
	}
	raw, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	// What the daemon would refuse to load is never written.
	if _, err := withheld.Parse(raw); err != nil {
		return err
	}
	_, err = stdout.Write(raw)
	return err
}

func scan(args []string, stdout, stderr io.Writer) (int, error) {
	fl := flag.NewFlagSet("scan", flag.ContinueOnError)
	setPath := fl.String("set", "", "the withheld set file")
	if err := fl.Parse(args); err != nil {
		return 2, err
	}
	if *setPath == "" || fl.NArg() == 0 {
		return 2, errors.New("scan needs -set FILE and at least one PATH")
	}
	set, err := withheld.Load(*setPath)
	if err != nil {
		return 2, err
	}
	var parts []withheld.Part
	for _, root := range fl.Args() {
		err := eachFile(root, stderr, func(path, _ string, content []byte) error {
			parts = append(parts,
				withheld.Part{Where: path + " (path)", Data: []byte(path)},
				withheld.Part{Where: path, Data: content, Whole: true})
			return nil
		})
		if err != nil {
			return 2, err
		}
	}
	res, err := set.Scan(context.Background(), parts)
	if err != nil {
		return 2, err
	}
	for _, f := range res.Found {
		fmt.Fprintf(stdout, "%s (%s): %s\n", f.Label, f.Mode, strings.Join(f.Where, ", "))
	}
	for _, in := range res.Incomplete {
		fmt.Fprintf(stdout, "incomplete: %s: %s\n", in.Where, in.Bound.Text())
	}
	if len(res.Found) > 0 || len(res.Incomplete) > 0 {
		return 1, nil
	}
	fmt.Fprintf(stdout, "clean: %d files against set %s\n", len(parts)/2, set.Digest())
	return 0, nil
}

// eachFile calls fn on root, or on every regular file under it, in lexical order,
// with the file's path and its name from root's parent. Anything else it meets (a
// symbolic link, a device) is skipped and said on stderr, and a root with no regular
// file is an error: a set built from it would withhold less than its author named.
func eachFile(root string, stderr io.Writer, fn func(path, name string, content []byte) error) error {
	parent := filepath.Dir(filepath.Clean(root))
	n := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			fmt.Fprintf(stderr, "plimsoll-withheld: %s is not a regular file (%s); skipped\n", path, d.Type())
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		name, err := filepath.Rel(parent, path)
		if err != nil {
			return err
		}
		n++
		return fn(filepath.ToSlash(path), filepath.ToSlash(name), content)
	})
	if err == nil && n == 0 {
		err = fmt.Errorf("%s holds no regular file", root)
	}
	return err
}

// label is s as a label: every byte a label may not hold becomes _, and a long one
// keeps its end, where a path's file name is.
func label(s string) string {
	b := []byte(s)
	for i, c := range b {
		if withheld.CheckLabel(string(c)) != nil {
			b[i] = '_'
		}
	}
	if len(b) > withheld.MaxLabelBytes {
		b = b[len(b)-withheld.MaxLabelBytes:]
	}
	return string(b)
}
