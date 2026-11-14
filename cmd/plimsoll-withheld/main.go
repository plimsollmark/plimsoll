// Command plimsoll-withheld builds a withheld set for plimsolld's ship scan
// (PLIMSOLL_WITHHELD_FILE) from the files and values that must never enter a sandbox,
// and scans a directory, or a container image, against a set offline. It writes digests,
// never a value, and never contacts a plimsoll daemon. docs/ship-scan.md is the
// operator's account.
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
	"os/exec"
	"path/filepath"
	"strconv"
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

  plimsoll-withheld scan -set FILE [-format text|sarif] PATH ...
      Scan files, or directories of them, against a set as the daemon would scan a
      call carrying them, inside the archives they hold too (tar, gzip, bzip2, zip),
      and list what was found and any file whose archives passed one of the scan's
      bounds (the daemon refuses such a call when the set has a refuse entry). Exit
      status 1 when anything was found or a bound was reached.

  plimsoll-withheld scan-image -set FILE [-format text|sarif] IMAGE
  plimsoll-withheld scan-image -set FILE [-format text|sarif] -archive PATH
      Scan a container image against a set, as docker save writes it (from the
      docker CLI, or a saved archive): every regular file of every layer on its own,
      with its path, so a file a later layer deletes is still found (it is still in
      the image's bytes), and the image configuration (its environment, labels and
      build history) whole. Run it before an image is pushed anywhere a sandbox
      provider stores it: whoever stores and runs an image can read it. A file
      larger than 64 MiB, a layer compressed with zstd, or a file holding what reads
      as an archive past the scan's bounds or in a format it does not read (common in
      compiled libraries) is listed as incomplete. Exit status 1 when anything was
      found, 3 when nothing was found but some file was not read whole, 0 when the
      image is clean; the last line names the image ID and the set's digest.

  -format sarif writes either scan's result as a SARIF 2.1.0 file instead, for
  GitHub code scanning and other readers of the standard: one result per find
  (rule find) and per file not read whole (rule unreadable), each naming the
  entry's label, the file's path (in an image, the layer and the path) and, for a
  value found in a line of a scanned file, the line. It holds no withheld value
  and no file content, and does not name a path the scan finds a value in; it is
  scanned against the set before it is written, and nothing is written when a
  label, a layer's name or a path given on the command line holds a value. The
  exit status is the same as the text output's.

  plimsoll-withheld known-unreadable -set FILE -known FILE IMAGE
      Create or update the known-unreadable list for this image's inspected content
      ID, keeping every other image's list. Records each unreadable file's path,
      reason and whole size. Run after reviewing what scan-image could not read.
      This acknowledges unread bytes; it does not prove they hold no withheld
      material. A rebuilt image has a new ID and needs a new list. The daemon reads
      it through PLIMSOLL_WITHHELD_KNOWN_FILE and refuses any unreadable file not
      listed with the same ID, path, reason and size, for audit-only sets too.
      Updates are atomic; concurrent writers refuse while FILE.lock exists. After
      an interrupted writer, check it has stopped before removing that directory.

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
	case "known-unreadable":
		code, err := knownUnreadable(args[1:], stdout, stderr)
		if err != nil {
			err = errors.New(withheld.CleanWhere(err.Error()))
		}
		return code, err
	case "scan-image":
		return scanImage(args[1:], stdout, stderr)
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
				fmt.Fprintf(stderr, "plimsoll-withheld: %s is empty (or only blank lines); skipped, since it would match every empty file\n", withheld.CleanWhere(path))
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
				fmt.Fprintf(stderr, "plimsoll-withheld: %s has %d distinctive lines, fewer than the %d a source entry needs; skipped\n", withheld.CleanWhere(path), len(digests), withheld.MinSourceLines)
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

// formatFlag adds -format to fl: text (the default) or sarif.
func formatFlag(fl *flag.FlagSet) *string {
	return fl.String("format", "text", "the output: text, or sarif (SARIF 2.1.0, for GitHub code scanning)")
}

func checkFormat(format string) error {
	if format != "text" && format != "sarif" {
		return fmt.Errorf("-format must be text or sarif, not %q", format)
	}
	return nil
}

// scannedFile is one file scan read, by its index in the parts (2i is its path, 2i+1
// its content).
type scannedFile struct {
	path    string
	content []byte
}

func scan(args []string, stdout, stderr io.Writer) (int, error) {
	fl := flag.NewFlagSet("scan", flag.ContinueOnError)
	setPath := fl.String("set", "", "the withheld set file")
	format := formatFlag(fl)
	if err := fl.Parse(args); err != nil {
		return 2, err
	}
	if *setPath == "" || fl.NArg() == 0 {
		return 2, errors.New("scan needs -set FILE and at least one PATH")
	}
	if err := checkFormat(*format); err != nil {
		return 2, err
	}
	set, err := withheld.Load(*setPath)
	if err != nil {
		return 2, err
	}
	var (
		parts []withheld.Part
		files []scannedFile
	)
	for _, root := range fl.Args() {
		err := eachFile(root, stderr, func(path, _ string, content []byte) error {
			// For SARIF a part is named by its file's index, which no name can make
			// ambiguous; the text output names it by its path.
			where := path
			if *format == "sarif" {
				where = "f" + strconv.Itoa(len(files))
			}
			files = append(files, scannedFile{path: path, content: content})
			parts = append(parts,
				withheld.Part{Where: where + " (path)", Data: []byte(path)},
				withheld.Part{Where: where, Data: content, Whole: true})
			return nil
		})
		if err != nil {
			return 2, err
		}
	}
	ctx := context.Background()
	res, err := set.Scan(ctx, parts)
	if err != nil {
		return 2, err
	}
	code := 0
	if len(res.Found) > 0 || len(res.Incomplete) > 0 {
		code = 1
	}
	if *format == "sarif" {
		raw, err := scanSARIF(ctx, set, files, res)
		if err != nil {
			return 2, err
		}
		_, err = stdout.Write(raw)
		return code, err
	}
	for _, f := range res.Found {
		fmt.Fprintf(stdout, "%s (%s): %s\n", f.Label, f.Mode, strings.Join(f.Where, ", "))
	}
	for _, in := range res.Incomplete {
		fmt.Fprintf(stdout, "incomplete: %s: %s\n", in.Where, in.Bound.Text())
	}
	if code != 0 {
		return code, nil
	}
	fmt.Fprintf(stdout, "clean: %d files against set %s\n", len(parts)/2, set.Digest())
	return 0, nil
}

// scanSARIF is scan's result as a SARIF file: each part is named by its file's index
// ("f3", "f3 (path)").
func scanSARIF(ctx context.Context, set *withheld.Set, files []scannedFile, res withheld.Result) ([]byte, error) {
	place := func(where string) (sarifPlace, int, error) {
		name, isPath := strings.CutSuffix(where, " (path)")
		i, err := strconv.Atoi(strings.TrimPrefix(name, "f"))
		if err != nil || !strings.HasPrefix(name, "f") || i < 0 || i >= len(files) {
			return sarifPlace{}, 0, fmt.Errorf("internal: a part named %q", where)
		}
		pl := sarifPlace{path: files[i].path, part: withheld.PartContent}
		if isPath {
			pl.part = withheld.PartPath
		}
		return pl, i, nil
	}
	w := newSARIF(set)
	for _, f := range res.Found {
		for _, at := range f.Where {
			pl, _, err := place(at)
			if err != nil {
				return nil, err
			}
			if pl.part == withheld.PartPath {
				if err := w.hide(ctx, "", pl.path); err != nil {
					return nil, err
				}
			}
		}
	}
	lines := map[int]map[string]int{}
	for _, f := range res.Found {
		for _, at := range f.Where {
			pl, i, err := place(at)
			if err != nil {
				return nil, err
			}
			if pl.part == withheld.PartContent {
				if lines[i] == nil {
					if lines[i], err = firstLines(ctx, set, files[i].content); err != nil {
						return nil, err
					}
				}
				pl.line = lines[i][f.Label+"\x00"+string(f.Mode)]
			}
			w.find(f, pl)
		}
	}
	for _, in := range res.Incomplete {
		pl, _, err := place(in.Where)
		if err != nil {
			return nil, err
		}
		w.unreadable(in, pl)
	}
	return w.bytes(ctx)
}

// imageSARIF is scan-image's result as a SARIF file, the image read (what) its root
// artifact, each layer nested in it and each file in its layer.
func imageSARIF(ctx context.Context, set *withheld.Set, what string, res withheld.ImageResult) ([]byte, error) {
	place := func(where string) sarifPlace {
		if p, ok := res.Places[where]; ok {
			return sarifPlace{layer: p.Layer, path: p.Path, part: p.Part}
		}
		return sarifPlace{path: where, part: withheld.PartContent}
	}
	w := newSARIF(set)
	w.forImage(what)
	for _, f := range res.Found {
		for _, at := range f.Where {
			if pl := place(at); pl.part == withheld.PartPath {
				if err := w.hide(ctx, pl.layer, pl.path); err != nil {
					return nil, err
				}
			}
		}
	}
	for _, f := range res.Found {
		for _, at := range f.Where {
			w.find(f, place(at))
		}
	}
	for _, in := range res.Incomplete {
		w.unreadable(in, place(in.Where))
	}
	return w.bytes(ctx)
}

// scanImage scans one image, from the docker CLI or a saved archive, against a set.
func scanImage(args []string, stdout, stderr io.Writer) (int, error) {
	fl := flag.NewFlagSet("scan-image", flag.ContinueOnError)
	setPath := fl.String("set", "", "the withheld set file")
	archivePath := fl.String("archive", "", "an image archive docker save wrote, instead of IMAGE")
	format := formatFlag(fl)
	if err := fl.Parse(args); err != nil {
		return 2, err
	}
	if *setPath == "" || (*archivePath == "") == (fl.NArg() == 0) || fl.NArg() > 1 {
		return 2, errors.New("scan-image needs -set FILE and one IMAGE, or -set FILE and -archive PATH")
	}
	if err := checkFormat(*format); err != nil {
		return 2, err
	}
	set, err := withheld.Load(*setPath)
	if err != nil {
		return 2, err
	}
	ctx := context.Background()
	var (
		archive io.Reader
		what    string
		wait    = func() error { return nil }
	)
	if *archivePath != "" {
		f, err := os.Open(*archivePath)
		if err != nil {
			return 2, err
		}
		defer f.Close()
		archive, what = f, "archive "+*archivePath
	} else {
		// The ID first, and the save by that ID, so a tag moved meanwhile cannot make the
		// clean line name an image that was not the one read.
		out, err := exec.CommandContext(ctx, "docker", "image", "inspect", "--format", "{{.Id}}", fl.Arg(0)).Output()
		if err != nil {
			return 2, fmt.Errorf("docker image inspect %s: %w", fl.Arg(0), err)
		}
		id := strings.TrimSpace(string(out))
		save := exec.CommandContext(ctx, "docker", "save", id)
		save.Stderr = stderr
		pipe, err := save.StdoutPipe()
		if err != nil {
			return 2, err
		}
		if err := save.Start(); err != nil {
			return 2, fmt.Errorf("docker save: %w", err)
		}
		archive, what = pipe, "image "+id+" ("+fl.Arg(0)+")"
		// After the scan: what follows the archive's end marker is drained, so docker save
		// is not left blocked writing it; after a failed scan docker save is stopped.
		wait = func() error {
			if _, err := io.Copy(io.Discard, pipe); err != nil {
				_ = save.Process.Kill()
			}
			return save.Wait()
		}
	}
	res, err := set.ScanImage(ctx, archive)
	if err != nil {
		if c, ok := archive.(io.Closer); ok && *archivePath == "" {
			_ = c.Close() // docker save then stops on a broken pipe
		}
	}
	if werr := wait(); err == nil && werr != nil {
		err = fmt.Errorf("docker save: %w", werr)
	}
	if err != nil {
		return 2, err
	}
	if *format == "sarif" {
		code := 0
		switch {
		case len(res.Found) > 0:
			code = 1
		case len(res.Incomplete) > 0:
			code = 3
		}
		raw, err := imageSARIF(ctx, set, what, res)
		if err != nil {
			return 2, err
		}
		_, err = stdout.Write(raw)
		return code, err
	}
	for _, f := range res.Found {
		fmt.Fprintf(stdout, "%s (%s): %s\n", f.Label, f.Mode, strings.Join(f.Where, ", "))
	}
	for _, in := range res.Incomplete {
		fmt.Fprintf(stdout, "incomplete: %s: %s\n", in.Where, in.Bound.Text())
	}
	switch {
	case len(res.Found) > 0:
		fmt.Fprintf(stdout, "found: %d entries in %d files, %d layers of %s against set %s\n", len(res.Found), res.Files, res.Layers, what, set.Digest())
		return 1, nil
	case len(res.Incomplete) > 0:
		fmt.Fprintf(stdout, "nothing found, %d of %d files not read whole, %d layers of %s against set %s\n", len(res.Incomplete), res.Files, res.Layers, what, set.Digest())
		return 3, nil
	}
	fmt.Fprintf(stdout, "clean: %d files in %d layers of %s against set %s\n", res.Files, res.Layers, what, set.Digest())
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
			fmt.Fprintf(stderr, "plimsoll-withheld: %s is not a regular file (%s); skipped\n", withheld.CleanWhere(path), d.Type())
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
