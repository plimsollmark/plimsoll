// Command suiterun is the one reader of go test's results for the Makefile's suites.
//
//	suiterun test [-quiet] [go test flags and packages]
//	suiterun stream PACKAGE -run PATTERN [+ PACKAGE -run PATTERN]... < a test binary's output
//	suiterun check FILE
//	suiterun unselected FILE [BY-HAND LIST]...
//	suiterun leftovers DIR
//
// test runs go test -json with the arguments given, prints what go test -v would print (or,
// with -quiet, what plain go test would: package lines and the output of failed tests), and
// appends every test's result to the file SUITE_RESULTS names, one JSON object a line. Its
// exit status is go test's.
//
// stream is test for a suite that runs compiled test binaries itself (the agent-sandbox
// suite runs them inside the cluster's network): it reads, on standard input, what the
// binaries print under -test.v=test2json, turns it into the same events with go tool
// test2json, and records them. Its arguments say which tests the binaries were asked for,
// as go test's would, so unselected can read them; its exit status is 1 when a test failed.
//
// check is a required suite's verdict (the Makefile's SUITE_END): it fails when the results
// hold a skipped test, naming each, and when they hold no passed test at all, so a suite
// line that runs go test without this reader, and a selection that matched nothing, fail
// too. Until 2026-11-20 the verdict was a grep for "--- SKIP" in the printed log, which go
// test prints only under -v, a flag nothing required.
//
// unselected is the short pass's check (make race): a test that skipped there runs only
// where a suite selects it, so each skipped test must be selected by the go test of some
// target that runs through SUITE_BEGIN, read from make's own dry run of each such target
// (its packages, its -run and its -skip). A test that skipped and that no target selects
// runs nowhere, and fails the pass, unless a by-hand list names it with its reason (a test
// someone runs on purpose with a flag of its own); a listed test that did not skip fails the
// pass as well. Nine docker tests had run in no target and no CI job until this check: two
// whose names held none of the docker suite's words, and seven in a package the suite did
// not name; the check found eight more that skipped only for the seconds they take.
//
// leftovers is a docker suite's last check: it fails when a container the suite's run
// started is still on the docker host, names each, and removes it. The run is told apart
// from every other on the host by DIR, the directory the suite made for it and handed its
// tests as TMPDIR: the docker provider keeps its private files (the guest's resolv.conf,
// the guest guard) under TMPDIR and bind-mounts them into every container it starts, so a
// container of this run is one with a mount from under DIR, and another suite's at the
// same moment never is. It waits up to a minute for a container already being removed.
// Until 2026-11-20 nothing checked: the docker Python suite left a paused session container
// on every run, and the docker exec attached to it kept the gate's scope alive.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
)

// Result is one test's outcome, as a line of the results file. Test is empty for a
// package's own line.
type Result struct {
	Package string  `json:"package"`
	Test    string  `json:"test,omitempty"`
	Action  string  `json:"action"` // pass, fail or skip
	Elapsed float64 `json:"elapsed"`
	Reason  string  `json:"reason,omitempty"` // a skipped test's last lines
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: suiterun test [-quiet] [go test arguments] | suiterun stream PACKAGE -run PATTERN ... | suiterun check FILE | suiterun unselected FILE [BY-HAND LIST]... | suiterun leftovers DIR")
		os.Exit(2)
	}
	var err error
	code := 0
	switch os.Args[1] {
	case "test":
		code, err = runTest(os.Args[2:], os.Getenv("SUITE_RESULTS"), os.Stdout, os.Stderr)
	case "stream":
		code, err = runStream(os.Getenv("SUITE_RESULTS"), os.Stdin, os.Stdout, os.Stderr)
	case "check":
		if len(os.Args) != 3 {
			err = errors.New("check takes the results file")
			break
		}
		err = check(os.Args[2], os.Stdout)
	case "unselected":
		if len(os.Args) < 3 {
			err = errors.New("unselected takes the short pass's results file, then any by-hand lists")
			break
		}
		err = unselected(os.Args[2], ".", os.Args[3:], os.Stdout)
	case "leftovers":
		if len(os.Args) != 3 {
			err = errors.New("leftovers takes the run's directory")
			break
		}
		err = leftovers(os.Args[2], dockerHost{}, time.Minute, os.Stderr)
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "suiterun:", err)
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}

// event is one line of go test -json (cmd/test2json).
type event struct {
	Action  string
	Package string
	Test    string
	Elapsed float64
	Output  string
}

// runTest runs go test -json with args and returns its exit status.
func runTest(args []string, resultsPath string, stdout, stderr io.Writer) (int, error) {
	quiet := false
	if len(args) > 0 && args[0] == "-quiet" {
		quiet, args = true, args[1:]
	}
	if resultsPath == "" {
		return 2, errors.New("SUITE_RESULTS names no results file (the Makefile's SUITE_BEGIN sets it)")
	}
	cmd := exec.Command("go", append([]string{"test", "-json"}, args...)...)
	cmd.Stderr = stderr
	cmd.Stdin = os.Stdin
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return 2, err
	}
	if err := cmd.Start(); err != nil {
		return 2, err
	}
	results := read(pipe, stdout, quiet)
	waitErr := cmd.Wait()
	if err := appendResults(resultsPath, results); err != nil {
		return 2, err
	}
	var exit *exec.ExitError
	switch {
	case waitErr == nil:
		return 0, nil
	case errors.As(waitErr, &exit):
		return exit.ExitCode(), nil
	default:
		return 2, waitErr
	}
}

// runStream reads test binaries' -test.v=test2json output from in.
func runStream(resultsPath string, in io.Reader, stdout, stderr io.Writer) (int, error) {
	if resultsPath == "" {
		return 2, errors.New("SUITE_RESULTS names no results file (the Makefile's SUITE_BEGIN sets it)")
	}
	cmd := exec.Command("go", "tool", "test2json", "-t")
	cmd.Stdin, cmd.Stderr = in, stderr
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return 2, err
	}
	if err := cmd.Start(); err != nil {
		return 2, err
	}
	results := read(pipe, stdout, false)
	if err := cmd.Wait(); err != nil {
		return 2, fmt.Errorf("go tool test2json: %w", err)
	}
	if err := appendResults(resultsPath, results); err != nil {
		return 2, err
	}
	for _, r := range results {
		if r.Action == "fail" {
			return 1, nil
		}
	}
	return 0, nil
}

// read turns go test -json's stream into results and into the text a person reads.
func read(r io.Reader, out io.Writer, quiet bool) []Result {
	type key struct{ pkg, test string }
	var results []Result
	tail := map[key][]string{} // each running test's output: all of it when quiet (shown if it fails), else its last lines
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20)
	for sc.Scan() {
		line := sc.Bytes()
		var e event
		if len(line) == 0 || line[0] != '{' || json.Unmarshal(line, &e) != nil || e.Action == "" {
			fmt.Fprintf(out, "%s\n", line) // not an event: a build's own line
			continue
		}
		k := key{e.Package, e.Test}
		switch e.Action {
		case "output", "build-output":
			if e.Test == "" || !quiet {
				fmt.Fprint(out, e.Output)
			}
			if e.Test != "" {
				tail[k] = append(tail[k], e.Output)
				if !quiet && len(tail[k]) > 4 {
					tail[k] = tail[k][len(tail[k])-4:]
				}
			}
		case "pass", "fail", "skip":
			res := Result{Package: e.Package, Test: e.Test, Action: e.Action, Elapsed: e.Elapsed}
			if e.Test != "" {
				if e.Action == "skip" {
					res.Reason = reason(tail[k])
				}
				if e.Action == "fail" && quiet {
					fmt.Fprint(out, strings.Join(tail[k], ""))
				}
				delete(tail, k)
			}
			results = append(results, res)
		}
	}
	return results
}

// reason is a skipped test's own words: its output less go test's "=== " and "--- " lines.
func reason(lines []string) string {
	var said []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "=== ") || strings.HasPrefix(l, "--- ") {
			continue
		}
		said = append(said, l)
	}
	s := strings.Join(said, " ")
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

func appendResults(path string, results []Result) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	for _, r := range results {
		if err := enc.Encode(r); err != nil {
			f.Close()
			return err
		}
	}
	return f.Close()
}

func load(path string) ([]Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Result
	dec := json.NewDecoder(f)
	for {
		var r Result
		if err := dec.Decode(&r); err == io.EOF {
			return out, nil
		} else if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		out = append(out, r)
	}
}

// check is a required suite's verdict on its results.
func check(path string, out io.Writer) error {
	results, err := load(path)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("no test result was recorded (%s is not there): a required suite runs go test through `suiterun test`, the Makefile's $(SUITE_TEST)", path)
	}
	if err != nil {
		return err
	}
	passed, failed := 0, 0
	var skipped []string
	for _, r := range results {
		if r.Test == "" {
			continue
		}
		switch r.Action {
		case "pass":
			passed++
		case "fail":
			failed++
		case "skip":
			skipped = append(skipped, fmt.Sprintf("    --- SKIP: %s %s (%s)", r.Package, r.Test, r.Reason))
		}
	}
	if len(skipped) > 0 {
		sort.Strings(skipped)
		return fmt.Errorf("required coverage was skipped:\n%s", strings.Join(skipped, "\n"))
	}
	if passed == 0 && failed == 0 {
		return errors.New("required coverage ran no test: the suite's selection matched nothing")
	}
	fmt.Fprintf(out, "%d tests passed, %d failed, none skipped (%s)\n", passed, failed, path)
	return nil
}

// selection is one go test of a suite: where it runs, the packages it names, and its -run
// and -skip.
type selection struct {
	target, dir string
	packages    []string
	run, skip   *regexp.Regexp
}

var (
	suiteTarget = regexp.MustCompile(`(?m)^([A-Za-z0-9_.-]+):[^=\n]*\n(?:\t.*\n)*?\t.*\$\(SUITE_BEGIN\)`)
	moduleLine  = regexp.MustCompile(`(?m)^module (\S+)$`)
	readerCall  = regexp.MustCompile(`\.reader (?:test|stream) `)
)

// selections reads, from make's dry run of every target that runs through SUITE_BEGIN in
// the Makefile and local.mk of dir, each go test the target would run.
func selections(dir string) ([]selection, error) {
	var targets []string
	for _, name := range []string{"Makefile", "local.mk"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			if name == "Makefile" {
				return nil, err
			}
			continue
		}
		for _, m := range suiteTarget.FindAllStringSubmatch(string(b), -1) {
			targets = append(targets, m[1])
		}
	}
	if len(targets) == 0 {
		return nil, errors.New("the Makefile has no target that runs through SUITE_BEGIN")
	}
	var out []selection
	for _, target := range targets {
		cmd := exec.Command("make", "-n", "--no-print-directory", "-C", dir, target, "DOCKER=1")
		cmd.Env = append(os.Environ(), "MAKEFLAGS=", "MFLAGS=")
		b, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("make -n %s: %w", target, err)
		}
		found := parseSelections(target, string(b))
		if len(found) == 0 {
			return nil, fmt.Errorf("make -n %s shows no go test through the reader (`.reader test` or `.reader stream`)", target)
		}
		out = append(out, found...)
	}
	return out, nil
}

// parseSelections finds each `<reader> test ...` in a dry run's text, with the directory a
// `cd DIR &&` before it in the same parentheses names.
func parseSelections(target, dry string) []selection {
	var out []selection
	// A recipe line make prints over several lines (its backslashes kept) is one command.
	for _, line := range strings.Split(strings.ReplaceAll(dry, "\\\n", " "), "\n") {
		rest := line
		for {
			i := readerCall.FindStringIndex(rest)
			if i == nil {
				break
			}
			before, after := rest[:i[0]], rest[i[1]:]
			rest = after
			dir := "."
			if open := strings.LastIndex(before, "(cd "); open >= 0 && !strings.Contains(before[open:], ")") {
				if f := strings.Fields(before[open+len("(cd "):]); len(f) > 0 {
					dir = f[0]
				}
			}
			sel := selection{target: target, dir: dir}
			words := shellWords(after)
			for j := 0; j < len(words); j++ {
				w := words[j]
				switch {
				case w == "+": // stream's next package and pattern
					out = append(out, sel)
					sel = selection{target: target, dir: dir}
				case (w == "-run" || w == "-skip") && j+1 < len(words):
					re, err := regexp.Compile(words[j+1])
					if err == nil && w == "-run" {
						sel.run = re
					} else if err == nil {
						sel.skip = re
					}
					j++
				case w == "-timeout" || w == "-parallel" || w == "-count" || w == "-C":
					j++
				case strings.HasPrefix(w, "-"):
				default:
					sel.packages = append(sel.packages, w)
				}
			}
			out = append(out, sel)
		}
	}
	return out
}

// shellWords splits a command's text into words up to its end (; && || ) or |), with single
// and double quotes taken off.
func shellWords(s string) []string {
	var words []string
	var cur strings.Builder
	in, quote := false, byte(0)
	flush := func() {
		if in {
			words = append(words, cur.String())
			cur.Reset()
			in = false
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			} else {
				cur.WriteByte(c)
			}
		case c == '\'' || c == '"':
			quote, in = c, true
		case c == ' ' || c == '\t':
			flush()
		case c == ';' || c == ')' || c == '|' || c == '&':
			flush()
			return words
		default:
			cur.WriteByte(c)
			in = true
		}
	}
	flush()
	return words
}

// selects reports whether sel's go test runs the top-level test name of package pkg (an
// import path), given the import path of the module at each directory.
func (sel selection) selects(modules map[string]string, pkg, name string) bool {
	if sel.run != nil && !sel.run.MatchString(name) {
		return false
	}
	if sel.skip != nil && sel.skip.MatchString(name) {
		return false
	}
	base, ok := modules[filepath.Clean(sel.dir)]
	if !ok {
		return false
	}
	for _, p := range sel.packages {
		p = strings.TrimSuffix(strings.TrimPrefix(p, "./"), "/")
		switch {
		case p == "..." && (pkg == base || strings.HasPrefix(pkg, base+"/")):
			return true
		case strings.HasSuffix(p, "/..."):
			root := base + "/" + strings.TrimSuffix(p, "/...")
			if pkg == root || strings.HasPrefix(pkg, root+"/") {
				return true
			}
		case p == "." && pkg == base, pkg == base+"/"+p, pkg == p:
			return true
		}
	}
	return false
}

// modulesOf maps each directory a selection runs in to the import path of the package at
// it: the nearest go.mod's module path plus the directory's place under it.
func modulesOf(dir string, sels []selection) map[string]string {
	out := map[string]string{}
	for _, sel := range sels {
		d := filepath.Clean(sel.dir)
		if _, done := out[d]; done {
			continue
		}
		for up, below := filepath.Join(dir, d), ""; ; {
			if b, err := os.ReadFile(filepath.Join(up, "go.mod")); err == nil {
				if m := moduleLine.FindSubmatch(b); m != nil {
					out[d] = strings.TrimSuffix(string(m[1])+"/"+filepath.ToSlash(below), "/")
				}
				break
			}
			parent := filepath.Dir(up)
			if parent == up {
				break
			}
			below, up = filepath.Join(filepath.Base(up), below), parent
		}
	}
	return out
}

// byHand reads lists of tests run by hand on purpose: "import/path TestName: why", one a
// line, # for a comment.
func byHand(paths []string) (map[[2]string]string, error) {
	out := map[[2]string]string{}
	for _, path := range paths {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		for n, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			head, why, ok := strings.Cut(line, ": ")
			f := strings.Fields(head)
			if !ok || len(f) != 2 || strings.TrimSpace(why) == "" {
				return nil, fmt.Errorf("%s:%d: want `import/path TestName: why it is run by hand, and how`", path, n+1)
			}
			out[[2]string{f[0], f[1]}] = why
		}
	}
	return out, nil
}

// unselected fails for every test that skipped in the short pass whose results path holds
// and that no suite of the Makefile in dir selects, the tests of the by-hand lists aside.
func unselected(path, dir string, lists []string, out io.Writer) error {
	results, err := load(path)
	if err != nil {
		return err
	}
	hand, err := byHand(lists)
	if err != nil {
		return err
	}
	sels, err := selections(dir)
	if err != nil {
		return err
	}
	modules := modulesOf(dir, sels)
	type test struct{ pkg, name string }
	skipped := map[test]string{}
	for _, r := range results {
		if r.Action != "skip" || r.Test == "" {
			continue
		}
		top := test{r.Package, strings.SplitN(r.Test, "/", 2)[0]}
		if skipped[top] == "" {
			skipped[top] = r.Reason
		}
	}
	var nowhere []string
	byHandSeen := 0
	for tst, why := range skipped {
		found := false
		for _, sel := range sels {
			if sel.selects(modules, tst.pkg, tst.name) {
				found = true
				if os.Getenv("SUITE_EXPLAIN") != "" {
					fmt.Fprintf(out, "%s %s: %s (in %s: %v)\n", tst.pkg, tst.name, sel.target, sel.dir, sel.packages)
				}
				break
			}
		}
		_, listed := hand[[2]string{tst.pkg, tst.name}]
		if listed {
			byHandSeen++
		}
		if !found && !listed {
			nowhere = append(nowhere, fmt.Sprintf("    %s %s (%s)", tst.pkg, tst.name, why))
		}
	}
	for k := range hand {
		if _, ok := skipped[test{k[0], k[1]}]; !ok {
			nowhere = append(nowhere, fmt.Sprintf("    %s %s is listed as run by hand and did not skip in this pass: it ran, or it is gone; take its line out", k[0], k[1]))
		}
	}
	if len(nowhere) > 0 {
		sort.Strings(nowhere)
		return fmt.Errorf("%d test(s) skipped in this pass and are selected by no suite of the Makefile, so they run nowhere (or a by-hand list is out of date): name each so a suite's -run selects it in a package the suite names, list it as run by hand with the reason, or remove it:\n%s", len(nowhere), strings.Join(nowhere, "\n"))
	}
	fmt.Fprintf(out, "%d tests skipped in this pass: %d are selected by a suite (%d go test lines of the Makefile's suites read), %d are run by hand and listed with the reason\n", len(skipped), len(skipped)-byHandSeen, len(sels), byHandSeen)
	return nil
}

// container is what leftovers reads of one container from docker inspect.
type container struct {
	ID      string
	Name    string
	Created string
	State   struct{ Status string }
	Config  struct {
		Image  string
		Labels map[string]string
	}
	Mounts []mount
}

// mount is one of a container's mounts, as docker inspect states it.
type mount struct{ Source string }

// containers is the docker host leftovers reads and cleans; a fake stands in for it in the
// tests.
type containers interface {
	// list is every container on the host, running or not.
	list() ([]container, error)
	// remove removes one, paused or not.
	remove(id string) error
}

// dockerHost is the docker CLI's host.
type dockerHost struct{}

func (dockerHost) list() ([]container, error) {
	ids, err := exec.Command("docker", "ps", "-aq", "--no-trunc").Output()
	if err != nil {
		return nil, fmt.Errorf("docker ps: %w", err)
	}
	if len(strings.Fields(string(ids))) == 0 {
		return nil, nil
	}
	// A container removed between the two commands makes docker inspect exit 1 after it
	// printed the others, so its output is read either way; an unreadable one is the error.
	out, ierr := exec.Command("docker", append([]string{"inspect"}, strings.Fields(string(ids))...)...).Output()
	var all []container
	if err := json.Unmarshal(out, &all); err != nil {
		return nil, fmt.Errorf("docker inspect: %v (%w)", ierr, err)
	}
	return all, nil
}

func (dockerHost) remove(id string) error {
	_ = exec.Command("docker", "unpause", id).Run() // a container that is not paused refuses, which is fine
	if out, err := exec.Command("docker", "rm", "-f", id).CombinedOutput(); err != nil {
		return fmt.Errorf("docker rm -f %s: %v: %s", id, err, bytes.TrimSpace(out))
	}
	return nil
}

// ofRun is each container on host with a mount from under dir.
func ofRun(host containers, dir string) ([]container, error) {
	dirs := []string{filepath.Clean(dir)}
	if real, err := filepath.EvalSymlinks(dir); err == nil && real != dirs[0] {
		dirs = append(dirs, real)
	}
	all, err := host.list()
	if err != nil {
		return nil, err
	}
	var mine []container
	for _, c := range all {
		if slices.ContainsFunc(c.Mounts, func(m mount) bool {
			return slices.ContainsFunc(dirs, func(d string) bool { return strings.HasPrefix(m.Source, d+string(filepath.Separator)) })
		}) {
			mine = append(mine, c)
		}
	}
	return mine, nil
}

// leftovers fails when a container of the run whose directory is dir is still on host
// after waiting up to wait for removals under way, naming each, and removes it.
func leftovers(dir string, host containers, wait time.Duration, out io.Writer) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("leftovers: %q is not an absolute path", dir)
	}
	deadline := time.Now().Add(wait)
	for {
		left, err := ofRun(host, dir)
		if err != nil {
			return err
		}
		if len(left) == 0 {
			return nil
		}
		if time.Now().Before(deadline) {
			time.Sleep(min(2*time.Second, time.Until(deadline)))
			continue
		}
		for _, c := range left {
			var sources []string
			for _, m := range c.Mounts {
				sources = append(sources, m.Source)
			}
			fmt.Fprintf(out, "left behind: %s %s, %s, image %s, created %s, instance %q, session %q, expires %q, mounts %s\n", c.ID[:min(12, len(c.ID))], strings.TrimPrefix(c.Name, "/"),
				c.State.Status, c.Config.Image, c.Created, c.Config.Labels["io.plimsoll.instance"], c.Config.Labels["io.plimsoll.session"], c.Config.Labels["io.plimsoll.expires"], strings.Join(sources, " "))
			if err := host.remove(c.ID); err != nil {
				fmt.Fprintf(out, "  and it could not be removed: %v\n", err)
			}
		}
		return fmt.Errorf("%d container(s) this suite's run started are still on the docker host (named above, now removed): a test that opens a session or starts a container must close it or drain its sandbox, pass or fail", len(left))
	}
}
