package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/internal/withheld"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// The hackathon's shipping mistake, replayed offline: a set built from the harness's
// source directory and its practice seeds finds the source shipped under another name
// with other line endings, and a seed inside an example URL in a viewer file.
func TestBuildThenScanFindsTheHackathonLeaks(t *testing.T) {
	dir := t.TempDir()
	sim := "import numpy as np\n\ndef step(state, u, dt):\n    return state + dt * (u - 0.3 * state)\n"
	write(t, filepath.Join(dir, "harness", "sim.py"), sim)
	write(t, filepath.Join(dir, "harness", "copy.py"), sim) // the same content twice: one entry
	write(t, filepath.Join(dir, "seeds.txt"), "# practice seeds\n731904\n\n  552018  \n")

	var set bytes.Buffer
	if code, err := run([]string{"build", "-mode", "refuse", "-values-mode", "audit", "-exempt", "judge",
		"-file", filepath.Join(dir, "harness"), "-values", filepath.Join(dir, "seeds.txt")}, &set, io.Discard); err != nil || code != 0 {
		t.Fatalf("build: %d, %v", code, err)
	}
	if strings.Contains(set.String(), "731904") || strings.Contains(set.String(), "def step") {
		t.Fatalf("the set holds a value: %s", set.String())
	}
	var parsed setFile
	if err := json.Unmarshal(set.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Entries) != 3 || parsed.Entries[0].Kind != withheld.KindFile || parsed.Entries[0].Label != "harness/copy.py" ||
		parsed.Entries[1].Label != "seeds.txt:2" || parsed.Entries[1].Mode != "audit" || parsed.Entries[2].Label != "seeds.txt:4" ||
		parsed.Entries[2].Length != 6 || len(parsed.ExemptCallers) != 1 {
		t.Fatalf("set: %+v", parsed)
	}
	setPath := filepath.Join(dir, "set.json")
	write(t, setPath, set.String())

	task := filepath.Join(dir, "task")
	write(t, filepath.Join(task, "helpers", "model.py"), strings.ReplaceAll(sim, "\n", "\r\n"))
	write(t, filepath.Join(task, "viewer.html"), `<a href="viewer.html?seed=552018&case=2">example</a>`)
	write(t, filepath.Join(task, "README.md"), "Fly the plant to the target; seed 1552018 is not a practice seed.")
	var out bytes.Buffer
	code, err := run([]string{"scan", "-set", setPath, task}, &out, io.Discard)
	if err != nil || code != 1 {
		t.Fatalf("scan: %d, %v\n%s", code, err, out.String())
	}
	for _, want := range []string{"harness/copy.py (refuse): " + filepath.ToSlash(filepath.Join(task, "helpers", "model.py")),
		"seeds.txt:4 (audit): " + filepath.ToSlash(filepath.Join(task, "viewer.html"))} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("scan output lacks %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "README") {
		t.Errorf("1552018 is another number:\n%s", out.String())
	}

	clean := filepath.Join(dir, "clean")
	write(t, filepath.Join(clean, "agent.py"), "print('hello')\n")
	out.Reset()
	if code, err := run([]string{"scan", "-set", setPath, clean}, &out, io.Discard); err != nil || code != 0 || !strings.HasPrefix(out.String(), "clean: 1 files") {
		t.Fatalf("clean scan: %d, %v, %s", code, err, out.String())
	}
}

// A value the scan could never find is refused at build time, and the error names the
// line, never the value: the value is the secret.
func TestBuildRefusesAValueTheScanCannotFind(t *testing.T) {
	dir := t.TempDir()
	for _, bad := range []string{"4821", "-0.731904", "a-b-c-d-e-f-g-h-i"} {
		path := filepath.Join(dir, "values.txt")
		write(t, path, "731904\n"+bad+"\n")
		var out bytes.Buffer
		_, err := run([]string{"build", "-mode", "audit", "-values", path}, &out, io.Discard)
		if err == nil || !strings.Contains(err.Error(), "values.txt line 2") || strings.Contains(err.Error(), bad) || out.Len() != 0 {
			t.Errorf("%q: %v (wrote %d bytes)", bad, err, out.Len())
		}
	}
	good := filepath.Join(dir, "good.txt")
	write(t, good, "731904\n")
	var out bytes.Buffer
	if _, err := run([]string{"build", "-mode", "never", "-values", good}, &out, io.Discard); err == nil || !strings.Contains(err.Error(), "mode") || out.Len() != 0 {
		t.Errorf("a set the daemon would refuse was written: %v", err)
	}
	if code, err := run([]string{"build", "-mode", "audit", "-values", good}, &out, io.Discard); err != nil || code != 0 || out.Len() == 0 {
		t.Errorf("the same values with a valid mode: %d, %v", code, err)
	}
}

// A file's label is its path from the named root's parent, never the operator's
// absolute path (a refusal shows the caller the label); a symbolic link is skipped and
// said, and a root with no regular file is refused rather than built into a set that
// withholds less than its author named.
func TestBuildLabelsAndSkips(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "srv", "harness", "sim.py"), "x = 1\n")
	write(t, filepath.Join(dir, "srv", "harness", "data", "cases.json"), "[1]\n")
	if err := os.Symlink(filepath.Join(dir, "srv", "harness", "sim.py"), filepath.Join(dir, "srv", "harness", "link.py")); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	if _, err := run([]string{"build", "-mode", "refuse", "-file", filepath.Join(dir, "srv", "harness"),
		"-file", filepath.Join(dir, "srv", "harness", "sim.py")}, &out, &errs); err != nil {
		t.Fatal(err)
	}
	var parsed setFile
	if err := json.Unmarshal(out.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	var labels []string
	for _, e := range parsed.Entries {
		labels = append(labels, e.Label)
	}
	if strings.Join(labels, " ") != "harness/data/cases.json harness/sim.py" {
		t.Errorf("labels %q; want each file's path from the root's parent", labels)
	}
	if strings.Contains(out.String(), dir) {
		t.Errorf("the set names the operator's directory: %s", out.String())
	}
	if !strings.Contains(errs.String(), "link.py is not a regular file") || !strings.Contains(errs.String(), "sim.py is the same content as harness/sim.py") {
		t.Errorf("stderr: %s", errs.String())
	}
	empty := filepath.Join(dir, "empty")
	if err := os.Mkdir(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if _, err := run([]string{"build", "-mode", "refuse", "-file", empty, "-file", filepath.Join(dir, "srv")}, &out, io.Discard); err == nil || !strings.Contains(err.Error(), "holds no regular file") || out.Len() != 0 {
		t.Errorf("an empty root: %v (wrote %d bytes)", err, out.Len())
	}
}

// A value is found where an encoding put it, by the set the builder writes: after an
// escaped character in a URL, in another letter case inside a wrapped base64 file, and
// form-encoded with + for its spaces, which the builder withholds as a second form under
// the value's label. Each find names the label once.
func TestBuildThenScanFindsEncodedValues(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "seeds.txt"), "731904\nKestrel-42\nfly north 7\nABC12345\nabc12345\n")
	var set, errs bytes.Buffer
	if _, err := run([]string{"build", "-mode", "audit", "-values", filepath.Join(dir, "seeds.txt")}, &set, &errs); err != nil {
		t.Fatal(err)
	}
	var parsed setFile
	if err := json.Unmarshal(set.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range parsed.Entries {
		got = append(got, fmt.Sprintf("%s/%d", e.Label, e.Length))
	}
	// Line 5 is line 4 in another case: the same entry, since values match in any case.
	if strings.Join(got, " ") != "seeds.txt:1/6 seeds.txt:2/10 seeds.txt:3/11 seeds.txt:3/11 seeds.txt:4/8" || parsed.Version != withheld.Version {
		t.Fatalf("entries %v, version %d", got, parsed.Version)
	}
	if !strings.Contains(errs.String(), "seeds.txt:5 is the same value (in any letter case) as seeds.txt:4") {
		t.Errorf("stderr: %s", errs.String())
	}
	if strings.Contains(strings.ToLower(set.String()), "kestrel") || strings.Contains(set.String(), "north") {
		t.Fatalf("the set holds a value: %s", set.String())
	}
	setPath := filepath.Join(dir, "set.json")
	write(t, setPath, set.String())

	task := filepath.Join(dir, "task")
	write(t, filepath.Join(task, "link.txt"), "next=viewer.html%3Fseed%3D731904%26case%3D2\n")
	encoded := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("# config\n", 8) + "name: KESTREL-42\n"))
	write(t, filepath.Join(task, "config.b64"), wrapAt(encoded, 76))
	write(t, filepath.Join(task, "form.txt"), "q=fly+north+7&again=fly%20north%207")
	write(t, filepath.Join(task, "notes.txt"), "seed 1731904 and kestrel-420 are other strings")
	var out bytes.Buffer
	code, err := run([]string{"scan", "-set", setPath, task}, &out, io.Discard)
	if err != nil || code != 1 {
		t.Fatalf("scan: %d, %v\n%s", code, err, out.String())
	}
	at := func(name string) string { return filepath.ToSlash(filepath.Join(task, name)) }
	want := "seeds.txt:1 (audit): " + at("link.txt") + "\n" +
		"seeds.txt:2 (audit): " + at("config.b64") + "\n" +
		"seeds.txt:3 (audit): " + at("form.txt") + "\n"
	if out.String() != want {
		t.Errorf("scan output:\n%s\nwant:\n%s", out.String(), want)
	}
}

func wrapAt(s string, n int) string {
	var b strings.Builder
	for len(s) > n {
		b.WriteString(s[:n] + "\n")
		s = s[n:]
	}
	return b.String() + s + "\n"
}

// An empty file (or one of blank lines) in a withheld directory is skipped and said:
// its entry would match every empty file a caller ships, such as an __init__.py.
func TestBuildSkipsAnEmptyFile(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "harness", "__init__.py"), "")
	write(t, filepath.Join(dir, "harness", "blank.txt"), "\n  \n\n")
	write(t, filepath.Join(dir, "harness", "sim.py"), "x = step(1)\n")
	var set, errs bytes.Buffer
	if _, err := run([]string{"build", "-mode", "refuse", "-file", filepath.Join(dir, "harness")}, &set, &errs); err != nil {
		t.Fatal(err)
	}
	var parsed setFile
	if err := json.Unmarshal(set.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Entries) != 1 || parsed.Entries[0].Label != "harness/sim.py" {
		t.Fatalf("entries %+v", parsed.Entries)
	}
	for _, name := range []string{"__init__.py is empty", "blank.txt is empty"} {
		if !strings.Contains(errs.String(), name) {
			t.Errorf("stderr lacks %q: %s", name, errs.String())
		}
	}
	setPath := filepath.Join(dir, "set.json")
	write(t, setPath, set.String())
	task := filepath.Join(dir, "task")
	write(t, filepath.Join(task, "pkg", "__init__.py"), "")
	var out bytes.Buffer
	if code, err := run([]string{"scan", "-set", setPath, task}, &out, io.Discard); err != nil || code != 0 {
		t.Errorf("an empty file the caller ships: %d, %v, %s", code, err, out.String())
	}
	if _, err := run([]string{"build", "-mode", "refuse", "-file", filepath.Join(dir, "harness", "__init__.py")}, io.Discard, io.Discard); err == nil {
		t.Error("a set of nothing but an empty file was built")
	}
}

// The offline scan reads inside archives as the daemon does: the harness packed in a
// .tar.gz on disk is found, and an archive past a bound is said and fails the scan.
func TestScanReadsArchives(t *testing.T) {
	dir := t.TempDir()
	sim := "import numpy as np\n\ndef step(state, u, dt):\n    return state + dt * (u - 0.3 * state)\n"
	write(t, filepath.Join(dir, "harness", "sim.py"), sim)
	var set bytes.Buffer
	if _, err := run([]string{"build", "-mode", "refuse", "-file", filepath.Join(dir, "harness")}, &set, io.Discard); err != nil {
		t.Fatal(err)
	}
	setPath := filepath.Join(dir, "set.json")
	write(t, setPath, set.String())

	var tgz bytes.Buffer
	gz := gzip.NewWriter(&tgz)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "vendor/model.py", Mode: 0o644, Size: int64(len(sim)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	io.WriteString(tw, sim)
	tw.Close()
	gz.Close()
	task := filepath.Join(dir, "task")
	write(t, filepath.Join(task, "deps.tgz"), tgz.String())
	var out bytes.Buffer
	code, err := run([]string{"scan", "-set", setPath, task}, &out, io.Discard)
	if want := "harness/sim.py (refuse): " + filepath.ToSlash(filepath.Join(task, "deps.tgz")); err != nil || code != 1 || !strings.Contains(out.String(), want) {
		t.Fatalf("scan: %d, %v; want %q in:\n%s", code, err, want, out.String())
	}

	var bomb bytes.Buffer
	gz = gzip.NewWriter(&bomb)
	gz.Write(make([]byte, withheld.MaxArchiveBytes+1))
	gz.Close()
	big := filepath.Join(dir, "big")
	write(t, filepath.Join(big, "zeros.gz"), bomb.String())
	out.Reset()
	code, err = run([]string{"scan", "-set", setPath, big}, &out, io.Discard)
	if want := "incomplete: " + filepath.ToSlash(filepath.Join(big, "zeros.gz")) + ": " + withheld.BoundArchiveBytes.Text(); err != nil || code != 1 || !strings.Contains(out.String(), want) {
		t.Fatalf("scan: %d, %v; want %q in:\n%s", code, err, want, out.String())
	}
}

// -source withholds a file's lines: an edited copy, shipped under another name, is
// found, in audit mode unless -source-mode says otherwise; a file with too few
// distinctive lines is skipped and said.
func TestBuildSourceFindsAnEditedCopy(t *testing.T) {
	dir := t.TempDir()
	plant := `WIND_GUST_TABLE = [0.12, 0.37, 0.05, 0.44, 0.29, 0.08]
def wind_at(t, seed):
    rng = np.random.default_rng(seed + int(t * 1000))
    gust = WIND_GUST_TABLE[int(t * 7) % len(WIND_GUST_TABLE)]
    return gust * rng.standard_normal()
def step(state, u, dt, seed):
    accel = u - DRAG_COEFFICIENT * vel * abs(vel) - GRAVITY_MPS2
    accel_with_wind = accel + wind_at(position_now, seed)
    return np.array([pos + dt * vel_next, vel_next])
def score(trajectory, target):
    errors = [abs(p - target) for p, _ in trajectory]
    settled = next((i for i, e in enumerate(errors) if e < 0.05), len(errors))
    return 100.0 - 0.5 * settled - 10.0 * max(errors[-20:])
`
	write(t, filepath.Join(dir, "harness", "plant.py"), plant)
	write(t, filepath.Join(dir, "harness", "tiny.py"), "x = 1\n")
	var set, errs bytes.Buffer
	if _, err := run([]string{"build", "-mode", "refuse", "-source", filepath.Join(dir, "harness")}, &set, &errs); err != nil {
		t.Fatal(err)
	}
	var parsed setFile
	if err := json.Unmarshal(set.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Entries) != 1 || parsed.Entries[0].Kind != withheld.KindSource || parsed.Entries[0].Label != "harness/plant.py" ||
		parsed.Entries[0].Mode != "audit" || len(parsed.Entries[0].Lines) != 12 || parsed.Entries[0].MinLines != withheld.MinSourceLines {
		t.Fatalf("entries %+v", parsed.Entries)
	}
	if !strings.Contains(errs.String(), "tiny.py has 0 distinctive lines") {
		t.Errorf("stderr: %s", errs.String())
	}
	setPath := filepath.Join(dir, "set.json")
	write(t, setPath, set.String())
	task := filepath.Join(dir, "task")
	write(t, filepath.Join(task, "sim", "model.py"), "import numpy as np\n\n"+strings.ReplaceAll(strings.ReplaceAll(plant, "def step(", "def advance("), "    ", "\t"))
	var out bytes.Buffer
	code, err := run([]string{"scan", "-set", setPath, task}, &out, io.Discard)
	if want := "harness/plant.py (audit): " + filepath.ToSlash(filepath.Join(task, "sim", "model.py")); err != nil || code != 1 || !strings.Contains(out.String(), want) {
		t.Fatalf("scan: %d, %v; want %q in:\n%s", code, err, want, out.String())
	}
	if _, err := run([]string{"build", "-mode", "refuse", "-source", filepath.Join(dir, "harness", "tiny.py")}, io.Discard, io.Discard); err == nil {
		t.Error("a set from a file of no distinctive line was built")
	}
}
