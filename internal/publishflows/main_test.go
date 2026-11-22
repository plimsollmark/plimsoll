package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var workflows = filepath.Join("..", "..", ".github", "workflows")

// TestPublishWorkflowsAreGenerated: every Python package's publish workflow is what the table
// and the template write, byte for byte (`make publish-workflows` writes them), and every
// workflow that publishes to PyPI has a row, so a new package cannot get a hand-made copy that
// drifts from the others.
func TestPublishWorkflowsAreGenerated(t *testing.T) {
	files, err := generate(workflows)
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range files {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("%s: %v (run make publish-workflows)", path, err)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s is not what internal/publishflows writes from its table; edit the table and run make publish-workflows\n%s", path, firstDiff(got, want))
		}
	}
	all, err := filepath.Glob(filepath.Join(workflows, "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range all {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := files[path]; !ok && strings.Contains(string(b), "pypa/gh-action-pypi-publish@") {
			t.Errorf("%s publishes to PyPI and has no row in internal/publishflows' table", path)
		}
	}
}

// TestPinsMustAgree: an action pinned to two commits in two workflow files is refused, so a pin
// edited in one file by hand cannot be written into the others.
func TestPinsMustAgree(t *testing.T) {
	dir := t.TempDir()
	src, err := filepath.Glob(filepath.Join(workflows, "*.yml"))
	if err != nil || len(src) == 0 {
		t.Fatalf("no workflows: %v", err)
	}
	for _, f := range src {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, filepath.Base(f)), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := generate(dir); err != nil {
		t.Fatalf("the copies do not generate: %v", err)
	}
	p := filepath.Join(dir, "publish-crewai.yml")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	edited := regexp.MustCompile(`actions/checkout@[0-9a-f]{40}`).ReplaceAll(b, []byte("actions/checkout@"+strings.Repeat("0", 40)))
	if bytes.Equal(edited, b) {
		t.Fatal("publish-crewai.yml pins no actions/checkout to edit")
	}
	if err := os.WriteFile(p, edited, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := generate(dir); err == nil || !strings.Contains(err.Error(), "one pin per action") {
		t.Errorf("two pins for actions/checkout were accepted: %v", err)
	}
}

// TestANewRowGetsAFile: a row with no file yet gets one, with a header naming its package and
// the checks every package row has.
func TestANewRowGetsAFile(t *testing.T) {
	pin, err := pins(workflows)
	if err != nil {
		t.Fatal(err)
	}
	p := Package{Workflow: "publish-example", Dir: "clients/python/example-plimsoll", Dist: "example-plimsoll",
		VersionFile: "clients/python/example-plimsoll/src/example_plimsoll/__init__.py", RequiresClient: true}
	b, err := render(p, nil, pin)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"# Publishes example-plimsoll (clients/python/example-plimsoll) to PyPI",
		"workflow publish-example.yml, environment pypi",
		"\nname: publish-example\n",
		"example_plimsoll/__init__.py does not say $version",
		"example-plimsoll does not require plimsoll-client==$version",
		"url: https://pypi.org/p/example-plimsoll",
	} {
		if !strings.Contains(string(b), want) {
			t.Errorf("a new row's file lacks %q:\n%s", want, b)
		}
	}
}

func firstDiff(got, want []byte) string {
	g, w := strings.Split(string(got), "\n"), strings.Split(string(want), "\n")
	for i := 0; i < len(g) || i < len(w); i++ {
		var a, b string
		if i < len(g) {
			a = g[i]
		}
		if i < len(w) {
			b = w[i]
		}
		if a != b {
			return "line " + itoa(i+1) + ":\n  file:      " + a + "\n  generated: " + b
		}
	}
	return "(same lines, different line endings)"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d []byte
	for ; n > 0; n /= 10 {
		d = append([]byte{byte('0' + n%10)}, d...)
	}
	return string(d)
}
