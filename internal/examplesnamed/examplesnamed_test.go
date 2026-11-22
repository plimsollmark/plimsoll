package examplesnamed

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestEveryShippedExampleIsNamed is the check itself, on this tree: every example that
// ships is named by a page that ships.
func TestEveryShippedExampleIsNamed(t *testing.T) {
	missing, err := Missing(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, ex := range missing {
		t.Errorf("%s ships but no public page names it: name it in the guide section it belongs to (README.md, clients/<client>/README.md, docs/*.md, docs/examples/), or, if it is not meant to be run, add it to Excluded with why", ex)
	}
}

func write(t *testing.T, root, name, text string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

// A planted example no page names fails, in both forms of the tree: the published one,
// where every present file ships, and the working copy, where only core lines ship.
func TestAPlantedUnnamedExampleFails(t *testing.T) {
	Excluded["examples/internal"] = "shared packages, never run on their own"
	defer delete(Excluded, "examples/internal")
	for _, withManifest := range []bool{false, true} {
		root := t.TempDir()
		write(t, root, "README.md", "Run examples/grant and `langchain_tool.py`.\n")
		write(t, root, "clients/python/examples/langchain_tool.py", "")
		write(t, root, "clients/python/examples/_shared.py", "")         // a helper: never an example
		write(t, root, "clients/python/examples/planted_unnamed.py", "") // the plant
		write(t, root, "examples/grant/main.go", "")
		write(t, root, "examples/grant-planted/main.go", "") // "examples/grant" in the README does not name it
		write(t, root, "examples/internal/shim/shim.go", "") // in Excluded
		want := []string{"clients/python/examples/planted_unnamed.py", "examples/grant-planted"}
		if withManifest {
			write(t, root, "examples/held/main.go", "") // private: does not ship, needs no page
			write(t, root, Manifest, strings.Join([]string{
				"# comment",
				"core README.md",
				"core clients/python/examples/langchain_tool.py",
				"core clients/python/examples/_shared.py",
				"core clients/python/examples/planted_unnamed.py",
				"core examples/grant/main.go",
				"core examples/grant-planted/main.go",
				"core examples/internal/shim/shim.go",
				"private examples/held/main.go",
			}, "\n")+"\n")
		}
		got, err := Missing(root)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(got, want) {
			t.Errorf("manifest %v: Missing = %q, want %q", withManifest, got, want)
		}
	}
}

// A page that does not ship names nothing: in the working copy, a private page that
// names the example leaves it unnamed.
func TestAPrivatePageNamesNothing(t *testing.T) {
	root := t.TempDir()
	write(t, root, "docs/held.md", "examples/grant\n")
	write(t, root, "examples/grant/main.go", "")
	write(t, root, Manifest, "private docs/held.md\ncore examples/grant/main.go\n")
	got, err := Missing(root)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"examples/grant"}) {
		t.Errorf("Missing = %q, want examples/grant", got)
	}
}

func TestNamedIsAWholeName(t *testing.T) {
	cases := []struct {
		text, ex string
		want     bool
	}{
		{"see examples/fanout.", "examples/fanout", true},
		{"[x](../examples/fanout/)", "examples/fanout", true},
		{"https://github.com/o/r/tree/main/examples/fanout", "examples/fanout", true},
		{"examples/fanout-cartpole", "examples/fanout", false},
		{"clients/typescript/examples/grant", "examples/grant", false},
		{"docs/examples/grant/index.html", "examples/grant", false},
		{"myexamples/grant", "examples/grant", false},
		{"`langchain_tool.py`", "clients/python/examples/langchain_tool.py", true},
		{"examples/langchain_tool.py", "clients/python/examples/langchain_tool.py", true},
		{"my_langchain_tool.py", "clients/python/examples/langchain_tool.py", false},
		{"langchain_tool.pyc", "clients/python/examples/langchain_tool.py", false},
		{"examples/fanout-cartpole and examples/fanout", "examples/fanout", true},
	}
	for _, c := range cases {
		if got := Named(c.text, c.ex); got != c.want {
			t.Errorf("Named(%q, %q) = %v, want %v", c.text, c.ex, got, c.want)
		}
	}
}
