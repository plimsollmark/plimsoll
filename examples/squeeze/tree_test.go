package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The tree a run records: the commit, clean while the code is the commit's; an edit or an
// untracked file in the module's code makes it dirty; a change in a nested module or a document
// does not. And a paid run refuses a tree that is not clean before it starts anything.
func TestARunRecordsItsCommitAndAPaidRunRefusesADirtyTree(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	dir := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	write := func(p, s string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, p)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, p), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	git("init", "-q")
	write("go.mod", "module x\n")
	write("a.go", "package x\n")
	write("nested/go.mod", "module y\n")
	git("add", ".")
	git("commit", "-q", "-m", "one")
	tr, err := treeState(filepath.Join(dir, "nested"))
	if err != nil {
		t.Fatal(err)
	}
	if !tr.Clean || len(tr.Commit) != 40 || tr.From != "git" {
		t.Fatalf("a committed tree: %+v", tr)
	}
	write("nested/b.go", "package y\n") // another module's code
	write("NOTES.md", "a note\n")       // a document
	if tr, _ = treeState(dir); !tr.Clean {
		t.Fatalf("a nested module's file or a document made the tree dirty: %+v", tr)
	}
	write("c.go", "package x\n")
	if tr, _ = treeState(dir); tr.Clean || len(tr.Dirty) != 1 || !strings.Contains(tr.Dirty[0], "c.go") {
		t.Fatalf("an untracked Go file: %+v", tr)
	}

	defer func(f func() Tree) { harnessTree = f }(harnessTree)
	harnessTree = func() Tree { return tr }
	t.Setenv("FAKE_MODEL_KEY", "k")
	err = runAndPublish(context.Background(), testJob(1, nil), "", t.TempDir(), "http://127.0.0.1:1", "", "", 1,
		modelOpts{api: "chat", model: "m", base: "https://example.invalid", keyEnv: "FAKE_MODEL_KEY", maxTokens: 1000, paid: true}, givenFresh{})
	if !errors.Is(err, errDirtyTree) || !strings.Contains(err.Error(), "c.go") {
		t.Fatalf("a paid run on a dirty tree: %v", err)
	}
}
