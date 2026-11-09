package main

import (
	"errors"
	"fmt"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
)

// Tree is the harness's own code as a run found it: the commit, and whether the checkout held a
// change the commit does not (an edit or an untracked file) in the code the run executes. run.json
// records it, so a reader can tell which code ran; a paid run refuses a tree that is not clean.
type Tree struct {
	Commit string   `json:"commit"`
	Clean  bool     `json:"clean"`
	Dirty  []string `json:"dirty,omitempty"` // the first changed or untracked paths, when not clean
	From   string   `json:"from"`            // git, a module version, or why neither could be read
}

// harnessTree reads the tree of this program's own source; tests replace it.
var harnessTree = func() Tree {
	_, file, _, ok := runtime.Caller(0)
	if ok && filepath.IsAbs(file) {
		if t, err := treeState(filepath.Dir(file)); err == nil {
			return t
		}
	}
	// Built from a module version (go run module@version): the code is the version's, checked
	// against the checksum database, so it is clean by construction.
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return Tree{Commit: bi.Main.Path + "@" + bi.Main.Version, Clean: true, From: "module version"}
	}
	return Tree{From: "unknown: the source is neither a git checkout nor a module version"}
}

// treeCode are the paths whose change changes what this program does: the module's Go code, its
// go.mod and go.sum, and this example's files (the course, the jobs). Nested modules (each its own
// go.mod) are left out, since this program does not build them; so are documents and data.
var treeCode = []string{"*.go", "go.mod", "go.sum", "examples/squeeze"}

// treeState is the commit and the code changes of the git checkout holding dir.
func treeState(dir string) (Tree, error) {
	git := func(args ...string) (string, error) {
		out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).Output()
		return strings.TrimSpace(string(out)), err
	}
	top, err := git("rev-parse", "--show-toplevel")
	if err != nil {
		return Tree{}, fmt.Errorf("not a git checkout: %w", err)
	}
	commit, err := git("rev-parse", "HEAD")
	if err != nil {
		return Tree{}, err
	}
	dir = top
	mods, err := git("ls-files", "--", "*/go.mod")
	if err != nil {
		return Tree{}, err
	}
	spec := append([]string{"status", "--porcelain", "--untracked-files=all", "--"}, treeCode...)
	for _, m := range strings.Fields(mods) {
		spec = append(spec, ":(exclude)"+path.Dir(m))
	}
	st, err := git(spec...)
	if err != nil {
		return Tree{}, err
	}
	t := Tree{Commit: commit, Clean: st == "", From: "git"}
	for i, line := range strings.Split(st, "\n") {
		if line == "" {
			continue
		}
		if i == 8 {
			t.Dirty = append(t.Dirty, "...")
			break
		}
		t.Dirty = append(t.Dirty, line)
	}
	return t, nil
}

// errDirtyTree is a paid run refused because the code it would run is not a commit's.
var errDirtyTree = errors.New("a paid run runs only a commit's code: commit or remove the changes in the harness's code first")
