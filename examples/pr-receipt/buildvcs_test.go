package main

import (
	"debug/buildinfo"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// stampWorld makes throwaway git repositories holding a tiny Go module, runs buildvcs.sh on them, and builds them as
// receipt.sh builds plimsolld, reading back what Go stamped. Every git, go and script run gets an environment of its
// own: none of the caller's GIT_ variables, Go settings or git configuration, and a module cache per build, since Go
// can answer a stamp from its module cache.
type stampWorld struct {
	t       *testing.T
	root    string
	bash    string
	script  string
	gocache string
	n       int
}

func newStampWorld(t *testing.T) *stampWorld {
	t.Helper()
	for _, tool := range []string{"git", "bash", "go"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
	bash, _ := exec.LookPath("bash")
	script, err := filepath.Abs("buildvcs.sh")
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("go", "env", "GOCACHE").Output()
	if err != nil {
		t.Fatal(err)
	}
	w := &stampWorld{t: t, root: t.TempDir(), bash: bash, script: script, gocache: strings.TrimSpace(string(out))}
	if err := os.Mkdir(filepath.Join(w.root, "home"), 0o755); err != nil {
		t.Fatal(err)
	}
	return w
}

// env is the environment of a script or go run: the test's own, less git's variables and Go's settings, plus extra
// (a later entry wins). No network: the proxy is a path that does not exist, and the tiny module needs nothing.
func (w *stampWorld) env(extra ...string) []string {
	var env []string
	drop := []string{"GOFLAGS=", "GOPROXY=", "GOSUMDB=", "GONOSUMDB=", "GONOPROXY=", "GOPRIVATE=", "GOTOOLCHAIN=", "GOMODCACHE=",
		"GOWORK=", "GOENV=", "GOCACHE=", "GOPATH=", "HOME=", "XDG_CONFIG_HOME=", "CDPATH="}
	for _, e := range os.Environ() {
		keep := !strings.HasPrefix(e, "GIT_")
		for _, d := range drop {
			keep = keep && !strings.HasPrefix(e, d)
		}
		if keep {
			env = append(env, e)
		}
	}
	w.n++
	env = append(env, "HOME="+filepath.Join(w.root, "home"), "XDG_CONFIG_HOME="+filepath.Join(w.root, "home", ".config"),
		"GOCACHE="+w.gocache, "GOPATH="+filepath.Join(w.root, "gopath"), "GOMODCACHE="+filepath.Join(w.root, fmt.Sprintf("modcache-%d", w.n)),
		"GOTOOLCHAIN=local", "GOPROXY=file:///nonexistent-proxy", "GOSUMDB=off", "GOFLAGS=-modcacherw", "GOWORK=off")
	return append(env, extra...)
}

func (w *stampWorld) git(dir string, args ...string) string {
	w.t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.com",
		"-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", "-c", "init.defaultBranch=main", "-c", "protocol.file.allow=always"}, args...)...)
	cmd.Env = w.env("GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		w.t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// module writes a tiny main module at dir; its source names dir, so no two repositories share a commit.
func (w *stampWorld) module(dir, path string) {
	w.t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		w.t.Fatal(err)
	}
	for name, body := range map[string]string{"go.mod": "module " + path + "\n\ngo 1.26\n", "main.go": "package main\n\n// " + dir + "\nfunc main() {}\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			w.t.Fatal(err)
		}
	}
}

// repo is a new repository at root/name holding the module, one commit, and the tags (lightweight).
func (w *stampWorld) repo(name, path string, tags ...string) string {
	w.t.Helper()
	dir := filepath.Join(w.root, name)
	w.module(dir, path)
	w.git(dir, "init", "-q")
	w.git(dir, "add", "-A")
	w.git(dir, "commit", "-q", "-m", name)
	for _, tag := range tags {
		w.git(dir, "tag", tag)
	}
	return dir
}

// shallow imitates the checkout action given a commit SHA: one commit fetched by its SHA at depth 1, no tags, then a
// detached checkout of it (actions/checkout's git-command-manager and ref-helper at the commit the workflow pins).
func (w *stampWorld) shallow(origin, sha, name string) string {
	w.t.Helper()
	dir := filepath.Join(w.root, name)
	if err := os.Mkdir(dir, 0o755); err != nil {
		w.t.Fatal(err)
	}
	w.git(dir, "init", "-q")
	w.git(dir, "remote", "add", "origin", "file://"+origin)
	w.git(dir, "-c", "protocol.version=2", "fetch", "-q", "--no-tags", "--prune", "--no-recurse-submodules", "--depth=1", "origin", sha)
	w.git(dir, "checkout", "-q", "--force", sha)
	return dir
}

// answer is what buildvcs.sh prints for dir.
func (w *stampWorld) answer(dir string, env []string) string {
	w.t.Helper()
	cmd := exec.Command(w.bash, w.script, dir)
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		w.t.Fatalf("buildvcs.sh %s: %v", dir, err)
	}
	return strings.TrimSpace(string(out))
}

// check is buildvcs.sh's second form on a binary built from dir.
func (w *stampWorld) check(dir, binary string, env []string) error {
	cmd := exec.Command(w.bash, w.script, dir, binary)
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// stamp is what one build states.
type stamp struct {
	version  string // the main module's version, or "build fails"
	revision string
	modified string
	vcs      bool // any vcs setting at all
	binary   string
}

func (w *stampWorld) build(dir, buildvcs string, env []string) stamp {
	w.t.Helper()
	w.n++
	binary := filepath.Join(w.root, fmt.Sprintf("bin-%d", w.n))
	cmd := exec.Command("go", "-C", dir, "build", "-buildvcs="+buildvcs, "-o", binary, ".")
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		if buildvcs == "false" {
			w.t.Fatalf("go build -buildvcs=false in %s: %v\n%s", dir, err, out)
		}
		return stamp{version: "build fails"}
	}
	bi, err := buildinfo.ReadFile(binary)
	if err != nil {
		w.t.Fatal(err)
	}
	s := stamp{version: bi.Main.Version, binary: binary}
	for _, kv := range bi.Settings {
		switch {
		case kv.Key == "vcs.revision":
			s.revision = kv.Value
		case kv.Key == "vcs.modified":
			s.modified = kv.Value
		}
		s.vcs = s.vcs || kv.Key == "vcs" || strings.HasPrefix(kv.Key, "vcs.")
	}
	return s
}

// stampMatches: want is a version, a version ending in * (a pseudo-version's prefix), or "build fails".
func stampMatches(got, want string) bool {
	if p, ok := strings.CutSuffix(want, "*"); ok {
		return strings.HasPrefix(got, p)
	}
	return got == want
}

// TestTheStampIsKeptOnlyWhereGoStampsTheRelease holds buildvcs.sh to Go's own behavior, not to a description of it:
// for each checkout it builds a tiny module with the script's answer and reads back what Go stamped. Whenever the
// script answers true, the binary states the release tag the case names, at the checkout's HEAD, unmodified, and the
// second form accepts it; whenever it answers false, the binary states (devel) and carries no version control
// setting. goStamps is what Go stamps there with -buildvcs=true, so each case shows the stamp the answer keeps or
// leaves out (measured with Go 1.26.11; a toolchain that stamps otherwise fails here, which is the point). The one
// case the first form cannot see (with GOPROXY=off, a pseudo-version Go's module cache remembers for the commit) is
// caught by the second form, and the recipe's second build then states (devel).
func TestTheStampIsKeptOnlyWhereGoStampsTheRelease(t *testing.T) {
	w := newStampWorld(t)
	annotated := func(name string, tags ...string) string {
		dir := w.repo(name, "example.com/tiny")
		for _, tag := range tags {
			w.git(dir, "tag", "-a", "-m", tag, tag)
		}
		return dir
	}
	changed := func(name, file string, hide bool) string {
		dir := w.repo(name, "example.com/tiny", "v0.28.0")
		if hide {
			w.git(dir, "config", "status.showUntrackedFiles", "no")
		}
		body := "package main\n\n// changed\n"
		if file == "main.go" {
			body += "func main() {}\n"
		}
		if err := os.WriteFile(filepath.Join(dir, file), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	// The origin a shallow checkout fetches from: one commit with a lightweight and an annotated release tag.
	origin := w.repo("origin", "example.com/tiny", "v0.27.2")
	w.git(origin, "tag", "-a", "-m", "v0.27.3", "v0.27.3")
	sha := w.git(origin, "rev-parse", "HEAD")
	other := w.repo("other", "example.com/other", "v1.4.0")
	noGit := filepath.Join(w.root, "nogit-bin")
	if err := os.Mkdir(noGit, 0o755); err != nil {
		t.Fatal(err)
	}
	goPath, _ := exec.LookPath("go")
	if err := os.Symlink(goPath, filepath.Join(noGit, "go")); err != nil {
		t.Fatal(err)
	}
	remembered := filepath.Join(w.root, "remembered-modcache")

	for _, c := range []struct {
		name      string
		setup     func(t *testing.T) (dir string, env []string)
		want      string // the answer the case requires ("" for either: the invariant alone)
		release   string // the tag a true answer must stamp
		goStamps  string // what Go stamps with -buildvcs=true
		cacheOnly bool   // only the second form can see what Go does here
	}{
		{name: "a plain clone at a release tag", want: "true", release: "v0.28.0", goStamps: "v0.28.0",
			setup: func(t *testing.T) (string, []string) { return w.repo("plain", "example.com/tiny", "v0.28.0"), nil }},
		{name: "an annotated release tag", want: "true", release: "v0.28.0", goStamps: "v0.28.0",
			setup: func(t *testing.T) (string, []string) { return annotated("annotated", "v0.28.0"), nil }},
		{name: "the first public release", want: "true", release: "v0.2.0", goStamps: "v0.2.0",
			setup: func(t *testing.T) (string, []string) { return w.repo("first", "example.com/tiny", "v0.2.0"), nil }},
		{name: "a release with a two-digit minor", want: "true", release: "v0.10.0", goStamps: "v0.10.0",
			setup: func(t *testing.T) (string, []string) { return w.repo("ten", "example.com/tiny", "v0.10.0"), nil }},
		{name: "a release past v1", want: "true", release: "v1.4.12", goStamps: "v1.4.12",
			setup: func(t *testing.T) (string, []string) { return w.repo("past1", "example.com/tiny", "v1.4.12"), nil }},
		{name: "a changed tracked file", want: "false", goStamps: "v0.28.0+dirty",
			setup: func(t *testing.T) (string, []string) { return changed("dirty", "main.go", false), nil }},
		{name: "an untracked file", want: "false", goStamps: "v0.28.0+dirty",
			setup: func(t *testing.T) (string, []string) { return changed("untracked", "extra.go", false), nil }},
		{name: "an untracked file git is set to hide", want: "false", goStamps: "v0.28.0",
			setup: func(t *testing.T) (string, []string) { return changed("hidden", "extra.go", true), nil }},
		{name: "an untagged commit", want: "false", goStamps: "v0.0.0-*",
			setup: func(t *testing.T) (string, []string) { return w.repo("untagged", "example.com/tiny"), nil }},
		{name: "a spent tag from before the public releases", want: "false", goStamps: "v0.1.7",
			setup: func(t *testing.T) (string, []string) { return w.repo("spent", "example.com/tiny", "v0.1.7"), nil }},
		{name: "a spent tag beside a release", want: "true", release: "v0.28.0", goStamps: "v0.28.0",
			setup: func(t *testing.T) (string, []string) {
				return w.repo("spentrelease", "example.com/tiny", "v0.1.7", "v0.28.0"), nil
			}},
		{name: "a pre-release tag", want: "false", goStamps: "v0.28.0-rc1",
			setup: func(t *testing.T) (string, []string) { return w.repo("rc", "example.com/tiny", "v0.28.0-rc1"), nil }},
		{name: "a tag that is no version", want: "false", goStamps: "v0.0.0-*",
			setup: func(t *testing.T) (string, []string) {
				return w.repo("noversion", "example.com/tiny", "release-candidate"), nil
			}},
		{name: "a leading zero in the patch number", want: "false", goStamps: "v0.0.0-*",
			setup: func(t *testing.T) (string, []string) { return w.repo("lz", "example.com/tiny", "v0.28.01"), nil }},
		{name: "a leading zero in the minor number past v1", want: "false", goStamps: "v0.0.0-*",
			setup: func(t *testing.T) (string, []string) { return w.repo("lz1", "example.com/tiny", "v1.01.0"), nil }},
		{name: "a leading zero in the minor number", want: "false", goStamps: "v0.0.0-*",
			setup: func(t *testing.T) (string, []string) { return w.repo("lz0", "example.com/tiny", "v0.02.0"), nil }},
		{name: "a release and a tag named latest", want: "true", release: "v0.28.0", goStamps: "v0.28.0",
			setup: func(t *testing.T) (string, []string) {
				return w.repo("latest", "example.com/tiny", "v0.28.0", "latest"), nil
			}},
		{name: "a release and a tag sorting before it", want: "true", release: "v0.28.0", goStamps: "v0.28.0",
			setup: func(t *testing.T) (string, []string) { return w.repo("aaa", "example.com/tiny", "v0.28.0", "aaa"), nil }},
		{name: "a release and a nested module's tag", want: "true", release: "v0.28.0", goStamps: "v0.28.0",
			setup: func(t *testing.T) (string, []string) {
				return w.repo("nestedtag", "example.com/tiny", "v0.28.0", "clients/mcp/v0.29.0"), nil
			}},
		{name: "two releases on one commit", want: "true", release: "v0.28.1", goStamps: "v0.28.1",
			setup: func(t *testing.T) (string, []string) {
				return w.repo("tworel", "example.com/tiny", "v0.28.0", "v0.28.1"), nil
			}},
		{name: "a release and v1.0.0 on one commit", want: "true", release: "v1.0.0", goStamps: "v1.0.0",
			setup: func(t *testing.T) (string, []string) {
				return w.repo("v1", "example.com/tiny", "v0.28.0", "v1.0.0"), nil
			}},
		{name: "a release and a later annotated release", want: "true", release: "v0.30.0", goStamps: "v0.30.0",
			setup: func(t *testing.T) (string, []string) {
				dir := w.repo("laterannotated", "example.com/tiny", "v0.28.0")
				w.git(dir, "tag", "-a", "-m", "v0.30.0", "v0.30.0")
				return dir, nil
			}},
		{name: "a release and its own release candidate", want: "true", release: "v0.28.0", goStamps: "v0.28.0",
			setup: func(t *testing.T) (string, []string) {
				return w.repo("ownrc", "example.com/tiny", "v0.28.0-rc.1", "v0.28.0"), nil
			}},
		{name: "a release and a higher release candidate", want: "false", goStamps: "v0.29.0-rc.1",
			setup: func(t *testing.T) (string, []string) {
				return w.repo("higherrc", "example.com/tiny", "v0.28.0", "v0.29.0-rc.1"), nil
			}},
		{name: "a release and a v2 tag", want: "true", release: "v0.28.0", goStamps: "v0.28.0",
			setup: func(t *testing.T) (string, []string) {
				return w.repo("v2tag", "example.com/tiny", "v0.28.0", "v2.0.0"), nil
			}},
		{name: "a release and a higher tag with build metadata", want: "false", goStamps: "v0.28.0",
			setup: func(t *testing.T) (string, []string) {
				return w.repo("meta", "example.com/tiny", "v0.28.0", "v0.29.0+meta"), nil
			}},
		{name: "a module path with a major version suffix", want: "false", goStamps: "v2.0.0-*",
			setup: func(t *testing.T) (string, []string) { return w.repo("v2path", "example.com/tiny/v2", "v0.28.0"), nil }},
		{name: "a worktree nested in its main checkout, at another release", want: "false", goStamps: "v0.29.0",
			setup: func(t *testing.T) (string, []string) {
				main := w.repo("main", "example.com/tiny", "v0.28.0")
				if err := os.WriteFile(filepath.Join(main, "main.go"), []byte("package main\n\nfunc main() { println(2) }\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				w.git(main, "commit", "-q", "-am", "two")
				w.git(main, "tag", "v0.29.0")
				if err := os.WriteFile(filepath.Join(main, ".git", "info", "exclude"), []byte("/wt/\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				w.git(main, "worktree", "add", "-q", "--detach", filepath.Join(main, "wt"), "v0.28.0")
				return filepath.Join(main, "wt"), nil
			}},
		{name: "a worktree outside its main checkout", want: "false",
			setup: func(t *testing.T) (string, []string) {
				main := w.repo("main2", "example.com/tiny", "v0.28.0")
				w.git(main, "worktree", "add", "-q", "--detach", filepath.Join(w.root, "wt2"), "v0.28.0")
				return filepath.Join(w.root, "wt2"), nil
			}},
		{name: "a submodule at a release tag", want: "false", goStamps: "(devel)",
			setup: func(t *testing.T) (string, []string) {
				src := w.repo("subsrc", "example.com/tiny", "v0.28.0")
				super := filepath.Join(w.root, "super")
				if err := os.MkdirAll(super, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(super, "README"), []byte("super\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				w.git(super, "init", "-q")
				w.git(super, "add", "README")
				w.git(super, "commit", "-q", "-m", "super")
				w.git(super, "submodule", "--quiet", "add", src, "plim")
				w.git(super, "commit", "-q", "-m", "submodule")
				return filepath.Join(super, "plim"), nil
			}},
		{name: "a module in a subdirectory of a tagged repository", want: "false", goStamps: "(devel)",
			setup: func(t *testing.T) (string, []string) {
				mono := filepath.Join(w.root, "mono")
				w.module(filepath.Join(mono, "third_party", "tiny"), "example.com/tiny")
				w.git(mono, "init", "-q")
				w.git(mono, "add", "-A")
				w.git(mono, "commit", "-q", "-m", "mono")
				w.git(mono, "tag", "v0.28.0")
				return filepath.Join(mono, "third_party", "tiny"), nil
			}},
		{name: "GIT_DIR and GIT_WORK_TREE naming another repository at its release", want: "false", goStamps: "v1.4.0",
			setup: func(t *testing.T) (string, []string) {
				return w.repo("redirected", "example.com/tiny"), []string{"GIT_DIR=" + filepath.Join(other, ".git"), "GIT_WORK_TREE=" + other}
			}},
		{name: "GIT_DIR alone naming another repository", want: "false", goStamps: "v1.4.0+dirty",
			setup: func(t *testing.T) (string, []string) {
				return w.repo("redirected2", "example.com/tiny"), []string{"GIT_DIR=" + filepath.Join(other, ".git")}
			}},
		// The same files as the other repository's release, committed apart and untagged: git's status is clean and
		// the work tree's top is this directory, so only the refusal of every GIT_ variable answers false.
		{name: "GIT_DIR naming another repository whose files match", want: "false", goStamps: "v1.4.0",
			setup: func(t *testing.T) (string, []string) {
				dir := filepath.Join(w.root, "twin")
				if err := os.Mkdir(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				for _, name := range []string{"go.mod", "main.go"} {
					b, err := os.ReadFile(filepath.Join(other, name))
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
						t.Fatal(err)
					}
				}
				w.git(dir, "init", "-q")
				w.git(dir, "add", "-A")
				w.git(dir, "commit", "-q", "-m", "a twin, untagged")
				return dir, []string{"GIT_DIR=" + filepath.Join(other, ".git")}
			}},
		// The repository's own configuration moves its work tree to a copy of the release, and the build directory
		// holds a change: git's status is clean and Go stamps the release over the changed code.
		{name: "a repository whose configuration moves its work tree elsewhere", want: "false", goStamps: "v0.28.0",
			setup: func(t *testing.T) (string, []string) {
				dir := w.repo("moved", "example.com/tiny", "v0.28.0")
				elsewhere := filepath.Join(w.root, "moved-tree")
				if err := os.Mkdir(elsewhere, 0o755); err != nil {
					t.Fatal(err)
				}
				for _, name := range []string{"go.mod", "main.go"} {
					b, err := os.ReadFile(filepath.Join(dir, name))
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(elsewhere, name), b, 0o644); err != nil {
						t.Fatal(err)
					}
				}
				w.git(dir, "config", "core.worktree", elsewhere)
				if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n\nfunc main() { println(\"changed\") }\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				return dir, nil
			}},
		{name: "git configuration from GIT_CONFIG_COUNT moving the work tree", want: "false", goStamps: "v0.28.0",
			setup: func(t *testing.T) (string, []string) {
				return w.repo("configured", "example.com/tiny", "v0.28.0"),
					[]string{"GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=core.worktree", "GIT_CONFIG_VALUE_0=" + other}
			}},
		{name: "a release with GIT_INDEX_FILE set", want: "false", goStamps: "v0.28.0+dirty",
			setup: func(t *testing.T) (string, []string) {
				return w.repo("index", "example.com/tiny", "v0.28.0"), []string{"GIT_INDEX_FILE=" + filepath.Join(w.root, "no-index")}
			}},
		{name: "no git installed", want: "false", goStamps: "build fails",
			setup: func(t *testing.T) (string, []string) {
				return w.repo("nogit", "example.com/tiny", "v0.28.0"), []string{"PATH=" + noGit}
			}},
		{name: "a shallow checkout of one commit without its tag", want: "false", goStamps: "v0.0.0-*",
			setup: func(t *testing.T) (string, []string) { return w.shallow(origin, sha, "shallow"), nil }},
		{name: "a shallow checkout of one commit, its lightweight release tag fetched", want: "true", release: "v0.27.2", goStamps: "v0.27.2",
			setup: func(t *testing.T) (string, []string) {
				dir := w.shallow(origin, sha, "shallowlight")
				w.git(dir, "fetch", "-q", "--no-tags", "--depth=1", "origin", "+refs/tags/v0.27.2:refs/tags/v0.27.2")
				return dir, nil
			}},
		{name: "a shallow checkout of one commit, its annotated release tag fetched", want: "true", release: "v0.27.3", goStamps: "v0.27.3",
			setup: func(t *testing.T) (string, []string) {
				dir := w.shallow(origin, sha, "shallowannotated")
				w.git(dir, "fetch", "-q", "--no-tags", "--depth=1", "origin", "+refs/tags/v0.27.3:refs/tags/v0.27.3")
				return dir, nil
			}},
		{name: "a directory that is no checkout", want: "false", goStamps: "(devel)",
			setup: func(t *testing.T) (string, []string) {
				dir := filepath.Join(w.root, "plaindir")
				w.module(dir, "example.com/tiny")
				return dir, nil
			}},
		{name: "a release whose commit Go's module cache remembers as a pseudo-version (GOPROXY=off)", want: "true",
			release: "v0.28.0", goStamps: "v0.0.0-*", cacheOnly: true,
			setup: func(t *testing.T) (string, []string) {
				dir := w.repo("remembered", "example.com/tiny")
				env := []string{"GOPROXY=off", "GOMODCACHE=" + remembered}
				w.build(dir, "true", w.env(env...)) // Go writes the untagged commit's pseudo-version into the cache
				w.git(dir, "tag", "v0.28.0")
				return dir, env
			}},
	} {
		t.Run(c.name, func(t *testing.T) {
			parent := w.t
			w.t = t
			defer func() { w.t = parent }()
			dir, extra := c.setup(t)
			env := w.env(extra...)
			got := w.answer(dir, env)
			goStamp := w.build(dir, "true", env)
			t.Logf("buildvcs.sh=%s, go -buildvcs=true stamps %s", got, goStamp.version)
			if c.want != "" && got != c.want {
				t.Errorf("buildvcs.sh says %q, want %q", got, c.want)
			}
			if c.goStamps != "" && !stampMatches(goStamp.version, c.goStamps) {
				t.Errorf("go -buildvcs=true stamps %s here, the case expects %s: Go's own behavior changed, so buildvcs.sh's rule needs measuring again", goStamp.version, c.goStamps)
			}
			// The recipe: build with the answer; when the second form refuses the binary, build again without the stamp.
			s := w.build(dir, got, env)
			refused := w.check(dir, s.binary, env)
			switch {
			case got == "true" && c.cacheOnly:
				if refused == nil {
					t.Fatalf("the second form accepts a binary stating %s at a release tag %s", s.version, c.release)
				}
				s = w.build(dir, "false", env)
				if err := w.check(dir, s.binary, env); err != nil {
					t.Errorf("the second form refuses the build without the stamp: %v", err)
				}
			case got == "true":
				head := w.git(dir, "rev-parse", "HEAD")
				if s.version != c.release || s.modified != "false" || s.revision != head {
					t.Errorf("buildvcs.sh says true and the build states %s at %s (modified %s); want the release %s at %s, unmodified",
						s.version, s.revision, s.modified, c.release, head)
				}
				if refused != nil {
					t.Errorf("the second form refuses the release build: %v", refused)
				}
			default:
				if refused != nil {
					t.Errorf("the second form refuses a build without the stamp: %v", refused)
				}
			}
			if got != "true" || c.cacheOnly {
				if s.version != "(devel)" || s.vcs {
					t.Errorf("the recipe's build states %s (version control settings: %v); want (devel) and none", s.version, s.vcs)
				}
			}
		})
	}
}
