package nativehelper

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/sandbox/internal/runnerwire"
)

// buildInputs are the files build.sh reads in the crate's folder dir (its inputs line: the
// crate's manifest, lock file, toolchain file, the script itself and every file under src/,
// whatever its name, since the build copies the whole folder: finding rust-native-helper-33);
// the pin must list each.
func buildInputs(t *testing.T, dir string) []string {
	t.Helper()
	in := []string{"Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "build.sh"}
	n := 0
	err := filepath.WalkDir(filepath.Join(dir, "src"), func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		in = append(in, filepath.ToSlash(rel))
		if strings.HasSuffix(rel, ".rs") {
			n++
		}
		return nil
	})
	if err != nil || n == 0 {
		t.Fatalf("no Rust sources under %s/src: %v", dir, err)
	}
	return in
}

func buildScript(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("program/build.sh")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// installedMachines is build.sh's installed line.
func installedMachines(t *testing.T) []string {
	t.Helper()
	m := regexp.MustCompile(`(?m)^readonly installed="([a-z0-9 ]+)"$`).FindStringSubmatch(buildScript(t))
	if m == nil {
		t.Fatal(`build.sh has no line readonly installed="..."`)
	}
	return strings.Fields(m[1])
}

// pins reads plimsoll-helper.sha256 (sha256sum's format, paths relative to program/).
func pins(t *testing.T) map[string]string {
	t.Helper()
	b, err := programFiles.ReadFile("program/plimsoll-helper.sha256")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		sum, name, ok := strings.Cut(line, "  ")
		if !ok || len(sum) != 64 {
			t.Fatalf("plimsoll-helper.sha256: %q is not a sha256sum line", line)
		}
		if _, dup := out[name]; dup {
			t.Fatalf("plimsoll-helper.sha256 lists %s twice", name)
		}
		out[name] = sum
	}
	return out
}

func digest(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// TestProgramMatchesItsPin: the pin lists exactly the build's inputs and the installed
// programs, and every file has the digest it lists. A source changed without a rebuild, a
// program changed without its pin, and a pin changed without its program each fail here.
func TestProgramMatchesItsPin(t *testing.T) {
	p := pins(t)
	want := buildInputs(t, "program")
	for _, g := range installedMachines(t) {
		want = append(want, strings.TrimPrefix(ProgramFile(g), "program/"))
	}
	var got []string
	for name := range p {
		got = append(got, name)
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("plimsoll-helper.sha256 lists %v; the build reads and installs %v", got, want)
	}
	for _, name := range buildInputs(t, "program") {
		b, err := os.ReadFile(filepath.Join("program", name))
		if err != nil {
			t.Fatal(err)
		}
		if d := digest(b); d != p[name] {
			t.Errorf("%s has sha256 %s, the pin says %s: it changed without a rebuild (run program/build.sh)", name, d, p[name])
		}
	}
	for _, g := range installedMachines(t) {
		b, err := Program(g)
		if err != nil {
			t.Fatal(err)
		}
		if d, name := digest(b), strings.TrimPrefix(ProgramFile(g), "program/"); d != p[name] {
			t.Errorf("%s has sha256 %s, the pin says %s", ProgramFile(g), d, p[name])
		}
	}
}

// TestProgramIsStatic: each installed program is a 64-bit executable for its machine with no
// interpreter and no shared library to load (static musl: no loader reads the image's
// environment, LD_PRELOAD included, before it runs; the design review's finding 7), and it
// carries the report marker runnerwire states.
func TestProgramIsStatic(t *testing.T) {
	machines := map[string]elf.Machine{"amd64": elf.EM_X86_64, "arm64": elf.EM_AARCH64}
	for _, g := range installedMachines(t) {
		b, err := Program(g)
		if err != nil {
			t.Fatal(err)
		}
		f, err := elf.NewFile(bytes.NewReader(b))
		if err != nil {
			t.Fatalf("%s: %v", ProgramFile(g), err)
		}
		if f.Machine != machines[g] || f.Class != elf.ELFCLASS64 || (f.Type != elf.ET_EXEC && f.Type != elf.ET_DYN) {
			t.Errorf("%s is %v %v %v, want a 64-bit executable for %v", ProgramFile(g), f.Class, f.Machine, f.Type, machines[g])
		}
		for _, p := range f.Progs {
			if p.Type == elf.PT_INTERP {
				t.Errorf("%s names an interpreter: it is not statically linked", ProgramFile(g))
			}
		}
		if libs, err := f.ImportedLibraries(); err != nil || len(libs) != 0 {
			t.Errorf("%s needs shared libraries %v (%v): it is not statically linked", ProgramFile(g), libs, err)
		}
		_ = f.Close()
		if n := bytes.Count(b, []byte(runnerwire.Marker)); n != 1 {
			t.Errorf("%s carries the report marker %q %d times, want once (runner.rs MARKER must match runnerwire.Marker)", ProgramFile(g), runnerwire.Marker, n)
		}
	}
}

// TestBuildIsPinned: the build names its image by digest, the toolchain exactly (the same
// version in build.sh and rust-toolchain.toml), builds for musl statically with no network
// and from the lock file, and compares its builds byte for byte.
func TestBuildIsPinned(t *testing.T) {
	s := buildScript(t)
	if !regexp.MustCompile(`(?m)^readonly image="rust@sha256:[0-9a-f]{64}"$`).MatchString(s) {
		t.Error("build.sh's image is not pinned by digest")
	}
	m := regexp.MustCompile(`(?m)^readonly rust_version="([0-9]+\.[0-9]+\.[0-9]+)"$`).FindStringSubmatch(s)
	tc, err := os.ReadFile("program/rust-toolchain.toml")
	if err != nil {
		t.Fatal(err)
	}
	if m == nil || !strings.Contains(string(tc), `channel = "`+m[1]+`"`) {
		t.Errorf("build.sh's toolchain %v is not rust-toolchain.toml's channel", m)
	}
	for _, flag := range []string{"x86_64-unknown-linux-musl", "+crt-static", "--network none", "--offline --locked", "cmp -s", "--build-id=none", "--remap-path-prefix"} {
		if !strings.Contains(s, flag) {
			t.Errorf("build.sh lost %q", flag)
		}
	}
}

// TestNoOutsideCrate: the crate depends on nothing (the design review's finding 8): its
// dependency table is empty and its lock file names the crate alone.
func TestNoOutsideCrate(t *testing.T) {
	manifest, err := os.ReadFile("program/Cargo.toml")
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`(?m)^\[dependencies\]\n(#.*\n|\n)*(\[|$)`).Match(manifest) {
		t.Error("Cargo.toml's [dependencies] is not empty")
	}
	for _, table := range []string{"[dev-dependencies]", "[build-dependencies]", "[target."} {
		if bytes.Contains(manifest, []byte(table)) {
			t.Errorf("Cargo.toml has %s", table)
		}
	}
	lock, err := os.ReadFile("program/Cargo.lock")
	if err != nil {
		t.Fatal(err)
	}
	if n := bytes.Count(lock, []byte("[[package]]")); n != 1 || !bytes.Contains(lock, []byte(`name = "plimsoll-helper"`)) {
		t.Errorf("Cargo.lock lists %d packages, want the crate alone", n)
	}
}

// TestBuildInputsAreEverySourceFile: build.sh's inputs line, run on a copy of the crate's
// folder holding one more file under src/ that is not Rust, names that file, as buildInputs
// does, and the pin test's comparison would then fail until the pin lists it (finding
// rust-native-helper-33); a file there whose name the list could not carry is refused.
func TestBuildInputsAreEverySourceFile(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Fatal("bash is needed to run build.sh's inputs line")
	}
	m := regexp.MustCompile(`(?ms)^(odd=.*?^fi\n)(readonly inputs=.*?)$`).FindStringSubmatch(buildScript(t))
	if m == nil {
		t.Fatal("build.sh has no odd= check followed by a readonly inputs= line")
	}
	inputs := func(dir string) ([]string, error) {
		cmd := exec.Command("bash", "-euc", `script_dir="$1"; `+m[1]+m[2]+`; echo "$inputs"`, "bash", dir)
		out, err := cmd.CombinedOutput()
		return strings.Fields(string(out)), err
	}
	copyTree := func(dst string) {
		t.Helper()
		err := filepath.WalkDir("program", func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel("program", path)
			if d.IsDir() {
				if d.Name() == "target" {
					return filepath.SkipDir
				}
				return os.MkdirAll(filepath.Join(dst, rel), 0o755)
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	got, err := inputs("program")
	if err != nil {
		t.Fatalf("build.sh's inputs line on the crate: %v: %v", err, got)
	}
	if want := buildInputs(t, "program"); !slices.Equal(got, want) {
		t.Fatalf("build.sh's inputs %v, buildInputs %v", got, want)
	}

	dir := t.TempDir()
	copyTree(dir)
	if err := os.MkdirAll(filepath.Join(dir, "src", "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "src", "data", "table.bin"), []byte{1, 2, 3}, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err = inputs(dir)
	if err != nil {
		t.Fatalf("build.sh's inputs line on a copy with src/data/table.bin: %v: %v", err, got)
	}
	if !slices.Contains(got, "src/data/table.bin") || !slices.Equal(got, buildInputs(t, dir)) {
		t.Fatalf("with src/data/table.bin, build.sh's inputs are %v and buildInputs %v; both must name it", got, buildInputs(t, dir))
	}
	if _, listed := pins(t)["src/data/table.bin"]; listed {
		t.Fatal("the committed pin lists src/data/table.bin")
	}

	if err := os.WriteFile(filepath.Join(dir, "src", "a b.rs"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := inputs(dir); err == nil {
		t.Fatalf("build.sh's inputs line took a file named with a space: %v", out)
	}
	if err := os.Remove(filepath.Join(dir, "src", "a b.rs")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("main.rs", filepath.Join(dir, "src", "link.rs")); err != nil {
		t.Fatal(err)
	}
	if out, err := inputs(dir); err == nil {
		t.Fatalf("build.sh's inputs line took a link under src/: %v", out)
	}
}

// goConst reads `NAME = value` (or `NAME = Signal(value)`) from a file of Go's own tables
// under GOROOT/src.
func goConst(t *testing.T, file, name string) int64 {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src", file))
	if err != nil {
		t.Fatalf("Go's table %s: %v", file, err)
	}
	m := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(name) + `\s+(?:[A-Za-z0-9]+\s+)?=\s+(?:Signal\()?(0x[0-9a-f]+|[0-9]+)\)?\s*$`).FindSubmatch(b)
	if m == nil {
		t.Fatalf("Go's table %s has no %s", file, name)
	}
	v, err := strconv.ParseInt(string(m[1]), 0, 64)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// rustConsts reads sys.rs's integer constants for each machine: a constant under
// #[cfg(target_arch = "...")] is that machine's, any other is both machines'.
func rustConsts(t *testing.T) map[string]map[string]int64 {
	t.Helper()
	b, err := os.ReadFile("program/src/sys.rs")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]int64{"x86_64": {}, "aarch64": {}}
	cfg := regexp.MustCompile(`^#\[cfg\(target_arch = "([a-z0-9_]+)"\)\]$`)
	def := regexp.MustCompile(`^(?:pub )?const ([A-Z0-9_]+): [a-z0-9_]+ = (0o[0-7_]+|0x[0-9a-f_]+|[0-9_]+);`)
	arch := ""
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if m := cfg.FindStringSubmatch(line); m != nil {
			arch = m[1]
			continue
		}
		m := def.FindStringSubmatch(line)
		if m == nil {
			arch = ""
			continue
		}
		v, err := strconv.ParseInt(strings.ReplaceAll(m[2], "_", ""), 0, 64)
		if err != nil {
			t.Fatalf("sys.rs: %s: %v", line, err)
		}
		for a := range out {
			if arch == "" || arch == a {
				if _, dup := out[a][m[1]]; dup {
					t.Fatalf("sys.rs defines %s twice for %s", m[1], a)
				}
				out[a][m[1]] = v
			}
		}
		if arch != "" {
			if _, known := out[arch]; !known {
				t.Fatalf("sys.rs has a constant for %s, a machine this test does not know", arch)
			}
		}
		arch = ""
	}
	return out
}

// TestSysConstantsMatchGo: every integer constant of sys.rs, on x86-64 and on aarch64, is the
// value in Go's own tables for that machine (syscall's zerrors and zsysnum files, which are
// generated from the kernel's headers, and the runtime's shared Linux definitions), so a value
// right on one machine and wrong on the other fails here on any machine (finding
// rust-native-helper-27: O_NOFOLLOW was x86-64's for both). POLLIN is in none of Go's tables;
// it is 1 on every Linux machine (the kernel's asm-generic/poll.h, which both use).
func TestSysConstantsMatchGo(t *testing.T) {
	goArch := map[string]string{"x86_64": "amd64", "aarch64": "arm64"}
	rust := rustConsts(t)
	for arch, consts := range rust {
		g := goArch[arch]
		want := map[string]int64{
			"O_NONBLOCK":       goConst(t, "syscall/zerrors_linux_"+g+".go", "O_NONBLOCK"),
			"O_NOFOLLOW":       goConst(t, "syscall/zerrors_linux_"+g+".go", "O_NOFOLLOW"),
			"O_CLOEXEC":        goConst(t, "syscall/zerrors_linux_"+g+".go", "O_CLOEXEC"),
			"PR_GET_DUMPABLE":  goConst(t, "syscall/zerrors_linux_"+g+".go", "PR_GET_DUMPABLE"),
			"PR_SET_DUMPABLE":  goConst(t, "syscall/zerrors_linux_"+g+".go", "PR_SET_DUMPABLE"),
			"SIGKILL":          goConst(t, "syscall/zerrors_linux_"+g+".go", "SIGKILL"),
			"SIGSTOP":          goConst(t, "syscall/zerrors_linux_"+g+".go", "SIGSTOP"),
			"SIGCHLD":          goConst(t, "syscall/zerrors_linux_"+g+".go", "SIGCHLD"),
			"SYS_RT_SIGACTION": goConst(t, "syscall/zsysnum_linux_"+g+".go", "SYS_RT_SIGACTION"),
			"SIG_SETMASK":      goConst(t, "runtime/os_linux_generic.go", "_SIG_SETMASK"),
			"SIGMAX":           goConst(t, "runtime/os_linux_generic.go", "_NSIG") - 1,
			"SIG_DFL":          goConst(t, "runtime/signal_unix.go", "_SIG_DFL"),
			"SIG_IGN":          goConst(t, "runtime/signal_unix.go", "_SIG_IGN"),
			"POLLIN":           1,
		}
		for name, v := range consts {
			w, checked := want[name]
			switch {
			case !checked:
				t.Errorf("sys.rs's %s (%s) is checked against no table here: add it", name, arch)
			case v != w:
				t.Errorf("sys.rs's %s is %#x on %s; Go's table says %#x", name, v, arch, w)
			}
		}
		for name := range want {
			if _, ok := consts[name]; !ok {
				t.Errorf("sys.rs defines no %s for %s", name, arch)
			}
		}
	}
	if rust["x86_64"]["O_NOFOLLOW"] == rust["aarch64"]["O_NOFOLLOW"] {
		t.Error("O_NOFOLLOW is one value for both machines; it is not")
	}
}

// TestNoDaemonPassesTheTestSwitch: the switch that skips the runner's non-dumpable call
// appears in the helper's own source and its built program, in tests, and in the review
// records that describe it, and in no other tracked file of the repository, of any kind (a
// script, a Dockerfile, an embedded program, a policy, a manifest), so nothing plimsoll starts
// can pass it (finding rust-native-helper-31). Outside a git checkout it reads every file
// instead. A string built in two pieces would still pass unseen; the helper's own self-check
// is the protection behind this scan: started with the switch it finds its descriptors open
// and runs nothing (measured 2026-11-20, the code review's evidence).
func TestNoDaemonPassesTheTestSwitch(t *testing.T) {
	main, err := os.ReadFile("program/src/main.rs")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(main, []byte(`"`+TestOnlyStayDumpable+`"`)) {
		t.Fatalf("main.rs does not define %s", TestOnlyStayDumpable)
	}
	root := filepath.Join("..", "..", "..")
	allowed := func(rel string) bool {
		switch {
		case strings.HasSuffix(rel, "_test.go"),
			rel == "sandbox/internal/nativehelper/helper.go",
			rel == "sandbox/internal/nativehelper/program/src/main.rs",
			strings.HasPrefix(rel, "sandbox/internal/nativehelper/program/plimsoll-helper_"),
			strings.HasPrefix(rel, "private/findings/"),
			strings.HasPrefix(rel, "private/reviews/"):
			return true
		}
		return false
	}
	// A tree that is not a checkout of its own can still sit inside one (the public export
	// stages its tree under the private checkout's tmp/), where git would list that
	// checkout's files under the folder, not this tree's: use git only when root is the top
	// of the checkout it finds.
	ownCheckout := false
	if top, err := exec.Command("git", "-C", root, "rev-parse", "--show-toplevel").Output(); err == nil {
		want, err1 := filepath.EvalSymlinks(root)
		got, err2 := filepath.EvalSymlinks(strings.TrimSpace(string(top)))
		want, _ = filepath.Abs(want)
		ownCheckout = err1 == nil && err2 == nil && want == got
	}
	var files []string
	var listed []byte
	err = errors.New("not a checkout of its own")
	if ownCheckout {
		listed, err = exec.Command("git", "-C", root, "ls-files", "-z").Output()
	}
	if out := listed; err == nil {
		for _, f := range strings.Split(strings.TrimRight(string(out), "\x00"), "\x00") {
			files = append(files, f)
		}
	} else {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				switch d.Name() {
				case ".git", "tmp", "node_modules", "target", ".claude":
					return filepath.SkipDir
				}
				return nil
			}
			rel, err := filepath.Rel(root, path)
			files = append(files, filepath.ToSlash(rel))
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(files) < 100 {
		t.Fatalf("read %d files; the repository has more", len(files))
	}
	for _, rel := range files {
		if allowed(rel) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(root, rel))
		if os.IsNotExist(err) {
			continue // tracked but deleted in this working copy
		}
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b, []byte("TestOnlyStayDumpable")) || bytes.Contains(b, []byte(TestOnlyStayDumpable)) {
			t.Errorf("%s names the runner's test-only switch", rel)
		}
	}
}

// TestProgramMachines: Program answers for each installed machine and refuses any other.
func TestProgramMachines(t *testing.T) {
	inst := map[string]bool{}
	for _, g := range installedMachines(t) {
		inst[g] = true
	}
	for _, g := range []string{"amd64", "arm64", "riscv64"} {
		b, err := Program(g)
		switch {
		case inst[g] && (err != nil || len(b) == 0):
			t.Errorf("Program(%s): %v", g, err)
		case !inst[g] && (err == nil || !strings.Contains(err.Error(), "no native helper is built for "+g)):
			t.Errorf("Program(%s): %d bytes, %v", g, len(b), err)
		}
	}
}
