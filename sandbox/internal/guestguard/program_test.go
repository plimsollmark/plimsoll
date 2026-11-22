package guestguard

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// buildInputs are the files build.sh reads; guard.sha256 must pin each.
var buildInputs = []string{"program/guard.c", "guest_filter.h", "program/build.sh"}

// installedMachines is the INSTALLED line of build.sh: the machines whose guard is committed.
func installedMachines(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile("program/build.sh")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^readonly installed="([a-z0-9 ]+)"$`).FindSubmatch(b)
	if m == nil {
		t.Fatal(`build.sh has no line readonly installed="..."`)
	}
	return strings.Fields(string(m[1]))
}

// pins reads guard.sha256 (sha256sum's format) as file name to digest.
func pins(t *testing.T) map[string]string {
	t.Helper()
	b, err := programFiles.ReadFile("program/guard.sha256")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		sum, name, ok := strings.Cut(line, "  ")
		if !ok || len(sum) != 64 {
			t.Fatalf("guard.sha256: %q is not a sha256sum line", line)
		}
		if _, dup := out[name]; dup {
			t.Fatalf("guard.sha256 lists %s twice", name)
		}
		out[name] = sum
	}
	return out
}

func digest(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// TestProgramMatchesItsPin: guard.sha256 lists exactly the build's inputs and the installed
// programs, and every file has the digest it lists. A program changed without its pin, a pin
// changed without its program, and an input (the source, the generated header, so the table,
// or the build) changed without a rebuild each fail here; the gate cannot rebuild, so this is
// as far as it checks.
func TestProgramMatchesItsPin(t *testing.T) {
	p := pins(t)
	want := append([]string{}, buildInputs...)
	for _, g := range installedMachines(t) {
		want = append(want, ProgramFile(g))
	}
	var got []string
	for name := range p {
		got = append(got, name)
	}
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("guard.sha256 lists %v; the build reads and installs %v", got, want)
	}
	for _, name := range buildInputs {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if d := digest(b); d != p[name] {
			t.Errorf("%s has sha256 %s, guard.sha256 pins %s: it changed without a rebuild (run build.sh)", name, d, p[name])
		}
	}
	for _, g := range installedMachines(t) {
		b, err := Program(g)
		if err != nil {
			t.Fatal(err)
		}
		if d := digest(b); d != p[ProgramFile(g)] {
			t.Errorf("%s has sha256 %s, guard.sha256 pins %s", ProgramFile(g), d, p[ProgramFile(g)])
		}
	}
}

// TestProgramCarriesTheFilter: each installed program is a static executable for its machine
// (no interpreter, so no loader reads the image's environment before it runs) and carries the
// bytes of the filter the table makes for that machine, once. This holds without the pin: a
// table changed without a rebuild fails here even if guard.sha256 were edited by hand.
func TestProgramCarriesTheFilter(t *testing.T) {
	tb := mustLoad(t)
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
		if f.Machine != machines[g] || f.Class != elf.ELFCLASS64 || f.Type != elf.ET_EXEC {
			t.Errorf("%s is %v %v %v, want a 64-bit executable for %v", ProgramFile(g), f.Class, f.Machine, f.Type, machines[g])
		}
		for _, p := range f.Progs {
			if p.Type == elf.PT_INTERP || p.Type == elf.PT_DYNAMIC {
				t.Errorf("%s has a %v segment: it is not statically linked", ProgramFile(g), p.Type)
			}
		}
		_ = f.Close()
		var found bool
		for _, v := range tb.Variants() {
			if v.Arch.GOARCH != g || v.Suffix != "" {
				continue
			}
			found = true
			prog, err := tb.Program(v)
			if err != nil {
				t.Fatal(err)
			}
			if n := bytes.Count(b, Encode(prog)); n != 1 {
				t.Errorf("%s carries the table's %s filter %d times, want once: rebuild with build.sh", ProgramFile(g), v.Arch.Name, n)
			}
		}
		if !found {
			t.Errorf("the table makes no filter for %s, but build.sh installs a guard for it", g)
		}
	}
}

// TestProgramMachines: Program answers for each installed machine and refuses any other with
// an error that says arm64 is not installed yet.
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
		case !inst[g] && err == nil:
			t.Errorf("Program(%s) answered %d bytes, but build.sh does not install it", g, len(b))
		case !inst[g] && !strings.Contains(err.Error(), "no guest guard program is built for "+g):
			t.Errorf("Program(%s): %v", g, err)
		}
	}
}

// TestBuildIsPinned: the build names its image by digest, never by a tag alone, and pins the
// compiler's download for both machines it can run on.
func TestBuildIsPinned(t *testing.T) {
	b, err := os.ReadFile("program/build.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !regexp.MustCompile(`(?m)^readonly image="[a-z0-9./-]+@sha256:[0-9a-f]{64}"$`).MatchString(s) {
		t.Error("build.sh's image is not pinned by digest")
	}
	if n := len(regexp.MustCompile(`expected_zig_sha="[0-9a-f]{64}"`).FindAllString(s, -1)); n != 2 {
		t.Errorf("build.sh pins %d Zig downloads, want 2 (x86_64 and aarch64)", n)
	}
	for _, flag := range []string{"-static", "-linux-musl", "--network none", "cmp -s"} {
		if !strings.Contains(s, flag) {
			t.Errorf("build.sh lost %q", flag)
		}
	}
}
