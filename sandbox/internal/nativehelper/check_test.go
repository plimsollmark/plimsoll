package nativehelper

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestCheckRefusals: each way a report of the image's runner can fall short is a refusal
// that says what is wrong and wraps ErrNotTheHelper; the report of the pinned file passes.
func TestCheckRefusals(t *testing.T) {
	t.Parallel()
	n := func(i int) *int { return &i }
	want := strings.Repeat("ab", 32)
	other := strings.Repeat("0", 64)
	for _, c := range []struct {
		name string
		r    FileReport
		msg  string
	}{
		{"the pinned file", FileReport{Type: "file", UID: n(0), Mode: n(0o755), SHA256: want}, ""},
		{"read-only to root too", FileReport{Type: "file", UID: n(0), Mode: n(0o555), SHA256: want}, ""},
		{"no report", FileReport{}, "the check reported nothing for " + InContainer},
		{"missing", FileReport{Error: "ENOENT"}, "there is no file at " + InContainer + " (ENOENT)"},
		{"a link", FileReport{Type: "link", UID: n(0), Mode: n(0o777)}, InContainer + " is not a regular file (lstat: link)"},
		{"a folder", FileReport{Type: "other", UID: n(0), Mode: n(0o755)}, "is not a regular file (lstat: other)"},
		{"the guest's", FileReport{Type: "file", UID: n(61000), Mode: n(0o755), SHA256: want}, "owned by uid 61000 with mode 0755"},
		{"group-writable", FileReport{Type: "file", UID: n(0), Mode: n(0o775), SHA256: want}, "mode 0775; it must be root's and writable by no one else"},
		{"world-writable", FileReport{Type: "file", UID: n(0), Mode: n(0o757), SHA256: want}, "mode 0757"},
		{"setuid", FileReport{Type: "file", UID: n(0), Mode: n(0o4755), SHA256: want}, "has mode 4755; it must carry no setuid, setgid or sticky bit"},
		{"setgid", FileReport{Type: "file", UID: n(0), Mode: n(0o2755), SHA256: want}, "has mode 2755"},
		{"sticky", FileReport{Type: "file", UID: n(0), Mode: n(0o1755), SHA256: want}, "has mode 1755"},
		{"no owner", FileReport{Type: "file", Mode: n(0o755), SHA256: want}, "reported no owner or no mode"},
		{"no mode", FileReport{Type: "file", UID: n(0), SHA256: want}, "reported no owner or no mode"},
		{"other bytes", FileReport{Type: "file", UID: n(0), Mode: n(0o755), Size: 7, SHA256: other}, "has sha256 " + other + " (7 bytes); want " + want},
		{"no hash", FileReport{Type: "file", UID: n(0), Mode: n(0o755)}, "has sha256  (0 bytes)"},
	} {
		err := c.r.Check(want)
		switch {
		case c.msg == "" && err != nil:
			t.Errorf("%s: refused: %v", c.name, err)
		case c.msg != "" && (err == nil || !strings.Contains(err.Error(), c.msg) || !errors.Is(err, ErrNotTheHelper)):
			t.Errorf("%s: %v; want it to say %q and wrap ErrNotTheHelper", c.name, err, c.msg)
		}
	}
}

// TestCheckJSReadsTheFile: the program every provider runs in the sandbox reports a file's
// type, owner, mode, size and SHA-256 as Check reads them, a link as a link (never what it
// points at), and a missing path as its error code. Run with this machine's node.
func TestCheckJSReadsTheFile(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	prog, err := Program(runtime.GOARCH)
	if err != nil {
		t.Skip(err)
	}
	sum, err := SHA256(runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	file, link := filepath.Join(dir, "plimsoll-helper"), filepath.Join(dir, "link")
	if err := os.WriteFile(file, prog, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	report := func(p string) FileReport {
		t.Helper()
		out, err := exec.Command(node, "--eval", CheckJS, p).Output()
		if err != nil {
			t.Fatalf("CheckJS on %s: %v", p, err)
		}
		var r FileReport
		if err := json.Unmarshal(out, &r); err != nil {
			t.Fatalf("CheckJS on %s printed %q: %v", p, out, err)
		}
		return r
	}
	r := report(file)
	if r.Type != "file" || r.UID == nil || *r.UID != os.Getuid() || r.Mode == nil || *r.Mode != 0o755 || r.Size != int64(len(prog)) || r.SHA256 != sum {
		t.Fatalf("the helper's file: %+v", r)
	}
	// Owned by this user, not root: the one check a file of this test cannot pass.
	if err := r.Check(sum); os.Getuid() != 0 && (err == nil || !strings.Contains(err.Error(), "must be root's")) {
		t.Fatalf("Check of a file this user owns: %v", err)
	}
	if r := report(link); r.Type != "link" || r.SHA256 != "" {
		t.Fatalf("a link to it: %+v; want reported as a link, not followed", r)
	}
	if r := report(filepath.Join(dir, "missing")); r.Error != "ENOENT" {
		t.Fatalf("a missing path: %+v", r)
	}
	// CheckExpr is the same judgment for InContainer, inside a program that binds fs and cr.
	if !strings.Contains(CheckExpr, `("`+InContainer+`")`) || !strings.Contains(CheckJS, CheckExpr[1:len(CheckExpr)-len(`)("`+InContainer+`")`)]) {
		t.Fatal("CheckExpr is not CheckJS's function applied to InContainer")
	}
	// The machine is node's own name for this machine.
	if want := map[string]string{"amd64": "x64", "arm64": "arm64"}[runtime.GOARCH]; want != "" && r.Arch != want {
		t.Fatalf("the reported machine %q; want %q", r.Arch, want)
	}
}

// TestCheckBuiltIsTheSandboxsMachine: a provider whose sandboxes run on another machine
// judges the image against the x86-64 helper whatever machine plimsolld runs on (review
// finding rust-native-helper-43: an arm64 plimsolld driving an x86-64 gateway or cluster was
// refused for its own machine), refuses a sandbox that reports another machine by name, and
// names the reported machine in every refusal.
func TestCheckBuiltIsTheSandboxsMachine(t *testing.T) {
	t.Parallel()
	n := func(i int) *int { return &i }
	sum, err := SHA256(BuiltMachine)
	if err != nil {
		t.Fatal(err)
	}
	x86 := FileReport{Type: "file", UID: n(0), Mode: n(0o755), SHA256: sum, Arch: "x64"}
	if err := x86.CheckBuilt(); err != nil {
		t.Fatalf("an x86-64 sandbox with the pinned helper: %v", err)
	}
	for _, c := range []struct {
		name string
		r    FileReport
		msg  string
	}{
		{"an arm64 sandbox", FileReport{Type: "file", UID: n(0), Mode: n(0o755), SHA256: strings.Repeat("0", 64), Arch: "arm64"}, "the sandbox's machine is arm64 (node's process.arch); the native helper is built for x86-64 (x64) only"},
		{"an arm64 sandbox carrying the x86-64 bytes", FileReport{Type: "file", UID: n(0), Mode: n(0o755), SHA256: sum, Arch: "arm64"}, "the sandbox's machine is arm64"},
		{"no machine reported", FileReport{Type: "file", UID: n(0), Mode: n(0o755), SHA256: sum}, "the sandbox's machine is not reported"},
		{"missing on an arm64 sandbox", FileReport{Error: "ENOENT", Arch: "arm64"}, "there is no file at " + InContainer + " (ENOENT) (the sandbox's machine: arm64)"},
		{"other bytes on x86-64", FileReport{Type: "file", UID: n(0), Mode: n(0o755), SHA256: strings.Repeat("0", 64), Arch: "x64"}, "(the sandbox's machine: x64)"},
	} {
		if err := c.r.CheckBuilt(); err == nil || !strings.Contains(err.Error(), c.msg) || !errors.Is(err, ErrNotTheHelper) {
			t.Errorf("%s: %v; want it to say %q and wrap ErrNotTheHelper", c.name, err, c.msg)
		}
	}
}
