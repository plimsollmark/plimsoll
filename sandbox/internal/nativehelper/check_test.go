package nativehelper

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
	want := Want{SHA256: strings.Repeat("ab", 32), Identity: "inputs " + strings.Repeat("cd", 32)}
	other := strings.Repeat("0", 64)
	for _, c := range []struct {
		name string
		r    FileReport
		msg  string
	}{
		{"the pinned file", FileReport{Type: "file", UID: n(0), Mode: n(0o711), SHA256: want.SHA256, Identity: want.Identity}, ""},
		{"read-only to root too", FileReport{Type: "file", UID: n(0), Mode: n(0o511), SHA256: want.SHA256, Identity: want.Identity}, ""},
		// session-files-14: a file the guest may read is dumpable from its exec until its
		// own first call, so a mode with any read bit for the group or every user is refused.
		{"readable by every user", FileReport{Type: "file", UID: n(0), Mode: n(0o755), SHA256: want.SHA256, Identity: want.Identity}, "has mode 0755; it must be readable by root alone and runnable by every user (0711)"},
		{"readable by its group", FileReport{Type: "file", UID: n(0), Mode: n(0o751), SHA256: want.SHA256, Identity: want.Identity}, "has mode 0751; it must be readable by root alone"},
		{"not runnable by every user", FileReport{Type: "file", UID: n(0), Mode: n(0o710), SHA256: want.SHA256, Identity: want.Identity}, "has mode 0710; it must be readable by root alone and runnable by every user"},
		{"read as the guest", FileReport{Type: "file", UID: n(0), Mode: n(0o711), Size: 9, Read: "EACCES"}, "could not read " + InContainer + " (EACCES); it is readable by root alone, so the check must read it as root"},
		{"no report", FileReport{}, "the check reported nothing for " + InContainer},
		{"missing", FileReport{Error: "ENOENT"}, "there is no file at " + InContainer + " (ENOENT)"},
		{"a link", FileReport{Type: "link", UID: n(0), Mode: n(0o777)}, InContainer + " is not a regular file (lstat: link)"},
		{"a folder", FileReport{Type: "other", UID: n(0), Mode: n(0o755)}, "is not a regular file (lstat: other)"},
		{"the guest's", FileReport{Type: "file", UID: n(61000), Mode: n(0o711), SHA256: want.SHA256, Identity: want.Identity}, "owned by uid 61000 with mode 0711"},
		{"group-writable", FileReport{Type: "file", UID: n(0), Mode: n(0o731), SHA256: want.SHA256, Identity: want.Identity}, "mode 0731; it must be root's and writable by no one else"},
		{"world-writable", FileReport{Type: "file", UID: n(0), Mode: n(0o713), SHA256: want.SHA256, Identity: want.Identity}, "mode 0713"},
		{"setuid", FileReport{Type: "file", UID: n(0), Mode: n(0o4711), SHA256: want.SHA256, Identity: want.Identity}, "has mode 4711; it must carry no setuid, setgid or sticky bit"},
		{"setgid", FileReport{Type: "file", UID: n(0), Mode: n(0o2711), SHA256: want.SHA256, Identity: want.Identity}, "has mode 2711"},
		{"sticky", FileReport{Type: "file", UID: n(0), Mode: n(0o1711), SHA256: want.SHA256, Identity: want.Identity}, "has mode 1711"},
		{"no owner", FileReport{Type: "file", Mode: n(0o711), SHA256: want.SHA256, Identity: want.Identity}, "reported no owner or no mode"},
		{"no mode", FileReport{Type: "file", UID: n(0), SHA256: want.SHA256, Identity: want.Identity}, "reported no owner or no mode"},
		{"other bytes", FileReport{Type: "file", UID: n(0), Mode: n(0o711), Size: 7, SHA256: other}, "has sha256 " + other + " (7 bytes); want " + want.SHA256},
		{"no hash", FileReport{Type: "file", UID: n(0), Mode: n(0o711)}, "has sha256  (0 bytes)"},
		// The identity: a build from before the identity command answers its usage (exit 2),
		// and another build of the helper names other inputs, even with the bytes the check wants.
		{"a build without the identity command", FileReport{Type: "file", UID: n(0), Mode: n(0o711), SHA256: want.SHA256, IdentityError: "exit 2"}, "did not report which build it is (its identity command: exit 2)"},
		{"no identity reported", FileReport{Type: "file", UID: n(0), Mode: n(0o711), SHA256: want.SHA256}, `reports the build ""; this plimsolld's helper is "` + want.Identity + `"`},
		{"another build's identity", FileReport{Type: "file", UID: n(0), Mode: n(0o711), SHA256: want.SHA256, Identity: "inputs " + other}, `reports the build "inputs ` + other + `"`},
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
	want, err := Pinned(runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	sum := want.SHA256
	// The helper is a static Linux program: elsewhere its identity command cannot run here.
	runs := runtime.GOOS == "linux"
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
	if r.Type != "file" || r.UID == nil || *r.UID != os.Getuid() || r.Mode == nil || *r.Mode != 0o755 || r.Size != int64(len(prog)) || r.SHA256 != sum || r.Read != "" {
		t.Fatalf("the helper's file: %+v", r)
	}
	if runs && (r.Identity != want.Identity || r.IdentityError != "") {
		t.Fatalf("the helper's identity: %q (%s); want %q", r.Identity, r.IdentityError, want.Identity)
	}
	// A file this user may not read (as the guest sees the installed helper, mode 0711 and
	// root's: here mode 0311, this user's) is reported by type, owner, mode and size, with the
	// code its read failed with and no hash.
	sealed := filepath.Join(dir, "sealed")
	if err := os.WriteFile(sealed, prog, 0o311); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sealed, 0o311); err != nil {
		t.Fatal(err)
	}
	if r := report(sealed); os.Getuid() != 0 && (r.Type != "file" || *r.Mode != 0o311 || r.Size != int64(len(prog)) || r.SHA256 != "" || r.Read != "EACCES") {
		t.Fatalf("a file this user may not read: %+v; want its size and EACCES, no hash", r)
	} else if runs && r.Identity != want.Identity {
		// Unreadable but runnable, as the guest finds the installed helper: its identity is
		// what tells this build from another of the same size.
		t.Fatalf("a file this user may run but not read reports %q (%s); want %q", r.Identity, r.IdentityError, want.Identity)
	}
	// A program that is not the helper answers the identity command with its own failure.
	other := filepath.Join(dir, "other")
	if err := os.WriteFile(other, []byte("#!/bin/sh\necho usage >&2\nexit 2\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if r := report(other); runs && (r.Identity != "" || r.IdentityError != "exit 2") {
		t.Fatalf("a program without the identity command: %q, %q; want exit 2", r.Identity, r.IdentityError)
	}
	// One with a set-id bit, or writable by others, is not started at all: a root check
	// would start it as root, and a guest's check as its owner.
	marker := filepath.Join(dir, "ran")
	for _, mode := range []os.FileMode{0o755 | os.ModeSetuid, 0o775} {
		starts := filepath.Join(dir, "starts")
		_ = os.Remove(starts)
		if err := os.WriteFile(starts, []byte("#!/bin/sh\ntouch "+marker+"\necho inputs x\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(starts, mode); err != nil {
			t.Fatal(err)
		}
		if r := report(starts); !strings.HasPrefix(r.IdentityError, "not run: ") || r.Identity != "" {
			t.Fatalf("a program of mode %v: identity %q, %q; want it not run", mode, r.Identity, r.IdentityError)
		}
		if _, err := os.Stat(marker); err == nil {
			t.Fatalf("a program of mode %v was started", mode)
		}
	}
	// Owned by this user, not root: the one check a file of this test cannot pass.
	if err := r.Check(want); os.Getuid() != 0 && (err == nil || !strings.Contains(err.Error(), "must be root's")) {
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
	prog, err := Program(BuiltMachine)
	if err != nil {
		t.Fatal(err)
	}
	size := int64(len(prog))
	id, err := Identity()
	if err != nil {
		t.Fatal(err)
	}
	x86 := FileReport{Type: "file", UID: n(0), Mode: n(0o711), Size: size, Read: "EACCES", Arch: "x64", Identity: id}
	if err := x86.CheckBuilt(); err != nil {
		t.Fatalf("an x86-64 sandbox with the pinned helper: %v", err)
	}
	for _, c := range []struct {
		name string
		r    FileReport
		msg  string
	}{
		{"an arm64 sandbox", FileReport{Type: "file", UID: n(0), Mode: n(0o711), Read: "EACCES", Arch: "arm64"}, "the sandbox's machine is arm64 (node's process.arch); the native helper is built for x86-64 (x64) only"},
		{"an arm64 sandbox carrying the x86-64 build", FileReport{Type: "file", UID: n(0), Mode: n(0o711), Size: size, Read: "EACCES", Arch: "arm64"}, "the sandbox's machine is arm64"},
		{"no machine reported", FileReport{Type: "file", UID: n(0), Mode: n(0o711), Size: size, Read: "EACCES"}, "the sandbox's machine is not reported"},
		{"missing on an arm64 sandbox", FileReport{Error: "ENOENT", Arch: "arm64"}, "there is no file at " + InContainer + " (ENOENT) (the sandbox's machine: arm64)"},
		{"another size on x86-64", FileReport{Type: "file", UID: n(0), Mode: n(0o711), Size: size + 1, Read: "EACCES", Arch: "x64"}, "is " + fmt.Sprint(size+1) + " bytes; this plimsolld's helper is " + fmt.Sprint(size) + " (the sandbox's machine: x64)"},
		{"readable by the guest", FileReport{Type: "file", UID: n(0), Mode: n(0o755), Size: size, SHA256: sum, Arch: "x64"}, "has mode 0755; it must be readable by root alone"},
		{"read by the guest", FileReport{Type: "file", UID: n(0), Mode: n(0o711), Size: size, SHA256: sum, Arch: "x64"}, "the guest read " + InContainer},
		{"a read that failed otherwise", FileReport{Type: "file", UID: n(0), Mode: n(0o711), Size: size, Read: "EIO", Arch: "x64"}, "failed with EIO, not a refusal of its permission"},
		// Size alone never passes: the build pinned 1b403142 (file contract 5) was this size
		// too, and answers the identity command with its usage; another build names other inputs.
		{"the earlier build 1b403142, of the same size", FileReport{Type: "file", UID: n(0), Mode: n(0o711), Size: size, Read: "EACCES", Arch: "x64", IdentityError: "exit 2"}, "did not report which build it is (its identity command: exit 2)"},
		{"another build of the same size", FileReport{Type: "file", UID: n(0), Mode: n(0o711), Size: size, Read: "EACCES", Arch: "x64", Identity: "inputs " + strings.Repeat("0", 64)}, `reports the build "inputs 0000`},
		{"a by-hand build", FileReport{Type: "file", UID: n(0), Mode: n(0o711), Size: size, Read: "EACCES", Arch: "x64", Identity: "inputs none"}, `reports the build "inputs none"`},
	} {
		if err := c.r.CheckBuilt(); err == nil || !strings.Contains(err.Error(), c.msg) || !errors.Is(err, ErrNotTheHelper) {
			t.Errorf("%s: %v; want it to say %q and wrap ErrNotTheHelper", c.name, err, c.msg)
		}
	}
}

// TestIdentityIsThePinsInputs: the identity the checks require is "inputs " and the SHA-256 of
// the pin's lines for the build's inputs, as build.sh computes it before it builds, and the
// committed build reports exactly that (run here on Linux, where the static program runs), so
// the pinned build's identity is fixed by the pin.
func TestIdentityIsThePinsInputs(t *testing.T) {
	pin, err := os.ReadFile("program/plimsoll-helper.sha256")
	if err != nil {
		t.Fatal(err)
	}
	var inputs []string
	for _, line := range strings.SplitAfter(string(pin), "\n") {
		if line != "" && !strings.Contains(line, "  plimsoll-helper_") {
			inputs = append(inputs, line)
		}
	}
	sum := sha256.Sum256([]byte(strings.Join(inputs, "")))
	id, err := Identity()
	if err != nil || id != "inputs "+hex.EncodeToString(sum[:]) || len(inputs) < 5 {
		t.Fatalf("Identity: %q, %v; the pin's %d input lines hash to %x", id, err, len(inputs), sum)
	}
	for _, g := range installedMachines(t) {
		prog, err := Program(g)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(prog, []byte(strings.TrimPrefix(id, "inputs "))) {
			t.Errorf("%s does not carry the identity %s: it was built from other inputs, or without build.sh", ProgramFile(g), id)
		}
		if runtime.GOOS != "linux" || g != runtime.GOARCH {
			continue
		}
		f := filepath.Join(t.TempDir(), "plimsoll-helper")
		if err := os.WriteFile(f, prog, 0o755); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(f, "identity").Output()
		if err != nil || string(out) != id+"\n" {
			t.Fatalf("the committed build's identity command: %q, %v; want %q", out, err, id+"\n")
		}
	}
}
