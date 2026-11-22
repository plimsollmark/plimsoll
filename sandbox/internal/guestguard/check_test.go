package guestguard

import (
	"bytes"
	"debug/elf"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// TestCheckAttemptsAreTheTables holds the check's attempts to the table: the self-check first,
// with the self-check's own errno, and every other answer an errno the table gives for it.
func TestCheckAttemptsAreTheTables(t *testing.T) {
	tab, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	as, err := tab.CheckAttempts("amd64")
	if err != nil {
		t.Fatal(err)
	}
	if as[0].Name != tab.SelfCheck.Request || as[0].Args[0] != tab.SelfCheck.Arg0() || as[0].Errno != tab.SelfCheck.Errno {
		t.Fatalf("the first attempt %+v is not the self-check %+v", as[0], tab.SelfCheck)
	}
	want := map[string]string{"unshare": EPERM, "clone3": ENOSYS, "ptrace": EPERM, "mount": EPERM}
	exits := map[int]bool{}
	for _, a := range as[1:] {
		if a.Want != want[a.Name] || a.Errno != errnos[a.Want] {
			t.Errorf("%s: %s (%d), want %s", a.Name, a.Want, a.Errno, want[a.Name])
		}
		if exits[a.Exit] || a.Exit == 0 || a.Exit == CheckExitOrdinary {
			t.Errorf("%s: exit %d is not its own", a.Name, a.Exit)
		}
		exits[a.Exit] = true
	}
	if _, err := tab.CheckAttempts("riscv64"); err == nil {
		t.Fatal("a machine with no filter got attempts")
	}
	if _, err := CheckProgram("arm64"); err == nil {
		t.Fatal("arm64, which has no installed guard, got a check program")
	}
}

// TestCheckProgramIsAStaticELF reads the check's bytes back as an ELF file: an x86-64
// executable, entered at its first instruction, one segment read and run but never written, a
// stack that cannot be run, and no interpreter (it needs nothing of an image).
func TestCheckProgramIsAStaticELF(t *testing.T) {
	b, err := CheckProgram("amd64")
	if err != nil {
		t.Fatal(err)
	}
	f, err := elf.NewFile(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if f.Class != elf.ELFCLASS64 || f.Machine != elf.EM_X86_64 || f.Type != elf.ET_EXEC || f.Entry != checkBase+64+2*56 {
		t.Fatalf("header: %v %v %v entry %#x", f.Class, f.Machine, f.Type, f.Entry)
	}
	if len(f.Progs) != 2 {
		t.Fatalf("%d program headers, want 2", len(f.Progs))
	}
	load, stack := f.Progs[0], f.Progs[1]
	if load.Type != elf.PT_LOAD || load.Flags != elf.PF_R|elf.PF_X || load.Off != 0 || load.Vaddr != checkBase || load.Filesz != uint64(len(b)) {
		t.Fatalf("load segment %+v", load.ProgHeader)
	}
	if stack.Type != elf.PT_GNU_STACK || stack.Flags&elf.PF_X != 0 {
		t.Fatalf("stack %+v", stack.ProgHeader)
	}
	if !bytes.HasSuffix(b, []byte(CheckOK)) {
		t.Fatal("the line the check writes is not at its end")
	}
	again, _ := CheckProgram("amd64")
	if !bytes.Equal(b, again) {
		t.Fatal("two builds of the check differ")
	}
}

// TestCheckProgramOnThisKernel runs the check on this machine's own kernel: alone it stops at
// the self-check (exit CheckExitSelfCheck, nothing written), since no filter here gives that
// answer, so it makes no later request; behind the committed guard it gets every answer of the
// table and writes CheckOK. The deletion check for the check itself: an attempt whose answer the
// guard does not give fails here.
func TestCheckProgramOnThisKernel(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("the check and the guard run on linux/amd64 only")
	}
	dir := t.TempDir()
	check, guard := filepath.Join(dir, "check"), filepath.Join(dir, "guard")
	prog, err := CheckProgram("amd64")
	if err != nil {
		t.Fatal(err)
	}
	g, err := Program("amd64")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(check, prog, 0o555); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(guard, g, 0o555); err != nil {
		t.Fatal(err)
	}
	run := func(argv ...string) (int, string) {
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.Env = []string{}
		out, err := cmd.Output()
		var exitErr *exec.ExitError
		switch {
		case err == nil:
			return 0, string(out)
		case errors.As(err, &exitErr):
			return exitErr.ExitCode(), string(out)
		default:
			if errors.Is(err, os.ErrPermission) {
				t.Skipf("%s cannot run programs from %s: %v", runtime.GOOS, dir, err)
			}
			t.Fatal(err)
		}
		return -1, ""
	}
	if code, out := run(check); code != CheckExitSelfCheck || out != "" {
		t.Fatalf("the check alone exited %d with %q; want %d and nothing, since no filter here answers the self-check", code, out, CheckExitSelfCheck)
	}
	code, out := run(guard, "--", check)
	if code != 0 || out != CheckOK {
		tab, _ := Load()
		t.Fatalf("behind the guard the check exited %d (%s) with %q, want 0 and %q", code, tab.CheckExitSays("amd64", code), out, CheckOK)
	}
}
