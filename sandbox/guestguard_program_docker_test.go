package sandbox

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox/internal/guestguard"
)

// guestGuardInContainer is where the guard file is mounted in these tests: where the provider
// mounts it (docker_guestguard.go).
const guestGuardInContainer = guestGuardTarget

// runGuestGuardContainer runs one container of plimsoll's python image with the guard file
// mounted read-only, script on standard input, and returns standard output.
func runGuestGuardContainer(t *testing.T, d *DockerSandbox, guard string, extra []string, entry []string, script string) []byte {
	t.Helper()
	args := []string{"run", "--rm", "-i", "--network", "none", "--cap-drop", "ALL",
		"--user", d.guestUser(), "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
		"--mount", "type=bind,source=" + guard + ",target=" + guestGuardInContainer + ",readonly"}
	if d.Runtime != "" {
		args = append(args, "--runtime", d.Runtime)
	}
	args = append(args, extra...)
	args = append(args, "--entrypoint", entry[0], d.ProjectImage)
	args = append(args, entry[1:]...)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdin = strings.NewReader(script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("docker %s under %q: %v: %s\noutput:\n%s", strings.Join(args, " "), d.Runtime, err, stderr.String(), out)
	}
	return out
}

// guestGuardLines reads the JSON lines a script printed whose key field is set, by that field.
func guestGuardLines(t *testing.T, out []byte, key string) map[string]map[string]any {
	t.Helper()
	lines := map[string]map[string]any{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("%q is not a JSON line (%v); the whole output:\n%s", line, err, out)
		}
		if name, ok := m[key].(string); ok {
			lines[name] = m
		}
	}
	return lines
}

// TestDockerGuestGuardProgram runs the committed guard program for this machine, written by
// writeGuestGuard and handed into the container as one read-only file, under docker's ordinary
// runtime (runc, under plimsoll's shipped profile) or gVisor (SANDBOX_DOCKER_RUNTIME=runsc).
//
// Behind it (docker starts the guard first, then /usr/bin/env -i and python3, as the design's step
// 3 will start every command): every request of the table, made with harmless arguments, gets the
// answer Table.Decide gives; ordinary work goes on (a thread, a pipe, a shell pipeline); a program
// started behind the guard, and one that program starts, keep the filter; a filter the guarded
// code adds cannot let a refused request through, and the filter cannot be taken off; the guard
// file cannot be written. Without it, in a second container docker starts without
// no-new-privileges (and, under runc, without a host profile, so that unshare(0) is allowed and
// the self-check has something to catch): the same requests are logged as the control, at least
// one must differ; the guard sets no-new-privileges itself; it passes its arguments and
// environment through untouched; and each of its five failure codes is reached once, with its
// line on standard error and the program after "--" never started.
func TestDockerGuestGuardProgram(t *testing.T) {
	t.Parallel()
	d := testDocker()
	d.ProjectImage = pythonProjectImage
	requireProjectImage(t, d)
	shippedSeccomp(t, d)
	tb, v, cases := guestGuardCases(t, d)
	if v.Suffix != "" {
		t.Fatalf("the guard program carries the table's one filter for every runtime, but this runtime's variant is %q", v.Suffix)
	}
	if _, err := guestguard.Program(runtime.GOARCH); err != nil {
		t.Skipf("%v (the arm64 build is the named next step)", err)
	}
	guard, err := writeGuestGuard(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	prctlNr := map[string]int{"x86_64": 157, "aarch64": 167}[v.Arch.Name]
	unshareNr := map[string]int{"x86_64": 272, "aarch64": 97}[v.Arch.Name]
	// Every row of the table, with zero arguments (clone stays as the cases make it, with and
	// without a namespace flag: clone with no exit signal is not a child python can wait for).
	for _, r := range tb.Rows(v) {
		if r.Name != "clone" {
			cases = append(cases, guestGuardCase{Name: r.Name + ", zero arguments", Nr: int64(r.Number(v.Arch)), Args: []int64{0, 0, 0, 0, 0, 0}})
		}
	}
	filter, err := guestguard.Filter(runtime.GOARCH, "")
	if err != nil {
		t.Fatal(err)
	}
	casesJSON, err := json.Marshal(cases)
	if err != nil {
		t.Fatal(err)
	}
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	prelude := func(modes string) string {
		return fmt.Sprintf("FILTER = bytes.fromhex(%q)\nCASES = %s\nMODES = %s\nPRCTL_NR = %d\nUNSHARE_NR = %d\nGUEST_GUARD = %q\n",
			hex.EncodeToString(filter), casesJSON, modes, prctlNr, unshareNr, guestGuardInContainer)
	}
	env := []string{"/usr/bin/env", "-i", "PATH=/usr/local/bin:/usr/bin:/bin", "python3", "-I", "-"}
	runtimeName := d.Runtime
	if runtimeName == "" {
		runtimeName = "runc"
	}

	// Behind the guard, under plimsoll's lockdown.
	lock := []string{"--security-opt", "no-new-privileges"}
	if d.Runtime != "runsc" {
		lock = append(lock, "--security-opt", "seccomp="+d.Seccomp)
	}
	behind := runGuestGuardContainer(t, d, guard, lock, append([]string{guestGuardInContainer, "--"}, env...),
		prelude(`["behind"]`)+read("guest_guard_attempts.py")+read("guest_guard_program_checks.py"))

	// Without it: the control, and the guard's failures.
	unguarded := []string{}
	if d.Runtime != "runsc" {
		unguarded = append(unguarded, "--security-opt", "seccomp=unconfined")
	}
	without := runGuestGuardContainer(t, d, guard, unguarded, env,
		prelude(`["control"]`)+read("guest_guard_attempts.py")+read("guest_guard_program_codes.py"))

	rows := guestGuardRows(t, append(append([]byte{}, behind...), without...))
	differs := 0
	for _, c := range cases {
		g, ok := rows[c.Name+"/behind"]
		ctl, ok2 := rows[c.Name+"/control"]
		if !ok || !ok2 {
			t.Fatalf("no row for %q behind the guard and without it; the outputs:\n%s\n%s", c.Name, behind, without)
		}
		arg0 := uint64(0)
		if len(c.Args) > 0 {
			arg0 = uint64(c.Args[0])
		}
		if want := tb.Decide(v, v.Arch.Audit(), uint32(c.Nr), arg0); g.answer() != want {
			t.Errorf("%s, behind the guard: %s; the table says %s", c.Name, g.answer(), want)
		}
		if g.answer() != ctl.answer() {
			differs++
		}
		t.Logf("%s on %s: without the guard %s; behind it %s", c.Name, runtimeName, ctl.answer(), g.answer())
	}
	if differs == 0 {
		t.Errorf("under %s every request got the same answer behind the guard as without it", runtimeName)
	}

	const eperm, einval = -errEPERM, -22
	checks := guestGuardLines(t, behind, "check")
	num := func(m map[string]any, k string) int {
		f, ok := m[k].(float64)
		if !ok {
			return -1 << 30
		}
		return int(f)
	}
	filtered := func(name string, m map[string]any) {
		t.Helper()
		if m == nil {
			t.Errorf("%s: no line; the output:\n%s", name, behind)
			return
		}
		if num(m, "seccomp") != 2 || num(m, "nnp") != 1 || num(m, "unshare") != eperm || num(m, "ptrace") != eperm || num(m, "self_check") != -133 {
			t.Errorf("%s: %v; want filter mode 2, no-new-privileges 1, unshare and ptrace not permitted, the self-check answered EHWPOISON (-133)", name, m)
		}
	}
	for _, name := range []string{"state", "thread", "started program", "program started by a started program"} {
		filtered(name, checks[name])
	}
	for _, name := range []string{"started program", "program started by a started program"} {
		if m := checks[name]; m != nil && num(m, "exit") != 0 {
			t.Errorf("%s exited %d: %v", name, num(m, "exit"), m["stderr"])
		}
	}
	if m := checks["pipe and child"]; m == nil || m["pipe"] != "through a pipe" || m["shell_out"] != "through\n" || num(m, "shell_exit") != 0 {
		t.Errorf("ordinary work behind the guard: %v", m)
	}
	if m := checks["a weaker filter added"]; m == nil || num(m, "installed") != 0 || num(m, "child_exit") != 0 {
		t.Errorf("adding an allow-everything filter: %v; want it taken (it can only refuse more)", m)
	} else {
		filtered("after an allow-everything filter was added", m)
	}
	if m := checks["taking the filter off"]; m == nil || num(m, "disable") != einval || num(m, "clear_nnp") != einval {
		t.Errorf("taking the filter or no-new-privileges off: %v; want both refused with EINVAL", m)
	} else {
		filtered("after trying to take the filter off", m)
	}
	if m := checks["the guard file"]; m == nil || num(m, "open_for_write") >= 0 || num(m, "chmod") >= 0 {
		t.Errorf("the guard file behind the guard: %v; want it neither writable nor changeable", m)
	} else {
		t.Logf("the guard file on %s: open for writing %d, chmod %d (minus the errno)", runtimeName, num(m, "open_for_write"), num(m, "chmod"))
	}

	runs := guestGuardLines(t, without, "run")
	get := func(name string) map[string]any {
		m := runs[name]
		if m == nil {
			t.Fatalf("no run %q; the output:\n%s", name, without)
		}
		return m
	}
	if m := get("no-new-privileges without the guard"); num(m, "exit") != 0 {
		t.Errorf("the container without the guard has no-new-privileges %d; the check of the guard's own setting needs 0", num(m, "exit"))
	}
	if m := get("no-new-privileges and the filter behind the guard"); num(m, "exit") != 0 || m["stdout"] != "1 2\n" {
		t.Errorf("behind the guard in a container without no-new-privileges: %v; want no-new-privileges 1 and filter mode 2", m)
	}
	if m := get("environment and arguments pass through"); num(m, "exit") != 0 || m["stdout"] != "zero|a b||1|" {
		t.Errorf("arguments and environment through the guard: %v", m)
	}
	if m := get("environment passes through whole"); num(m, "exit") != 0 || m["stdout"] != "A=1\nB=two words\n" {
		t.Errorf("the environment through the guard: %v; want exactly the two variables it was given", m)
	}
	for _, f := range []struct {
		run, step string
		code      int
	}{
		{"usage: nothing", "usage", 120},
		{"usage: no --", "usage", 120},
		{"usage: nothing after --", "usage", 120},
		{"usage: --pid1 not as process 1", "usage", 120},
		{"usage: --pid1 with no --", "usage", 120},
		{"usage: --pid1 twice", "usage", 120},
		{"exec: a missing program", "exec", 124},
		{"exec: a name, not a path", "exec", 124},
		{"no_new_privs: refused", "no_new_privs", 121},
		{"install: refused", "install", 122},
		{"self-check: the filter ignored", "self-check", 123},
		// Finding guest-guard-13: the profile's refusal of unshare is not the guard's answer.
		{"self-check: the filter ignored under a profile that refuses unshare", "self-check", 123},
	} {
		m := get(f.run)
		stderr, _ := m["stderr"].(string)
		if num(m, "exit") != f.code || !strings.HasPrefix(stderr, "plimsoll guest guard: "+f.step) || strings.Count(stderr, "\n") != 1 || m["stdout"] != "" {
			t.Errorf("%s: exit %d, stdout %q, stderr %q; want exit %d, nothing started, one line naming %q", f.run, num(m, "exit"), m["stdout"], stderr, f.code, f.step)
		} else {
			t.Logf("%s on %s: exit %d, %s", f.run, runtimeName, f.code, strings.TrimSpace(stderr))
		}
	}
}
