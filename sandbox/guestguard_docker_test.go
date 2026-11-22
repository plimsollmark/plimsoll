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

// guestGuardCase is one request testdata/guest_guard_attempts.py makes, with and without the
// filter. Forks is 1 for a clone the kernel may let through, whose copy must end at once.
type guestGuardCase struct {
	Name  string  `json:"name"`
	Nr    int64   `json:"nr"`
	Args  []int64 `json:"args"`
	Forks int     `json:"forks"`
}

// errEHWPOISON is the errno only the guard's filter answers, for its self-check.
const errEHWPOISON = 133

type guestGuardRow struct {
	Case  string `json:"case"`
	Mode  string `json:"mode"`
	Exit  int    `json:"exit"`
	Ret   *int64 `json:"ret"`
	Error string `json:"error"`
}

// answer reads a row as the table's words: allowed, EPERM, ENOSYS, killed, or what else.
func (r guestGuardRow) answer() string {
	switch {
	case r.Exit == -sigsys:
		return guestguard.Kill
	case r.Exit != 0 || r.Ret == nil:
		return fmt.Sprintf("the child failed (exit %d): %s", r.Exit, r.Error)
	case *r.Ret >= 0:
		return guestguard.Allow
	case *r.Ret == -errEPERM:
		return guestguard.EPERM
	case *r.Ret == -errENOSYS:
		return guestguard.ENOSYS
	case *r.Ret == -errEHWPOISON:
		return "EHWPOISON" // the self-check's answer (refused.json, self_check; TestSelfCheck holds it)
	}
	return fmt.Sprintf("refused, errno %d", -*r.Ret)
}

// TestDockerGuestGuardFilterInstalls: the committed bytes of the guest guard's filter for this
// machine are a filter the runtime takes (runc under the shipped profile, or gVisor with
// SANDBOX_DOCKER_RUNTIME=runsc), installed by prctl as the guard will install it, and once
// installed each request gets exactly the answer the table gives: an ordinary request goes
// through, unshare, mount and clone with a namespace flag are not permitted, clone3, request -1
// and a number above the ceiling are not implemented, ptrace as decision 137's line says, and on
// x86-64 the x32 bit is killed. The same requests made without the filter are logged beside
// them, and at least one must differ, or the filter changed nothing a test could see.
//
// The bytes are installed here from Python through ctypes, the same two prctl calls the guard
// program makes; TestDockerGuestGuardProgram runs the program itself.
func TestDockerGuestGuardFilterInstalls(t *testing.T) {
	t.Parallel()
	d := testDocker()
	d.ProjectImage = pythonProjectImage
	requireProjectImage(t, d)
	shippedSeccomp(t, d)
	tb, v, cases := guestGuardCases(t, d)
	filter, err := guestguard.Filter(runtime.GOARCH, v.Suffix)
	if err != nil {
		t.Fatal(err)
	}
	casesJSON, err := json.Marshal(cases)
	if err != nil {
		t.Fatal(err)
	}
	script, err := os.ReadFile("testdata/guest_guard_attempts.py")
	if err != nil {
		t.Fatal(err)
	}
	attempts := fmt.Sprintf("FILTER = bytes.fromhex(%q)\nCASES = %s\n", hex.EncodeToString(filter), casesJSON) + string(script)

	args := []string{"run", "--rm", "-i", "--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--user", d.guestUser(), "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m"}
	if d.Runtime != "" {
		args = append(args, "--runtime", d.Runtime)
	}
	if d.Runtime != "runsc" { // gVisor filters requests itself; the provider sets no profile there either
		args = append(args, "--security-opt", "seccomp="+d.Seccomp)
	}
	args = append(args, "--entrypoint", "/usr/bin/env", d.ProjectImage, "-i", "PATH=/usr/local/bin:/usr/bin:/bin", "python3", "-I", "-")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdin = strings.NewReader(attempts)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("the attempts under %q: %v: %s", d.Runtime, err, stderr.String())
	}

	rows := guestGuardRows(t, out)
	runtimeName := d.Runtime
	if runtimeName == "" {
		runtimeName = "runc under " + filepath.Base(d.Seccomp)
	}
	differs := 0
	for _, c := range cases {
		g, ok := rows[c.Name+"/guarded"]
		ctl, ok2 := rows[c.Name+"/control"]
		if !ok || !ok2 {
			t.Fatalf("no row for %q in both modes; the whole output:\n%s", c.Name, out)
		}
		arg0 := uint64(0)
		if len(c.Args) > 0 {
			arg0 = uint64(c.Args[0])
		}
		want := tb.Decide(v, v.Arch.Audit(), uint32(c.Nr), arg0)
		if g.answer() != want {
			t.Errorf("%s, with the filter: %s; the table says %s", c.Name, g.answer(), want)
		}
		if g.answer() != ctl.answer() {
			differs++
		}
		t.Logf("%s on %s: without the filter %s; with it %s", c.Name, runtimeName, ctl.answer(), g.answer())
	}
	if a := rows["getpid/control"].answer(); a != guestguard.Allow {
		t.Errorf("getpid without the filter: %s; the attempts cannot tell the filter's answers from the runtime's", a)
	}
	if differs == 0 {
		t.Errorf("under %s every request got the same answer with the filter as without it: nothing shows the filter was in force", runtimeName)
	}
}

// guestGuardCases is what both guest guard docker tests need: the table, the variant of the
// filter for this machine and runtime, and the requests to make, each with the answer
// Table.Decide gives it.
func guestGuardCases(t *testing.T, d *DockerSandbox) (*guestguard.Table, guestguard.Variant, []guestGuardCase) {
	t.Helper()
	tb, err := guestguard.Load()
	if err != nil {
		t.Fatal(err)
	}
	suffix := ""
	if d.Runtime == "runsc" && tb.TracingRefused == guestguard.TracingGVisor {
		suffix = "_gvisor"
	}
	var v guestguard.Variant
	found := false
	for _, x := range tb.Variants() {
		if x.Arch.GOARCH == runtime.GOARCH && x.Suffix == suffix {
			v, found = x, true
		}
	}
	if !found {
		t.Skipf("the guest guard's filter is generated for x86-64 and aarch64, not %s", runtime.GOARCH)
	}
	num := func(name string) int64 {
		for _, r := range tb.Requests {
			if r.Name == name {
				return int64(r.Number(v.Arch))
			}
		}
		t.Fatalf("refused.json has no %s", name)
		return 0
	}
	getpid := int64(39)
	if v.Arch.Name == "aarch64" {
		getpid = 172
	}
	const cloneNewUser, sigchld = 0x10000000, 17
	cases := []guestGuardCase{
		{Name: "getpid", Nr: getpid},
		{Name: "clone as fork", Nr: num("clone"), Args: []int64{sigchld, 0, 0, 0, 0}, Forks: 1},
		{Name: "unshare CLONE_NEWUSER", Nr: num("unshare"), Args: []int64{cloneNewUser}},
		{Name: "the guard's self-check (unshare, every low flag bit)", Nr: num("unshare"), Args: []int64{-1}},
		{Name: "clone CLONE_NEWUSER", Nr: num("clone"), Args: []int64{cloneNewUser | sigchld, 0, 0, 0, 0}, Forks: 1},
		{Name: "clone3", Nr: num("clone3"), Args: []int64{0, 0}},
		{Name: "mount", Nr: num("mount"), Args: []int64{0, 0, 0, 0, 0}},
		{Name: "ptrace PTRACE_TRACEME", Nr: num("ptrace"), Args: []int64{0, 0, 0, 0}},
		{Name: "request -1", Nr: -1},
		{Name: "just above the ceiling", Nr: int64(tb.Ceiling) + 1},
	}
	if x32 := v.Arch.X32(); x32 != 0 {
		cases = append(cases, guestGuardCase{Name: "x32 getpid", Nr: int64(x32) | getpid})
	}
	for i := range cases {
		if cases[i].Args == nil {
			cases[i].Args = []int64{} // a Python list, not None
		}
	}
	return tb, v, cases
}

// guestGuardRows reads the attempts' JSON lines, keyed by case and mode; a line that is not an
// attempt (it has no "case") is skipped, so other checks can print beside them.
func guestGuardRows(t *testing.T, out []byte) map[string]guestGuardRow {
	t.Helper()
	rows := map[string]guestGuardRow{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		var r guestGuardRow
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("the attempts printed %q, not a JSON line (%v); the whole output:\n%s", line, err, out)
		}
		if r.Case != "" {
			rows[r.Case+"/"+r.Mode] = r
		}
	}
	return rows
}
