package sandbox

// Tests of plimsoll-session-init (docker/guard/session-init.c), which docker/Dockerfile
// builds into the project image for a session provider whose runtime has no init option
// (the WSL containers provider): PID 1 of a session container. The exec helper beside it,
// docker/guard/session-exec.c, is built into no image; its tests were removed with it
// from the image (they are in the history of this file).
//
// Each container runs as the guest with no network and no capabilities, under docker's
// own seccomp profile rather than plimsoll's, as the WSL provider applies none.
// Docker tests: they skip under -short, and without docker or the images.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox/internal/guestguard"
	"github.com/plimsollmark/plimsoll/sandbox/internal/providerkit"
)

const sessionInitPath = "/usr/local/bin/plimsoll-session-init"

// helperResult is one docker command's output and exit status.
type helperResult struct {
	stdout, stderr []byte
	code           int
}

// helperDocker runs one docker command with stdin (nil for none). A non-zero exit is a
// result; failing to start docker at all fails the test.
func helperDocker(t *testing.T, stdin []byte, args ...string) helperResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	r := helperResult{}
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("docker %s: %v", strings.Join(args, " "), err)
		}
		r.code = ee.ExitCode()
	}
	r.stdout, r.stderr = out.Bytes(), errb.Bytes()
	return r
}

// helperGuestFlags are the flags every container of these tests runs with: the guest's
// uid and gid, no network, no capabilities, and the docker suite's runtime when one is
// selected (SANDBOX_DOCKER_RUNTIME).
func helperGuestFlags(d *DockerSandbox) []string {
	flags := []string{"--network", "none", "--cap-drop", "ALL", "--user", d.guestUser()}
	if d.Runtime != "" {
		flags = append(flags, "--runtime", d.Runtime)
	}
	return flags
}

// helperRun runs image's entrypoint override with args in a fresh container, as the
// guest, with stdin.
func helperRun(t *testing.T, d *DockerSandbox, image string, stdin []byte, extra []string, entrypoint string, args ...string) helperResult {
	t.Helper()
	argv := slices.Concat([]string{"run", "--rm", "-i"}, helperGuestFlags(d), extra, []string{"--entrypoint", entrypoint, image}, args)
	return helperDocker(t, stdin, argv...)
}

// helperContainer starts a container that stays up (entrypoint and args as its
// command) and removes it when the test ends.
func helperContainer(t *testing.T, d *DockerSandbox, image, entrypoint string, args ...string) string {
	t.Helper()
	name := "plimsoll-session-helpers-" + providerkit.RandHex(8)
	argv := slices.Concat([]string{"run", "-d", "--name", name}, helperGuestFlags(d), []string{"--entrypoint", entrypoint, image}, args)
	if r := helperDocker(t, nil, argv...); r.code != 0 {
		t.Fatalf("docker run: exit %d: %s", r.code, r.stderr)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
	return name
}

// helperProc is one /proc entry as helperListScript reads it.
type helperProc struct {
	PID   int    `json:"pid"`
	PPID  int    `json:"ppid"`
	State string `json:"state"`
	Cmd   string `json:"cmd"`
}

// helperListScript lists every process but itself, dead entries included (sessionkit's
// lister leaves those out).
const helperListScript = `const fs=require("node:fs");const out=[];
for(const d of fs.readdirSync("/proc")){if(!/^[0-9]+$/.test(d)||d===String(process.pid))continue;
try{const st=fs.readFileSync("/proc/"+d+"/stat","latin1");const f=st.slice(st.lastIndexOf(")")+2).split(" ");
const cmd=fs.readFileSync("/proc/"+d+"/cmdline","latin1").split("\0").join(" ").trim();
out.push({pid:+d,ppid:+f[1],state:f[0],cmd})}catch{}}
process.stdout.write(JSON.stringify(out))`

func helperList(t *testing.T, c string) []helperProc {
	t.Helper()
	r := helperDocker(t, nil, "exec", c, "node", "-e", helperListScript)
	if r.code != 0 {
		t.Fatalf("listing: exit %d: %s", r.code, r.stderr)
	}
	var procs []helperProc
	if err := json.Unmarshal(r.stdout, &procs); err != nil {
		t.Fatalf("listing %q: %v", r.stdout, err)
	}
	return procs
}

func TestSessionInitReapsOrphans(t *testing.T) {
	t.Parallel()
	d := testDocker()
	requireProjectImage(t, d)
	c := helperContainer(t, d, d.ProjectImage, sessionInitPath, "/bin/sleep", "2147483647")
	if r := helperDocker(t, nil, "exec", c, "/bin/sh", "-c",
		`i=0; while [ $i -lt 50 ]; do /bin/sleep 1000 </dev/null >/dev/null 2>&1 & i=$((i+1)); done`); r.code != 0 {
		t.Fatalf("starting the background processes: exit %d: %s", r.code, r.stderr)
	}
	var orphans []string
	deadline := time.Now().Add(30 * time.Second)
	for {
		orphans = orphans[:0]
		for _, p := range helperList(t, c) {
			if p.Cmd == "/bin/sleep 1000" && p.PPID == 1 {
				orphans = append(orphans, strconv.Itoa(p.PID))
			}
		}
		if len(orphans) == 50 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d of the 50 background processes are PID 1's children", len(orphans))
		}
		time.Sleep(200 * time.Millisecond)
	}
	if r := helperDocker(t, nil, slices.Concat([]string{"exec", c, "/bin/kill", "-9"}, orphans)...); r.code != 0 {
		t.Fatalf("killing them: exit %d: %s", r.code, r.stderr)
	}
	want := []helperProc{
		{PID: 1, PPID: 0, Cmd: sessionInitPath + " /bin/sleep 2147483647"},
		{PPID: 1, Cmd: "/bin/sleep 2147483647"},
	}
	deadline = time.Now().Add(30 * time.Second)
	for {
		procs := helperList(t, c)
		slices.SortFunc(procs, func(a, b helperProc) int { return a.PID - b.PID })
		ok := len(procs) == 2
		for i := 0; ok && i < 2; i++ {
			p := procs[i]
			ok = p.PPID == want[i].PPID && p.Cmd == want[i].Cmd && p.State != "Z" && p.State != "X" &&
				(want[i].PID == 0 || p.PID == want[i].PID)
		}
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("after the kill the container lists %+v; want PID 1 and the sleep, no dead entries", procs)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func TestSessionInitRefusesOutsidePID1(t *testing.T) {
	t.Parallel()
	d := testDocker()
	requireProjectImage(t, d)
	r := helperRun(t, d, d.ProjectImage, nil, nil, "/bin/sh", "-c", sessionInitPath+" /bin/true; echo $?")
	if r.code != 0 || string(r.stdout) != "2\n" {
		t.Fatalf("outside PID 1: exit %d, stdout %q, stderr %q; want it to exit 2", r.code, r.stdout, r.stderr)
	}
	// As PID 1 it refuses no command and a command that is not an absolute path.
	for _, args := range [][]string{nil, {"sleep", "1"}} {
		if r := helperRun(t, d, d.ProjectImage, nil, nil, sessionInitPath, args...); r.code != 2 {
			t.Errorf("as PID 1 with %q: exit %d, stderr %q; want 2", args, r.code, r.stderr)
		}
	}
}

func TestSessionInitExitsWithItsChild(t *testing.T) {
	t.Parallel()
	d := testDocker()
	requireProjectImage(t, d)
	for _, tc := range []struct {
		args []string
		want int
	}{
		{[]string{"/bin/false"}, 1},
		{[]string{"/bin/sh", "-c", "exit 7"}, 7},
		{[]string{"/bin/sh", "-c", "kill -9 $$"}, 128 + 9},
		{[]string{"/nonexistent"}, 127},
	} {
		if r := helperRun(t, d, d.ProjectImage, nil, nil, sessionInitPath, tc.args...); r.code != tc.want {
			t.Errorf("main command %q: the container exited %d, stderr %q; want %d", tc.args, r.code, r.stderr, tc.want)
		}
	}
}

// TestSessionInitRunsBehindTheGuestGuard runs the init behind docker's guest guard
// (sandbox/internal/guestguard/program/guard.c), mounted where the docker provider mounts it, as
// a session provider that puts the guard in front of every command would start it: the
// init, which the guard's plain mode becomes, is still PID 1 under the filter and exits with
// its child; and the guard's own PID 1 mode (--pid1) makes the init its child, so the init
// refuses (exit 2): a provider starts it behind the plain mode, or uses the guard's PID 1
// mode in its place.
func TestSessionInitRunsBehindTheGuestGuard(t *testing.T) {
	t.Parallel()
	d := testDocker()
	requireProjectImage(t, d)
	if _, err := guestguard.Program(runtime.GOARCH); err != nil {
		t.Skipf("%v (the arm64 build is the named next step)", err)
	}
	guard, err := writeGuestGuard(t.TempDir())
	if err != nil {
		t.Fatalf("writing the guest guard: %v", err)
	}
	mount := []string{"--init=false", "--mount", "type=bind,source=" + guard + ",target=" + guestGuardTarget + ",readonly"}
	r := helperRun(t, d, d.ProjectImage, nil, mount, guestGuardTarget, "--", sessionInitPath, "/bin/sh", "-c", "grep '^Seccomp:' /proc/1/status; exit 7")
	if r.code != 7 || string(r.stdout) != "Seccomp:\t2\n" {
		t.Errorf("the init behind the guard: exit %d, stdout %q, stderr %q; want exit 7 and PID 1 under the filter (Seccomp 2)", r.code, r.stdout, r.stderr)
	}
	r = helperRun(t, d, d.ProjectImage, nil, mount, guestGuardTarget, guestGuardPID1, "--", sessionInitPath, "/bin/true")
	if r.code != 2 {
		t.Errorf("the init behind the guard's PID 1 mode: exit %d, stderr %q; want 2 (the init is not PID 1 there)", r.code, r.stderr)
	}
}
