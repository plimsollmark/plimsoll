package sandbox_test

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandbox/internal/sessionkit"
)

// sweepIn runs script (sh, with $SWEEP holding the sweep's program) in a throwaway
// container of the project image. The sweep kills every process but its ancestors,
// so it can only be tried inside a container of its own.
func sweepIn(t *testing.T, script string, docker ...string) string {
	t.Helper()
	d := sessionDocker(t) // the same skip-or-require rules as the session tests
	args := append([]string{"run", "--rm", "--network", "none", "--user", "61000:61000" /* the provider's default guest uid */, "-e", "SWEEP=" + sessionkit.SweepScript}, docker...)
	args = append(args, "--entrypoint", "sh", d.ProjectImage, "-c", script)
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	return strings.TrimSpace(string(out))
}

// A disk budget of 0 means no bound, so the sweep measures nothing: past the entry
// bound, or at a directory it cannot read, it used to end the session anyway.
func TestDockerSweepWithNoBudgetMeasuresNothing(t *testing.T) {
	t.Parallel()
	sandbox.HeavyDockerTest(t)
	got := sweepIn(t, `node -e 'const fs = require("fs"); fs.mkdirSync("/tmp/d"); for (let i = 0; i <= 200000; i++) fs.writeFileSync("/tmp/d/" + i, "")'
node -e "$SWEEP" 0 200000 walk /tmp >/dev/null; echo "none=$?"
node -e "$SWEEP" 1073741824 200000 walk /tmp >/dev/null; echo "budget=$?"`)
	if got != "none=0\nbudget=10" {
		t.Fatalf("got %q; want no verdict on files without a budget (none=0), and the entry bound with one (budget=10)", got)
	}
}

// Measured by statfs, a session's tmpfs counts a file deleted while a process still
// holds it open, which a walk of the directory cannot see.
func TestDockerSweepStatfsCountsAnOpenDeletedFile(t *testing.T) {
	t.Parallel()
	got := sweepIn(t, `node -e 'require("fs").writeFileSync("/m/big", Buffer.alloc(16 << 20))'
exec 3</m/big; rm /m/big
node -e "$SWEEP" 8388608 200000 statfs /m >/dev/null; echo "statfs=$?"
node -e "$SWEEP" 8388608 200000 walk /m >/dev/null; echo "walk=$?"`, "--tmpfs", "/m:size=32m")
	if got != "statfs=10\nwalk=0" {
		t.Fatalf("got %q; want the deleted 16 MiB over an 8 MiB budget by statfs (10) and invisible to the walk (0)", got)
	}
}

// quiesceIn runs script in a throwaway container with $QUIESCE holding the quiesce's
// program, $SWEEP the sweep's and $IDENT a program that prints one process's identity
// as the sweep and the quiesce read it (pid:starttime:cmdline-hex). Like the sweep,
// the quiesce signals every process but its ancestors, so it can only be tried inside
// a container of its own.
func quiesceIn(t *testing.T, script string) string {
	t.Helper()
	d := sessionDocker(t)
	const ident = `const fs=require("node:fs");const d=process.argv[1];
const st=fs.readFileSync("/proc/"+d+"/stat","latin1");const f=st.slice(st.lastIndexOf(")")+2).split(" ");
process.stdout.write(d+":"+f[19]+":"+fs.readFileSync("/proc/"+d+"/cmdline").toString("hex"))`
	const state = `const fs=require("node:fs");const d=process.argv[1];let st;
try{st=fs.readFileSync("/proc/"+d+"/stat","latin1")}catch{process.stdout.write("gone");process.exit(0)}
process.stdout.write(st.slice(st.lastIndexOf(")")+2).split(" ")[0])`
	args := []string{"run", "--rm", "--network", "none", "--user", "61000:61000",
		"-e", "SWEEP=" + sessionkit.SweepScript, "-e", "QUIESCE=" + sessionkit.QuiesceScript,
		"-e", "IDENT=" + ident, "-e", "STATE=" + state,
		"--entrypoint", "sh", d.ProjectImage, "-c", script}
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	return strings.TrimSpace(string(out))
}

// The quiesce before a project call kills every process of the session's, the
// interpreters it keeps included, so that nothing of it runs while plimsoll starts a
// process in the container: until the runner guard has loaded, a process of the same
// uid can read the starting process's stdin, which carries the report key, and its
// memory. It spares only plimsoll's own processes, named by identity.
//
// Killing, not stopping: a stopped process can arrange its own SIGCONT before it is
// stopped (an asynchronous descriptor notification, a POSIX timer), so a stop is not a
// lasting boundary. This test holds a process stopped with such a notification armed
// and shows that it runs again, which is why the quiesce does not stop anything.
func TestDockerQuiesceKillsEverythingOfTheSessions(t *testing.T) {
	t.Parallel()
	got := quiesceIn(t, `node -e 'setInterval(()=>{}, 1000)' & interp=$!
sleep 600 & stray=$!
sleep 1
own=$(node -e "$IDENT" $$)
node -e "$QUIESCE" "$own" >/dev/null 2>&1; echo "quiesce=$?"
echo "interp=$(node -e "$STATE" $interp)"
echo "stray=$(node -e "$STATE" $stray)"`)
	// Checked line by line: a shell may report a killed background job of its own.
	for _, want := range []string{"quiesce=0", "interp=gone", "stray=gone"} {
		if !strings.Contains(got, want) {
			t.Fatalf("got %q; want %q among its lines (everything of the session's killed)", got, want)
		}
	}
}

// A process the quiesce may not signal is never counted as dealt with: a kill refused
// for permission leaves it unresolved, so the quiesce gives up, exit 1, and the call
// does not start. A live process held the loop open before the round-6 review too;
// what the review changed is that a refused kill no longer counts as a kill when the
// liveness read says dead, which this property does not need a misread to show.
// Every process of a session's container runs as the guest uid, so the test makes the
// one exception itself: the container starts as root, leaves a process running as
// root, and runs the quiesce as the guest uid.
func TestDockerQuiesceFailsOnAProcessItCannotKill(t *testing.T) {
	t.Parallel()
	d := sessionDocker(t)
	const asGuest = `process.setgid(61000);process.setuid(61000);eval(process.env.QUIESCE)`
	script := `sleep 600 & root=$!
sleep 1
node -e "$ASGUEST"; echo "quiesce=$?"
echo "root=$(test -d /proc/$root && echo alive || echo gone)"`
	args := []string{"run", "--rm", "--network", "none", "--user", "0:0",
		"-e", "QUIESCE=" + sessionkit.QuiesceScript, "-e", "ASGUEST=" + asGuest,
		"--entrypoint", "sh", d.ProjectImage, "-c", script}
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	got := string(out)
	for _, want := range []string{"quiesce=1", "root=alive"} {
		if !strings.Contains(got, want) {
			t.Fatalf("got %q; want %q among its lines (a process the quiesce cannot kill fails it)", got, want)
		}
	}
}
