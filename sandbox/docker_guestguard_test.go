package sandbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/internal/boundary"
	"github.com/plimsollmark/plimsoll/sandbox/internal/guestguard"
	"github.com/plimsollmark/plimsoll/sandbox/internal/sessionkit"
)

// The docker provider's wiring of the guest guard (docker_guestguard.go), without docker: every
// command it hands to docker starts behind the guard, once, and docker is never asked to start
// a container command another way.

func TestGuardFirst(t *testing.T) {
	t.Parallel()
	got, err := guardFirst([]string{"/usr/bin/env", "-i", "PATH=/bin", "node", "-"})
	if err != nil || !slices.Equal(got, []string{guestGuardTarget, "--", "/usr/bin/env", "-i", "PATH=/bin", "node", "-"}) {
		t.Fatalf("guardFirst: %q, %v; want the guard, --, then the command whole", got, err)
	}
	if _, err := guardFirst(nil); err == nil {
		t.Error("guardFirst accepted an empty command")
	}
	for _, twice := range [][]string{
		{guestGuardTarget, "--", "/usr/bin/env"},
		{"/usr/bin/env", "-i", "sh", "-c", "x", "sh", guestGuardTarget, "--", "node"},
	} {
		if _, err := guardFirst(twice); err == nil {
			t.Errorf("guardFirst accepted %q, which names the guard already: it would run twice", twice)
		}
	}
}

// testGuard stands for the guard file Preflight verified, in the tests that do not reach
// dockerCommand (which names the real one, guestGuardPath).
const testGuard = "/private/guest-guard/guest-guard-0"

// testCheck stands for the guard check writeGuestGuardCheck wrote beside it, the one file the
// startup smoke test may mount at guestGuardCheckTarget.
const testCheck = "/private/guest-guard/guest-guard-check-0"

// withCheckMount is run with the smoke test's mount of the guard check from check, as
// smokeGuestGuard writes it: after the lockdown flags, in front of launch's entrypoint.
func withCheckMount(run []string, check string) []string {
	at := slices.Index(run, "--entrypoint")
	return slices.Concat(run[:at], []string{"--mount", bindMountSpec(check, guestGuardCheckTarget)}, run[at:])
}

// guardedRun is a docker run as launch builds it, after dockerArgs' --host, mounting guard.
func guardedRun(t *testing.T, argv ...string) []string {
	t.Helper()
	return guardedRunFrom(t, testGuard, argv...)
}

func guardedRunFrom(t *testing.T, guard string, argv ...string) []string {
	t.Helper()
	tail, err := launch(guard, "sha256:image", argv)
	if err != nil {
		t.Fatal(err)
	}
	return append([]string{"--host", "unix:///run/docker.sock", "run", "--rm", "-i", "--name", "crsbx-x", "--read-only", dockerNoInit}, tail...)
}

// guardedExec is a docker exec as execAs builds it, after dockerArgs' --host.
func guardedExec() []string {
	return []string{"--host", "unix:///run/docker.sock", "exec", "-i", "-w", "/work", "--user", "61001", "-e", "A=1", "plsm-session-x", guestGuardTarget, "--", "/usr/bin/env", "-i", "node"}
}

// unguardedDockerCommands are commands the refusing point must refuse, each with what it is:
// those of step 3a's test, then the review's (findings guest-guard-19 and 20,
// private/reviews/guest-guard-code-review-2026-11-19.md), then the allow list's own, then the
// near misses of the smoke test's guard check mount. guard is the verified file the good run
// mounts and check the guard check's file, so each row is refused for its own reason, not for
// naming another file.
func unguardedDockerCommands(t *testing.T, guard, check string) map[string][]string {
	t.Helper()
	g := guestGuardTarget
	run := guardedRunFrom(t, guard, "/usr/bin/env", "-i", "node", "-")
	exec := guardedExec()
	without := func(drop string) []string {
		var out []string
		for _, a := range run {
			if a != drop {
				out = append(out, a)
			}
		}
		return out
	}
	replace := func(args []string, at int, with ...string) []string {
		return slices.Concat(args[:at], with, args[at+1:])
	}
	entry := slices.Index(run, "--entrypoint")
	mount := slices.Index(run, "--mount")
	image := slices.Index(run, "sha256:image")
	execAt := slices.Index(exec, g)
	// beforeImage puts docker run flags in front of the image.
	beforeImage := func(flags ...string) []string { return slices.Concat(run[:image], flags, run[image:]) }
	// global puts docker's own flags between the --host pair and the command.
	global := func(args []string, flags ...string) []string { return slices.Concat(args[:2], flags, args[2:]) }
	return map[string][]string{
		// Step 3a's rows.
		"a run with the image's own entrypoint":     slices.Concat(run[:mount], run[mount+2:entry], run[entry+2:]),
		"a run whose entrypoint is not the guard":   replace(run, entry+1, "/usr/bin/env"),
		"a run with --entrypoint= written joined":   replace(slices.Delete(slices.Clone(run), entry+1, entry+2), entry, "--entrypoint="+g),
		"a run with a second --entrypoint":          slices.Concat(run[:entry], []string{"--entrypoint", "/bin/sh"}, run[entry:]),
		"a run naming the guard twice":              append(slices.Clone(run), g, "--", "node"),
		"a run without the guard's mount":           slices.Concat(run[:mount], run[mount+2:]),
		"a run whose guard mount is writable":       replace(run, mount+1, strings.TrimSuffix(run[mount+1], ",readonly")),
		"a run naming the guard nowhere":            without(g),
		"an exec without the guard":                 slices.Concat(exec[:execAt], exec[execAt+2:]),
		"an exec naming the guard twice":            slices.Concat(exec, []string{g, "--", "node"}),
		"an exec whose guard is not followed by --": replace(exec, execAt+1, "/usr/bin/env"),
		"docker create":                             {"--host", "h", "create", "--entrypoint", g, "img"},
		"docker start":                              {"--host", "h", "start", "x"},
		"docker restart":                            {"--host", "h", "restart", "x"},
		"docker container run":                      {"--host", "h", "container", "run", "img"},
		"docker attach":                             {"--host", "h", "attach", "x"},
		// The review's rows (finding guest-guard-19): a flag of docker's own in front of the
		// command, and commands that start processes, none on the old refusal list.
		"--log-level before a run":           global(run, "--log-level", "error"),
		"-H before a run":                    global(run, "-H", "unix:///x"),
		"--context before a run":             global(run, "--context", "default"),
		"-D before an exec":                  global(exec, "-D"),
		"a global flag with no --host":       slices.Concat([]string{"--log-level", "error"}, run[2:]),
		"a second --host pair":               global(run, "--host", "unix:///run/other.sock"),
		"docker sandbox (a CLI plugin)":      {"--host", "h", "sandbox", "run", "img"},
		"docker service create":              {"--host", "h", "service", "create", "img"},
		"docker debug":                       {"--host", "h", "debug", "ctr"},
		"docker build":                       {"--host", "h", "build", "."},
		"docker buildx build":                {"--host", "h", "buildx", "build", "."},
		"docker image build":                 {"--host", "h", "image", "build", "."},
		"docker image alone":                 {"--host", "h", "image"},
		"docker compose up":                  {"--host", "h", "compose", "up"},
		"docker stack deploy":                {"--host", "h", "stack", "deploy", "x"},
		"docker plugin install":              {"--host", "h", "plugin", "install", "x"},
		"docker update":                      {"--host", "h", "update", "--pids-limit", "-1", "x"},
		"docker cp into a container":         {"--host", "h", "cp", "/bin/sh", "x:/tmp/sh"},
		"rm with a flag it never carries":    {"--host", "h", "rm", "-v", "x"},
		"rm with no name":                    {"--host", "h", "rm", "-f"},
		"inspect with a joined flag":         {"--host", "h", "inspect", "--format={{.Id}}", "x"},
		"ps with a value-taking flag at end": {"--host", "h", "ps", "--filter"},
		// Finding guest-guard-20: where the guard stands in an exec, which file a run mounts.
		"an exec whose guard comes after the command":         {"--host", "h", "exec", "-i", "ctr", "/bin/sh", "-c", "id", g, "--"},
		"an exec naming the guard as an option's value":       {"--host", "h", "exec", "-e", "X=1", "-w", g, "--", "ctr", "/bin/sh"},
		"an exec with a flag it never carries":                slices.Concat(exec[:3], []string{"--privileged"}, exec[3:]),
		"an exec with -e NAME and no value":                   slices.Concat(exec[:3], []string{"-e", "PLIMSOLL_TOKEN"}, exec[3:]),
		"an exec with the guard and no command":               exec[:execAt+2],
		"a run mounting another file at the guard's path":     replace(run, mount+1, bindMountSpec("/bin/true", g)),
		"a run mounting with readonly=false, then readonly":   replace(run, mount+1, "type=bind,source="+guard+",target="+g+",readonly=false,readonly"),
		"a run with a second mount over the guard's path":     beforeImage("--mount", bindMountSpec("/bin/sh", g)),
		"a run with a tmpfs at the guard's path":              beforeImage("--tmpfs", g+":exec"),
		"a run with the guard's mount twice":                  beforeImage("--mount", run[mount+1]),
		"a run with a volume flag":                            beforeImage("-v", "/bin/sh:"+g+":ro"),
		"a run with -e":                                       beforeImage("-e", "A=1"),
		"a run with a flag it never carries":                  beforeImage("--privileged"),
		"a run whose image is not followed by --":             slices.Delete(slices.Clone(run), image+1, image+2),
		"a run with the guard's separator and no command":     run[:image+2],
		"a run with a flag value missing at the end":          slices.Concat(run[:image], []string{"--name"}),
		"a run with the guard's path as the image's argument": slices.Concat(run[:image+2], []string{g}),
		// Finding guest-guard-10 (decision 10 B): docker's own init would be process 1 outside the
		// guard, so a run asking for it is refused; the guard's process-1 word stands once, right
		// after the image, and never in an exec.
		"a run with docker's --init": beforeImage("--init"),
		// Finding guest-guard-39: every run says --init=false once, so a daemon whose default is
		// init cannot start docker's init as process 1; no other form of the flag is written.
		"a run with --init=true":                     beforeImage("--init=true"),
		"a run without --init=false":                 without(dockerNoInit),
		"a run with --init=false twice":              beforeImage(dockerNoInit),
		"a run with --init=False":                    slices.Concat(without(dockerNoInit)[:image-1], []string{"--init=False"}, without(dockerNoInit)[image-1:]),
		"a run with the process-1 word and no --":    replace(run, image+1, guestGuardPID1),
		"a run with the process-1 word twice":        slices.Concat(run[:image+1], []string{guestGuardPID1, guestGuardPID1}, run[image+1:]),
		"a run with the process-1 word after the --": slices.Concat(run[:image+2], []string{guestGuardPID1}, run[image+2:]),
		"an exec with the process-1 word":            slices.Concat(exec[:execAt+1], []string{guestGuardPID1}, exec[execAt+1:]),
		// The startup smoke test's guard check mount (smokeGuestGuard): accepted only read-only,
		// from exactly the check's file, at its one path, once.
		"a run mounting another file at the check's path":    withCheckMount(run, "/bin/sh"),
		"a run mounting the guard at the check's path":       withCheckMount(run, guard),
		"a run mounting the check writable":                  beforeImage("--mount", bindMount(check, guestGuardCheckTarget, false)),
		"a run mounting the check twice":                     withCheckMount(withCheckMount(run, check), check),
		"a run mounting the check at another path":           beforeImage("--mount", bindMountSpec(check, g+"-check2")),
		"a run mounting the check with readonly=false first": beforeImage("--mount", "type=bind,source="+check+",target="+guestGuardCheckTarget+",readonly=false,readonly"),
		"a run with a tmpfs at the check's path":             beforeImage("--tmpfs", guestGuardCheckTarget+":exec"),
		"a run mounting the check and a second one there":    beforeImage("--mount", bindMountSpec(check, guestGuardCheckTarget), "--mount", bindMountSpec("/bin/sh", guestGuardCheckTarget)),
	}
}

func TestCheckGuardedCommand(t *testing.T) {
	t.Parallel()
	run := guardedRun(t, "/usr/bin/env", "-i", "node", "-")
	if err := checkGuardedCommand(run, testGuard, testCheck); err != nil {
		t.Fatalf("a run launch built: %v", err)
	}
	if err := checkGuardedCommand(guardedExec(), testGuard, testCheck); err != nil {
		t.Fatalf("an exec guardFirst built: %v", err)
	}
	if err := checkGuardedCommand(withCheckMount(run, testCheck), testGuard, testCheck); err != nil {
		t.Fatalf("the smoke test's run with the guard check mounted: %v", err)
	}
	for _, ok := range [][]string{
		{"--host", "unix:///run/docker.sock", "inspect", "--type", "container", "x"},
		{"--host", "unix:///run/docker.sock", "inspect", "--format", "{{.State.Pid}}", "x"},
		{"--host", "unix:///run/docker.sock", "ps", "-a", "-q"},
		{"--host", "unix:///run/docker.sock", "ps", "-a", "-q", "--no-trunc", "--filter", "name=^x$"},
		{"--host", "unix:///run/docker.sock", "ps", "-a", "--filter", "label=io.plimsoll.expires", "--format", "{{.Names}}"},
		{"--host", "unix:///run/docker.sock", "rm", "-f", "x"},
		{"--host", "unix:///run/docker.sock", "pause", "x"},
		{"--host", "unix:///run/docker.sock", "unpause", "x"},
		{"--host", "unix:///run/docker.sock", "save", "sha256:image"},
		{"--host", "unix:///run/docker.sock", "info"},
		{"--host", "unix:///run/docker.sock", "info", "--format", "{{json .Runtimes}}"},
		{"--host", "unix:///run/docker.sock", "version", "--format", "{{.Server.Os}}/{{.Server.Arch}}"},
		{"--host", "unix:///run/docker.sock", "image", "inspect", "--format", "{{json .}}", "img"},
		{"--host", "unix:///run/docker.sock", "image", "inspect", "--platform", "linux/amd64", "--format", "{{json .}}", "sha256:image"},
		{"version"},
		{"ps"},
		nil,
	} {
		if err := checkGuardedCommand(ok, testGuard, testCheck); err != nil {
			t.Errorf("%q starts no container command, refused: %v", ok, err)
		}
	}
	for what, args := range unguardedDockerCommands(t, testGuard, testCheck) {
		err := checkGuardedCommand(args, testGuard, testCheck)
		if err == nil {
			t.Errorf("%s was not refused: %q", what, args)
		} else if !errors.As(err, new(dockerRefusal)) {
			t.Errorf("%s: %v is not a dockerRefusal", what, err)
		}
	}
	// The guard's mount must name the file Preflight verified, exactly: the same run against
	// another verified file, or with none known (a machine with no guard), is refused.
	for _, guard := range []string{"/private/guest-guard/guest-guard-1", "/private/guest-guard", ""} {
		if err := checkGuardedCommand(run, guard, testCheck); err == nil {
			t.Errorf("a run mounting %s passed with %q as the verified guard", testGuard, guard)
		}
	}
	// The same holds for the guard check's mount: another file as the known check, or none known
	// (a machine with no check), and the smoke test's run is refused.
	for _, check := range []string{"/private/guest-guard/guest-guard-check-1", "/private/guest-guard", ""} {
		if err := checkGuardedCommand(withCheckMount(run, testCheck), testGuard, check); err == nil {
			t.Errorf("a run mounting the check %s passed with %q as the known check", testCheck, check)
		}
	}
}

// Every docker run the provider builds passes the allow list, with each set of its flags: a
// run's container (no runtime, gVisor, runc with a profile; with and without /work; with a
// grant's broker socket; with a platform), the smoke test's detached run, and a session's
// container, each built by the provider's own functions.
func TestCheckGuardedCommandAcceptsTheProvidersRuns(t *testing.T) {
	t.Parallel()
	d := DefaultDocker("")
	expires := time.Unix(1_700_000_000, 0)
	argv := []string{"/usr/bin/env", "-i", "node", "-"}
	tail, err := launch(testGuard, "sha256:image", argv)
	if err != nil {
		t.Fatal(err)
	}
	pid1Tail, err := launchPID1(testGuard, "sha256:image", argv)
	if err != nil {
		t.Fatal(err)
	}
	if want := slices.Insert(slices.Clone(tail), 5, guestGuardPID1); !slices.Equal(pid1Tail, want) || pid1Tail[4] != "sha256:image" || pid1Tail[6] != "--" {
		t.Fatalf("launchPID1 built %q; want launch's %q with %s between the image and --", pid1Tail, tail, guestGuardPID1)
	}
	broker := []string{"--mount", bindMount("/private/broker/host-api.sock", containerSocketPath, false)}
	platform := []string{"--platform", "linux/amd64"}
	runs := map[string][]string{}
	for _, c := range []struct {
		runtime, seccomp string
		work             bool
	}{{"", "", false}, {"runsc", "", true}, {"runc", "/private/seccomp/seccomp-0.json", true}, {"runc", "", false}} {
		lock := d.lockdownArgs("crsbx-x", expires, c.work, c.runtime, c.seccomp)
		name := fmt.Sprintf("runtime %q, seccomp %q, work %v", c.runtime, c.seccomp, c.work)
		runs["a run, "+name] = slices.Concat(lock, tail)
		runs["a granted run on a platform, "+name] = slices.Concat(lock, broker, platform, tail)
		runs["the smoke test's detached run, "+name] = slices.Concat([]string{"run", "-d"}, lock[1:], platform, tail)
		runs["the smoke test's guard check run, "+name] = slices.Concat(lock, platform, []string{"--mount", bindMountSpec(testCheck, guestGuardCheckTarget)}, tail)
		session := []string{"run", "--name", "plsm-session-x", "--log-driver", "none", "--label", dockerSessionLabel + "=1"}
		session = append(session, d.labelArgs(expires)...)
		runs["a session's container, "+name] = slices.Concat(session, d.lockdownFlags(true, c.runtime, c.seccomp), broker, platform, pid1Tail)
	}
	for what, args := range runs {
		if err := checkGuardedCommand(append([]string{"--host", "unix:///run/docker.sock"}, args...), testGuard, testCheck); err != nil {
			t.Errorf("%s: %v (%q)", what, err, args)
		}
	}
}

// The refusing point itself (finding guest-guard-21): each command the check refuses, built
// through dockerCommand, carries the refusal and never starts docker. docker here is a stand-in
// on PATH that writes a line each time it is started; the good run and exec, built with the
// file dockerCommand names (guestGuardPath), start it, so the stand-in is shown to work. It
// fails when dockerCommand stops refusing (its cmd.Err dropped).
func TestDockerCommandRefusesUnguardedCommands(t *testing.T) {
	bin := t.TempDir()
	started := filepath.Join(bin, "started")
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte("#!/bin/sh\necho \"$*\" >> '"+started+"'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	files, err := dockerProcessFiles()
	if err != nil {
		t.Fatal(err)
	}
	guard, err := guestGuardPath(files.guard)
	if err != nil {
		t.Skipf("no guest guard is built for this machine: %v", err)
	}
	check, err := guestGuardCheckPath(files.guard)
	if err != nil {
		t.Skipf("no guard check is built for this machine: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	startedLines := func() int {
		b, err := os.ReadFile(started)
		if os.IsNotExist(err) {
			return 0
		} else if err != nil {
			t.Fatal(err)
		}
		return strings.Count(string(b), "\n")
	}
	// Every case is reported, none stops the test, so the deletion run of finding guest-guard-21
	// (the refusal in dockerCommand dropped) names each command that then starts docker, the
	// unguarded runs and execs among them.
	for what, args := range unguardedDockerCommands(t, guard, check) {
		before := startedLines()
		cmd := dockerCommand(ctx, args...)
		if cmd.Err == nil || !errors.As(cmd.Err, new(dockerRefusal)) {
			t.Errorf("%s: dockerCommand carries %v, not the refusal", what, cmd.Err)
		}
		if err := cmd.Run(); err == nil {
			t.Errorf("%s: dockerCommand's command ran", what)
		}
		if n := startedLines() - before; n != 0 {
			t.Errorf("%s: docker was started (%d times)", what, n)
		}
	}
	if n := startedLines(); n != 0 {
		t.Fatalf("docker was started %d times for commands the refusing point must refuse", n)
	}
	for what, args := range map[string][]string{
		"the good run":                     guardedRunFrom(t, guard, "/usr/bin/env", "-i", "node", "-"),
		"the good exec":                    guardedExec(),
		"the smoke test's guard check run": withCheckMount(guardedRunFrom(t, guard, "/usr/bin/env", "-i", guestGuardCheckTarget), check),
	} {
		before := startedLines()
		if err := dockerCommand(ctx, args...).Run(); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		if startedLines() != before+1 {
			t.Fatalf("%s did not start the stand-in docker, so the refusals above prove nothing", what)
		}
	}
	// The command that reads the operator's client setup starts docker context inspect alone.
	for _, args := range [][]string{{"run", "img"}, {"context", "use", "x"}, {"--context", "x", "context", "inspect"}, nil} {
		before := startedLines()
		if err := dockerResolveCommand(ctx, args...).Run(); err == nil || startedLines() != before {
			t.Errorf("dockerResolveCommand(%q) started docker", args)
		}
	}
	if err := dockerResolveCommand(ctx, "context", "inspect", "--format", "x").Run(); err != nil {
		t.Errorf("dockerResolveCommand(context inspect): %v", err)
	}
}

// Every command a start path hands to docker passes the refusing point in dockerCommand: launch
// (every run: a run's snippet and runner, a session's main process, the smoke programs), a
// session's execAs (every exec) and attach (every relay). The session here names a daemon that
// does not exist, so docker, when the command passes, fails to connect; a command refused by the
// guard's check never starts docker.
func TestDockerStartPathsGoBehindTheGuard(t *testing.T) {
	t.Parallel()
	for name, argv := range map[string][]string{
		"a snippet":                must(guestArgv(startMarker(), []string{"A=1"}, "node", "-")),
		"the runner":               must((&DockerSandbox{}).runnerArgv(startMarker())),
		"a session's main process": must(dockerSessionMain(dockerMainMarker())),
		"the sweep":                must(sessionControlArgv(nil, []string{"node", "-e", "0"})),
	} {
		run := guardedRun(t, argv...)
		if err := checkGuardedCommand(run, testGuard, testCheck); err != nil {
			t.Errorf("%s, launched: %v", name, err)
		}
		if run[slices.Index(run, "--entrypoint")+1] != guestGuardTarget || !slices.Equal(run[len(run)-len(argv)-1:], append([]string{"--"}, argv...)) {
			t.Errorf("%s: %q; want the guard as the entrypoint, then --, then the command whole", name, run)
		}
	}
	if _, err := launch("", "sha256:image", []string{"/usr/bin/env"}); err == nil {
		t.Error("launch built a run with no verified guard file")
	}

	s := &dockerSession{d: DefaultDocker(""), host: "unix://" + filepath.Join(t.TempDir(), "no-daemon.sock"), name: "plsm-session-none"}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// Refused by the guard's check: guardFirst's words, or any refusal of the refusing point (a
	// flag execAs or attach writes that is not on the allow list included).
	refusedByGuard := func(err error) bool {
		return err != nil && (strings.Contains(err.Error(), "guest guard") || errors.As(err, new(dockerRefusal)))
	}
	argv := must(sessionkit.ControlArgv(nil, sessionkit.ListArgv()...))
	if _, err := s.exec(ctx, argv, nil, nil, 4096, 4096); refusedByGuard(err) {
		t.Errorf("exec of the process lister: %v; want it handed to docker behind the guard", err)
	}
	if _, err := s.execAs(ctx, "61001", argv, []string{"A=1"}, nil, 4096, 4096); refusedByGuard(err) {
		t.Errorf("execAs as the checker: %v", err)
	}
	if _, err := s.exec(ctx, append([]string{guestGuardTarget, "--"}, argv...), nil, nil, 4096, 4096); !refusedByGuard(err) {
		t.Errorf("exec of a command that names the guard already: %v; want it refused, the guard would run twice", err)
	}
	a, err := s.attach([]string{"node", "-e", "0"}, nil)
	if refusedByGuard(err) {
		t.Errorf("attach of a relay: %v", err)
	}
	if err == nil {
		a.Close()
	}
}

func must(argv []string, err error) []string {
	if err != nil {
		panic(err)
	}
	return argv
}

// A cell's interpreter is started by the guarded launcher and keeps its filter: the start
// command handed to the launcher does not name the guard, so the guard runs once per command.
func TestDockerCellInterpreterIsGuardedOnce(t *testing.T) {
	t.Parallel()
	start := must(guestArgv("", []string{"A=1"}))
	if slices.Contains(start, guestGuardTarget) {
		t.Fatalf("the interpreter's start command %q names the guard; the launcher's exec already started behind it", start)
	}
}

func TestGuestGuardRefusal(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		code   int
		stderr string
		want   string // "" for not the guard's
	}{
		{120, "plimsoll guest guard: usage: guard -- PROGRAM [ARG...]: errno 22\n", "step usage, errno 22 (exit 120)"},
		{121, "plimsoll guest guard: no_new_privs: errno 1\n", "step no_new_privs, errno 1 (exit 121)"},
		{122, "plimsoll guest guard: install: errno 22\n", "step install, errno 22 (exit 122)"},
		{123, "plimsoll guest guard: self-check: the guard's own answer did not come back: errno 1\n", "step self-check, errno 1 (exit 123)"},
		{124, "plimsoll guest guard: exec: errno 2\n", "step exec, errno 2 (exit 124)"},
		{124, "WARNING: docker said something first\nplimsoll guest guard: exec: errno 2\n", "step exec, errno 2 (exit 124)"},
		{123, "plimsoll guest guard: exec: errno 2\n", ""},       // a step whose code is not the exit
		{124, "plimsoll guest guard: exec: errno 2\nmore\n", ""}, // not the last line
		{124, "plimsoll guest guard: exec: errno 2", ""},         // no newline: not the guard's write
		{124, "xplimsoll guest guard: exec: errno 2\n", ""},      // not a line of its own
		{124, "plimsoll guest guard: launch: errno 2\n", ""},     // no such step
		{125, "docker: Error response from daemon: x\n", ""},     // docker's own failure
		{-1, "plimsoll guest guard: exec: errno 2\n", ""},        // no exit code
		{124, "plimsoll guest guard: exec: errno 123456\n", ""},  // not an errno the guard prints
		{123, "plimsoll guest guard: self-check: \x00: errno 1\n", "step self-check, errno 1 (exit 123)"},
	} {
		got, ok := guestGuardRefusal(c.code, c.stderr)
		if ok != (c.want != "") || (ok && !strings.Contains(got, c.want)) {
			t.Errorf("guestGuardRefusal(%d, %q) = %q, %v; want %q", c.code, c.stderr, got, ok, c.want)
		}
		if ok && strings.ContainsAny(got, "\x00\n") {
			t.Errorf("guestGuardRefusal(%d, %q) = %q: it carries bytes of the line, not its own words", c.code, c.stderr, got)
		}
	}
}

// TestUnstartedRunIsNeverMarked holds a fresh run whose start marker is missing to its rule
// (unstartedRun): whatever its standard error and exit code, the guest guard's refusal shape
// included, the error is never marked not dispatched, since the run's own code can write that
// shape. The guard's shape is told in plimsoll's words, naming the step, and says whether the
// run's code ran is not known; anything else is docker not running the command, as before.
func TestUnstartedRunIsNeverMarked(t *testing.T) {
	t.Parallel()
	exitWith := func(code int) error {
		err := exec.Command("/bin/sh", "-c", fmt.Sprintf("exit %d", code)).Run()
		if exitCodeOf(err) != code {
			t.Fatalf("a shell's exit %d came back as %v", code, err)
		}
		return err
	}
	for _, c := range []struct {
		code   int
		stderr string
		want   []string
	}{
		{124, "plimsoll guest guard: exec: errno 2\n", []string{"guest guard", "step exec, errno 2, exit 124", "is not known"}},
		{123, impersonatorLine, []string{"guest guard", "step self-check, errno 1, exit 123", "is not known"}},
		{124, "WARNING: docker said something first\nplimsoll guest guard: exec: errno 2\n", []string{"step exec", "is not known"}},
		{123, "plimsoll guest guard: exec: errno 2\n", []string{"docker did not run the container's command"}},
		{125, "docker: Error response from daemon: x\n", []string{"docker did not run the container's command", "Error response"}},
	} {
		err := unstartedRun("container's command", exitWith(c.code), c.stderr)
		if reason, marked := NotDispatchedReason(err); marked {
			t.Errorf("exit %d, %q: marked not dispatched (reason %v): %v; a fresh run is never marked from its own standard error", c.code, c.stderr, reason, err)
		}
		for _, w := range c.want {
			if err == nil || !strings.Contains(err.Error(), w) {
				t.Errorf("exit %d, %q: %v; want it to say %q", c.code, c.stderr, err, w)
			}
		}
		if err != nil && strings.Contains(c.want[0], "guest guard") && strings.Contains(err.Error(), "plimsoll guest guard:") {
			t.Errorf("exit %d: %q carries the guard's line itself; want plimsoll's own words", c.code, err)
		}
	}
}

// TestGuestGuardAtOpen holds the open's two readings of a main process that did not start
// (finding guest-guard-16): the guard's own line when the attached docker run's standard error
// ends with it and the marker never came, named by its step and errno; and, when no line can
// be read, the exit code alone, as the open read it before, so a main process that exited with
// a code of the guard's is still refused not dispatched.
func TestGuestGuardAtOpen(t *testing.T) {
	t.Parallel()
	const line = "plimsoll guest guard: exec: errno 2\n"
	for _, c := range []struct {
		name  string
		start mainStart
		want  string // "" for no refusal read from the line
	}{
		{"the guard's line, no marker", mainStart{exit: 124, stderr: line}, "step exec, errno 2 (exit 124)"},
		{"docker's warning, then the guard's line", mainStart{exit: 122, stderr: "WARNING: x\nplimsoll guest guard: install: errno 22\n"}, "step install, errno 22 (exit 122)"},
		{"the marker came", mainStart{started: true, stderr: line}, ""},
		{"no line", mainStart{exit: 124, stderr: ""}, ""},
		{"a line for another code", mainStart{exit: 123, stderr: line}, ""},
		{"docker's own failure", mainStart{exit: 125, stderr: "docker: Error response from daemon: x\n"}, ""},
	} {
		err := guardLineAtOpen(c.start)
		if c.want == "" {
			if err != nil {
				t.Errorf("%s: %v; want no refusal read from the line", c.name, err)
			}
			continue
		}
		if reason, ok := NotDispatchedReason(err); !ok || reason != RefusalEnvironment || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "main process") {
			t.Errorf("%s: %v; want not dispatched, environment, naming the main process and %q", c.name, err, c.want)
		}
		if err != nil && strings.Contains(err.Error(), "plimsoll guest guard:") {
			t.Errorf("%s: %q carries the guard's line itself", c.name, err)
		}
	}

	stopped := func(code int) dockerInspect {
		var insp dockerInspect
		insp.State.Status, insp.State.ExitCode = "exited", code
		return insp
	}
	for code := 120; code <= 124; code++ {
		err := guardCodeAtOpen(false, stopped(code))
		if reason, ok := NotDispatchedReason(err); !ok || reason != RefusalEnvironment || !strings.Contains(err.Error(), fmt.Sprintf("exit %d, its code for step", code)) {
			t.Errorf("no line, exit %d: %v; want the code-only refusal, not dispatched, environment", code, err)
		}
		err = guardCodeAtOpen(true, stopped(code))
		if reason, ok := NotDispatchedReason(err); !ok || reason != RefusalEnvironment || strings.Contains(err.Error(), "refused") || !strings.Contains(err.Error(), "after the guest guard had started it") {
			t.Errorf("after the marker, exit %d: %v; want not dispatched, not read as the guard's refusal", code, err)
		}
	}
	for _, code := range []int{0, 1, 119, 125, 137} {
		if err := guardCodeAtOpen(false, stopped(code)); err != nil {
			t.Errorf("exit %d: %v; want no refusal, not a code of the guard's", code, err)
		}
	}
	running := stopped(124)
	running.State.Running = true
	if err := guardCodeAtOpen(false, running); err != nil {
		t.Errorf("a running main process: %v", err)
	}
}

// TestDockerContainerCommandsAreBuiltOnlyBehindTheGuard fails the build when a docker container
// command could be built outside the three start paths: in this package's docker files, the
// --entrypoint flag is written only in launch, a docker exec only in execAs and attach, each of
// the three calls guardFirst, the guard's path is named only in docker_guestguard.go (so no
// builder puts it in front by hand, once more), and dockerCommand applies checkGuardedCommand.
func TestDockerContainerCommandsAreBuiltOnlyBehindTheGuard(t *testing.T) {
	t.Parallel()
	files, err := filepath.Glob("docker*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	calls := map[string]map[string]bool{} // function to the functions it calls
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") || strings.HasPrefix(name, "dockercloud") {
			continue // dockercloud is another provider, with no command line of its own
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			fname := fn.Name.Name
			calls[fname] = map[string]bool{}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.CallExpr:
					switch fun := n.Fun.(type) {
					case *ast.Ident:
						calls[fname][fun.Name] = true
					case *ast.SelectorExpr:
						calls[fname][fun.Sel.Name] = true
					}
				case *ast.BasicLit:
					if n.Kind != token.STRING {
						return true
					}
					v, _ := strconv.Unquote(n.Value)
					if (v == "--entrypoint" || strings.HasPrefix(v, "--entrypoint=")) && fname != "launch" && name != "docker_guestguard.go" {
						t.Errorf("%s: %s writes --entrypoint; only launch starts a run's command (behind the guard)", fset.Position(n.Pos()), fname)
					}
					if v == guestGuardTarget {
						t.Errorf("%s: names the guard's path; only docker_guestguard.go does, through guardFirst", fset.Position(n.Pos()))
					}
				case *ast.CompositeLit:
					if len(n.Elts) == 0 {
						return true
					}
					if lit, ok := n.Elts[0].(*ast.BasicLit); ok && lit.Kind == token.STRING && lit.Value == `"exec"` && fname != "execAs" && fname != "attach" {
						t.Errorf("%s: %s builds a docker exec; only execAs and attach do (behind the guard)", fset.Position(n.Pos()), fname)
					}
				case *ast.Ident:
					if n.Name == "guestGuardTarget" && name != "docker_guestguard.go" {
						t.Errorf("%s: %s names guestGuardTarget; only docker_guestguard.go does, through guardFirst", fset.Position(n.Pos()), fname)
					}
				}
				return true
			})
		}
	}
	for _, fn := range []string{"launch", "execAs", "attach"} {
		if !calls[fn]["guardFirst"] {
			t.Errorf("%s does not call guardFirst", fn)
		}
	}
	if !calls["dockerCommand"]["checkGuardedCommand"] {
		t.Error("dockerCommand does not call checkGuardedCommand")
	}
}

// The guest guard is built for plimsolld's machine, and Preflight refuses a container platform
// of another machine (finding guest-guard-22): the daemon's, DOCKER_DEFAULT_PLATFORM, or an
// image's, each read from a stand-in answer here.
func TestCheckGuestGuardPlatform(t *testing.T) {
	t.Parallel()
	same := map[string]string{"plimsoll/sandbox": "linux/amd64", "plimsoll/sandbox-sim": "linux/amd64/v3"}
	for _, ok := range []struct{ daemon, def string }{
		{"linux/amd64", ""}, {"linux/x86_64", ""}, {"linux/amd64", "linux/amd64"}, {"linux/amd64", "linux/amd64/v2"},
	} {
		if err := checkGuestGuardPlatform("amd64", ok.daemon, ok.def, same); err != nil {
			t.Errorf("daemon %q, DOCKER_DEFAULT_PLATFORM %q: %v", ok.daemon, ok.def, err)
		}
	}
	for what, c := range map[string]struct {
		goarch, daemon, def string
		images              map[string]string
		want                string
	}{
		"an arm64 daemon":                            {"amd64", "linux/arm64", "", same, "the docker daemon runs containers on linux/arm64"},
		"a daemon that does not say":                 {"amd64", "", "", same, "docker stated no platform"},
		"a Windows daemon":                           {"amd64", "windows/amd64", "", same, "windows/amd64"},
		"DOCKER_DEFAULT_PLATFORM of another machine": {"amd64", "linux/amd64", "linux/arm64", same, "DOCKER_DEFAULT_PLATFORM=\"linux/arm64\""},
		"an image of another machine":                {"amd64", "linux/amd64", "", map[string]string{"plimsoll/sandbox": "linux/amd64", "img-arm": "linux/arm64/v8"}, "docker image \"img-arm\" is built for linux/arm64"},
		"an image that states no platform":           {"amd64", "linux/amd64", "", map[string]string{"img": ""}, "docker image \"img\" states no platform"},
		"plimsolld on arm64 against amd64 docker":    {"arm64", "linux/amd64", "", same, "the guest guard plimsolld mounts into every container is its own machine's build, linux/arm64"},
	} {
		err := checkGuestGuardPlatform(c.goarch, c.daemon, c.def, c.images)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v; want a refusal saying %q", what, err, c.want)
		}
	}
}

// Preflight reads the platforms from the daemon and refuses one that is not the guard's: a
// stand-in daemon that states each answer in turn.
func TestDockerPreflightRefusesAnotherMachineThanTheGuards(t *testing.T) {
	if _, err := guestGuardPath(t.TempDir()); err != nil {
		t.Skipf("no guest guard is built for this machine: %v", err)
	}
	other := "arm64"
	if runtime.GOARCH == "arm64" {
		other = "amd64"
	}
	stand := func(daemon, image string) string {
		version := "exit 1"
		if daemon != "" {
			version = "echo " + daemon + "; exit 0"
		}
		return "#!/bin/sh\n[ \"$1\" = --config ] && shift 2\nif [ \"$1\" = context ]; then echo unix:///var/run/docker.sock; exit 0; fi\n" +
			"if [ \"$1\" = --host ] && [ \"$3\" = version ]; then " + version + "; fi\n" +
			"if [ \"$1\" = --host ] && [ \"$3\" = info ] && [ \"$5\" = '{{json .DriverStatus}}' ]; then echo '[]'; exit 0; fi\n" +
			"if [ \"$1\" = --host ] && [ \"$3\" = info ]; then echo '{\"runc\":{\"path\":\"runc\"}}'; exit 0; fi\n" +
			"if [ \"$1\" = --host ] && [ \"$3\" = image ]; then echo '{\"Id\":\"sha256:d0cafe0000000000000000000000000000000000000000000000000000000000\"," + image + "\"Config\":{}}'; exit 0; fi\nexit 1\n"
	}
	here := "\"Os\":\"linux\",\"Architecture\":\"" + runtime.GOARCH + "\","
	for what, c := range map[string]struct {
		script, platform, want string
	}{
		"the guard's machine everywhere":    {stand("linux/"+runtime.GOARCH, here), "", ""},
		"a daemon of another machine":       {stand("linux/"+other, here), "", "the docker daemon runs containers on linux/" + other},
		"a daemon that does not say":        {stand("", here), "", "docker did not state its platform"},
		"DOCKER_DEFAULT_PLATFORM elsewhere": {stand("linux/"+runtime.GOARCH, here), "linux/" + other, "DOCKER_DEFAULT_PLATFORM"},
		"an image of another machine":       {stand("linux/"+runtime.GOARCH, "\"Os\":\"linux\",\"Architecture\":\""+other+"\","), "", "is built for linux/" + other},
		"an image that states no platform":  {stand("linux/"+runtime.GOARCH, ""), "", "states no platform"},
	} {
		t.Run(what, func(t *testing.T) {
			bin := t.TempDir()
			if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(c.script), 0o755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", bin)
			t.Setenv("DOCKER_HOST", "")
			t.Setenv("DOCKER_CONTEXT", "")
			t.Setenv("DOCKER_DEFAULT_PLATFORM", c.platform)
			d := DefaultDocker("")
			d.Runtime = "runc"
			err := d.Preflight(context.Background())
			if c.want == "" {
				if err != nil {
					t.Fatalf("Preflight: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Preflight: %v; want a refusal saying %q", err, c.want)
			}
			if _, serr := d.executionState(); serr == nil {
				t.Fatal("a refused Preflight left the provider ready")
			}
		})
	}
}

// fakeGuestGuardPath is a guard file's path as writeGuestGuard names it, for a test that fakes
// Preflight: the file does not exist, and nothing in such a test starts a container.
const fakeGuestGuardPath = "/nonexistent/guest-guard-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// TestGuestGuardPolicyNamesTheGuardFile: the policy word is the guard file's digest, read from the
// name writeGuestGuard gives it, and a path that is not such a name has none, so verifiedState
// refuses it; every policy the provider states ends with the word (withGuard).
func TestGuestGuardPolicyNamesTheGuardFile(t *testing.T) {
	if got := guestGuardPolicy(fakeGuestGuardPath); got != "guest-guard:sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" {
		t.Fatalf("guestGuardPolicy = %q", got)
	}
	for _, bad := range []string{"", "/x/guest-guard", "/x/guest-guard-check-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"/x/guest-guard-0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef", "/x/guest-guard-0123"} {
		if got := guestGuardPolicy(bad); got != "" {
			t.Errorf("guestGuardPolicy(%q) = %q, want none", bad, got)
		}
	}
	dir := t.TempDir()
	path, err := writeGuestGuard(dir)
	if err != nil {
		t.Skipf("no guard can be written here: %v", err)
	}
	prog, _ := guestguard.Program(runtime.GOARCH)
	sum := sha256.Sum256(prog)
	if got, want := guestGuardPolicy(path), "guest-guard:sha256:"+hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("the written guard's word is %q, want %q, the SHA-256 of its bytes", got, want)
	}
	st := dockerExecutionState{guardPolicy: guestGuardPolicy(path)}
	if got := st.withGuard("seccomp:docker-default"); got != "seccomp:docker-default "+guestGuardPolicy(path) {
		t.Fatalf("withGuard = %q", got)
	}
}

// testGuestGuardWord is the policy word of the guard this machine's provider writes: the SHA-256
// of the committed guard program's bytes.
func testGuestGuardWord(t *testing.T) string {
	t.Helper()
	prog, err := guestguard.Program(runtime.GOARCH)
	if err != nil {
		t.Skipf("no guard for this machine: %v", err)
	}
	sum := sha256.Sum256(prog)
	return GuestGuardPolicyPrefix + hex.EncodeToString(sum[:])
}

// standInDocker puts a docker on PATH that records each start and fails, and returns how many
// times it was started with a command line containing word ("" for any).
func standInDocker(t *testing.T) func(word string) int {
	t.Helper()
	bin := t.TempDir()
	log := filepath.Join(bin, "started")
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte("#!/bin/sh\necho \"$*\" >> '"+log+"'\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	return func(word string) int {
		b, err := os.ReadFile(log)
		if os.IsNotExist(err) {
			return 0
		} else if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			if line != "" && strings.Contains(line, word) {
				n++
			}
		}
		return n
	}
}

// refusedState is an execution state whose guard is not the file dockerCommand names
// (guestGuardPath), so every docker run built from it is refused by the refusing point.
func refusedState() dockerExecutionState {
	return dockerExecutionState{host: "unix:///nonexistent.sock", guard: "/nonexistent/guest-guard-0", isolation: IsolationContainer,
		imageID: "sha256:image", projectImageID: "sha256:project", moduleImageID: "sha256:module"}
}

// requireRefusedNotDispatched requires err to be the refusing point's refusal, marked not
// dispatched for the environment, in plimsoll's own words only.
func requireRefusedNotDispatched(t *testing.T, what string, err error) {
	t.Helper()
	if reason, ok := NotDispatchedReason(err); !ok || reason != RefusalEnvironment {
		t.Fatalf("%s: %v (reason %v, marked %v); want not dispatched, environment", what, err, reason, ok)
	}
	if !errors.As(err, new(dockerRefusal)) {
		t.Fatalf("%s: %v does not carry the refusal", what, err)
	}
	if strings.Contains(err.Error(), "/nonexistent") || strings.Contains(err.Error(), "-bad-name") {
		t.Fatalf("%s: the error quotes the refused command: %v", what, err)
	}
}

// A command the refusing point refuses never started docker, so a fresh run, a project run, a
// module run and a session's open return it marked not dispatched, reason environment (finding
// guest-guard-24).
func TestDockerRefusedCommandIsNotDispatched(t *testing.T) {
	started := standInDocker(t)
	if _, err := guestGuardPath(t.TempDir()); err != nil {
		t.Skipf("no guest guard is built for this machine: %v", err)
	}
	d := DefaultDocker("")
	ctx := context.Background()
	st := refusedState()
	_, err := d.runSnippet(ctx, st, Request{Code: "1", Timeout: 5 * time.Second})
	requireRefusedNotDispatched(t, "a fresh run", err)
	_, err = d.runPlan(ctx, st, st.projectImageID, ProjectRequest{Steps: []string{"true"}, Timeout: 5 * time.Second})
	requireRefusedNotDispatched(t, "a project run", err)
	// RunModule runs the module image through runPlan.
	_, err = d.runPlan(ctx, st, st.moduleImageID, ProjectRequest{Steps: []string{"true"}, Timeout: 5 * time.Second})
	requireRefusedNotDispatched(t, "a module run", err)
	_, err = d.newSessionContainer(ctx, st, time.Now().Add(time.Minute))
	requireRefusedNotDispatched(t, "a session's open", err)
	if n := started(""); n != 0 {
		t.Fatalf("docker was started %d times", n)
	}
}

// In a session, a refused command fails the open or a pool member before a caller holds it,
// marked not dispatched; once a caller holds the session it ends the session as a boundary
// that could not be proven does, and the call gets that end (finding guest-guard-24). Every
// process a session's call starts is started by an exec (execAs) or a relay (attach), so those
// two are the paths. The container's name here makes every exec refused (a word starting with -
// where the container stands), and so would every removal, so the teardown here removes nothing.
func TestDockerSessionRefusedCommand(t *testing.T) {
	started := standInDocker(t)
	argv := must(sessionkit.ControlArgv(nil, sessionkit.ListArgv()...))
	newSession := func(t *testing.T) *dockerSession {
		broker, err := startDockerSessionBroker()
		if err != nil {
			t.Fatal(err)
		}
		s := &dockerSession{d: DefaultDocker(""), name: "-bad-name", host: "unix:///nonexistent.sock", broker: broker}
		hooks := s.hooks()
		hooks.Teardown = func() {}
		s.life = sessionkit.NewLife(s.name, hooks)
		t.Cleanup(func() {
			broker.Close()
			s.life.Close()
			select {
			case <-s.life.Done():
			case <-time.After(30 * time.Second):
				t.Error("the session's teardown did not finish")
			}
		})
		return s
	}
	t.Run("not held", func(t *testing.T) {
		s := newSession(t)
		_, err := s.exec(context.Background(), argv, nil, nil, 1<<10, 1<<10)
		requireRefusedNotDispatched(t, "an exec at open", err)
		_, err = s.attach(argv, nil)
		requireRefusedNotDispatched(t, "a relay at open", err)
		if s.Err() != nil {
			t.Fatalf("the open's refusal ended the session itself: %v", s.Err())
		}
	})
	for what, call := range map[string]func(s *dockerSession) error{
		"an exec": func(s *dockerSession) error {
			_, err := s.exec(context.Background(), argv, nil, nil, 1<<10, 1<<10)
			return err
		},
		"a relay": func(s *dockerSession) error {
			_, err := s.attach(argv, nil)
			return err
		},
	} {
		t.Run("held, "+what, func(t *testing.T) {
			s := newSession(t)
			s.held.Store(true)
			err := call(s)
			var end *SessionEndedError
			if !errors.As(err, &end) || end.Reason != SessionBoundaryFailed {
				t.Fatalf("%s in a held session: %v; want the session ended, boundary failed", what, err)
			}
			if s.Err() == nil {
				t.Fatal("the session is still open")
			}
			if strings.Contains(err.Error(), "-bad-name") {
				t.Fatalf("the end quotes the refused command: %v", err)
			}
		})
	}
	if n := started("exec"); n != 0 {
		t.Fatalf("docker exec was started %d times", n)
	}
}

// TestDockerSessionCallRefusal holds the one place that decides a held session's call mark
// (callRefusal, finding guest-guard-24, 24 B, narrowed by hunt-security-30) to its rule: the
// call's own command refused by the refusing point, where docker never started, is marked not
// dispatched, reason environment, and ends the session; a standard error and exit code in the
// guard's refusal's form with no start marker end the session unmarked, whatever came before
// the line and whether bytes were dropped, since code of the session can write that line and
// take the marker; a marker, an exec error or no guard's line is left to the call's other
// branches.
func TestDockerSessionCallRefusal(t *testing.T) {
	t.Parallel()
	const marker = "plimsoll-started:0123456789abcdef\n"
	const line = "plimsoll guest guard: exec: errno 2\n"
	newSession := func(t *testing.T) *dockerSession {
		s := &dockerSession{d: DefaultDocker(""), name: "plsm-session-none"}
		hooks := s.hooks()
		hooks.Teardown = func() {}
		s.life = sessionkit.NewLife(s.name, hooks)
		t.Cleanup(s.life.Close)
		s.held.Store(true)
		return s
	}
	for _, c := range []struct {
		name   string
		out    dockerExecResult
		err    error
		marked bool // marked not dispatched, the session ended
		ended  bool // the session ended unmarked
	}{
		{name: "the refusing point refused it", out: dockerExecResult{refused: true}, marked: true},
		{name: "the guard's line and code with no marker", out: dockerExecResult{exited: true, exitCode: 124, stderr: line}, ended: true},
		{name: "bytes written before the guard's line", out: dockerExecResult{exited: true, exitCode: 124, stderr: "x\n" + line}, ended: true},
		{name: "the guard's line with bytes dropped", out: dockerExecResult{exited: true, exitCode: 124, stderr: line, stderrTruncated: true}, ended: true},
		{name: "the call started", out: dockerExecResult{exited: true, exitCode: 124, stderr: marker + line}},
		{name: "a code that is not the line's", out: dockerExecResult{exited: true, exitCode: 123, stderr: line}},
		{name: "no line", out: dockerExecResult{exited: true, exitCode: 1, stderr: "docker: error\n"}},
		{name: "no exit status", out: dockerExecResult{stderr: line}},
		{name: "an exec error", out: dockerExecResult{exited: true, exitCode: 124, stderr: line}, err: errors.New("the stream broke")},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := newSession(t)
			if c.out.refused {
				// What execAs returns with refused set: the session ended by s.refused.
				_ = s.refused(&refusedCommandError{})
			}
			err := s.callRefusal(c.out, c.err, marker)
			reason, marked := NotDispatchedReason(err)
			var end *SessionEndedError
			switch {
			case c.marked:
				if !marked || reason != RefusalEnvironment || !errors.As(err, &end) || end.Reason != SessionBoundaryFailed {
					t.Fatalf("%v (reason %v, marked %v); want not dispatched, environment, the session ended, boundary failed", err, reason, marked)
				}
			case c.ended:
				if marked || !errors.As(err, &end) || end.Reason != SessionBoundaryFailed {
					t.Fatalf("%v (marked %v); want the session ended, boundary failed, unmarked", err, marked)
				}
				if !strings.Contains(end.Detail, "step exec, errno 2, exit 124") || !strings.Contains(end.Detail, "whether the call's code ran is not known") || strings.Contains(end.Detail, "nothing was started") {
					t.Fatalf("the end's words %q; want the guard's step read and that whether the call ran is not known, never that nothing was started", end.Detail)
				}
			default:
				if err != nil || s.Err() != nil {
					t.Fatalf("%v (session %v); want nothing decided here and the session open", err, s.Err())
				}
			}
		})
	}
}

// TestGuestGuardCheckFailedSaysWhatTheExitSays holds smokeGuestGuard's refusal to the exit it
// read (finding guest-guard-30): only the self-check's exit says the filter is missing; a later
// attempt's says the filter is on and answers otherwise than its table; the ordinary request's
// says something refuses too much; exit 0 with another output and an exit the check never uses
// say whether the filter is on is not known. No message says what another case says.
func TestGuestGuardCheckFailedSaysWhatTheExitSays(t *testing.T) {
	const notBehind = "is not behind the guest guard's filter"
	for _, c := range []struct {
		name   string
		code   int
		stdout string
		want   []string
		never  []string
	}{
		{"the self-check", guestguard.CheckExitSelfCheck, "", []string{notBehind, "the self-check request did not get the answer only that filter gives", "exit 10"}, []string{"is behind the guest guard's filter (", "not known"}},
		{"a later attempt", guestguard.CheckExitMount, "", []string{"is behind the guest guard's filter (the self-check got the answer only that filter gives), but the filter does not answer as its table says", "a mount request is not refused", "exit 14"}, []string{notBehind, "not known"}},
		{"the ordinary request", guestguard.CheckExitOrdinary, "", []string{"gave every answer the guard check requires", "an ordinary request (a write to standard output) did not work", "refuses more than the guard's table says", "exit 15"}, []string{notBehind, "not known"}},
		{"exit 0 with another output", 0, "something else\n", []string{"exited 0 but wrote \"something else\\n\"", "whether the guest guard's filter is on is not known", "exit 0"}, []string{notBehind}},
		{"an exit the check never uses", 159, "", []string{"ended with exit 159, a code it never uses", "159 is SIGSYS", "whether the guest guard's filter is on is not known"}, []string{notBehind}},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := guestGuardCheckFailed("amd64", c.code, c.stdout)
			if err == nil {
				t.Fatal("no refusal")
			}
			for _, w := range c.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("%v\nwant it to say %q", err, w)
				}
			}
			for _, n := range c.never {
				if strings.Contains(err.Error(), n) {
					t.Errorf("%v\nwant it not to say %q", err, n)
				}
			}
			if !strings.Contains(err.Error(), "nothing is served until the guard check passes") {
				t.Errorf("%v\nwant it to say nothing is served", err)
			}
		})
	}
}

// TestGuestGuardClaimSaysWhatTheCheckProves holds the guest-guard claim (published on
// docs/isolation-tiers.md) and docs/seccomp.md to what the startup check proves: each says
// which of the check's answers tell the guest guard from no guest guard, since a mount is
// refused without it too (finding guest-guard-31), that the guard's own bytes prove the rest, and
// each names, among what is not covered, the sdk_env variant the check never runs under
// (findings guest-guard-28 and guest-guard-26).
func TestGuestGuardClaimSaysWhatTheCheckProves(t *testing.T) {
	e, ok := boundary.For("docker").Entries[boundary.GuestGuard]
	if !ok {
		t.Fatal("docker declares no guest-guard claim")
	}
	claim, notCovered, ok := strings.Cut(e.How, "Not covered:")
	if !ok {
		t.Fatalf("the guest-guard claim has no Not covered list: %s", e.How)
	}
	seccomp, err := os.ReadFile("../docs/seccomp.md")
	if err != nil {
		t.Fatal(err)
	}
	section, _, _ := strings.Cut(string(seccomp), "## Architectures")
	_, section, _ = strings.Cut(section, "## The guest guard: a second filter in front of every program")
	page, pageNotCovered, ok := strings.Cut(section, "**What it does not cover.**")
	if !ok {
		t.Fatal("docs/seccomp.md's guest guard section has no list of what it does not cover")
	}
	for name, text := range map[string][2]string{"the guest-guard claim": {claim, notCovered}, "docs/seccomp.md": {page, pageNotCovered}} {
		for _, want := range []string{"Not every one of those answers tells the guest guard from no guest guard", "a mount", "only the guest guard's filter gives", "under gVisor also the namespace and tracing answers", "proved by the guest guard's own bytes"} {
			if !strings.Contains(strings.Join(strings.Fields(text[0]), " "), want) {
				t.Errorf("%s does not say %q", name, want)
			}
		}
		if !strings.Contains(text[1], "`sdk_env`") || !strings.Contains(strings.Join(strings.Fields(text[1]), " "), "default") {
			t.Errorf("%s's list of what is not covered does not name the sdk_env variant the startup check never runs under", name)
		}
	}
}
