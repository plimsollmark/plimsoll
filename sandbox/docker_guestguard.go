package sandbox

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/plimsollmark/plimsoll/sandbox/internal/sessionkit"
)

// The guest guard in the docker provider (the guard's design, step 3, private to the working
// copy; decisions 1 A and 2 A): every command the provider starts inside a container, the
// guest's and plimsoll's own alike, starts as guestGuardTarget -- COMMAND, so the guard puts its
// filter on (sandbox/internal/guestguard: no namespace, no mount, no new root, no clone3, no
// tracing, no other entry) before anything else runs, and every process that command starts
// keeps it. Three places hand a command to docker: launch (every docker run: a run's snippet or
// runner, a session's main process, the smoke programs), and a session's execAs (every docker
// exec: the snippet and runner of a session's call, the sweep, the quiesce, the process lister,
// the identity check, the interpreter launcher) and attach (every relay). Each builds its command
// through guardFirst, and dockerCommand refuses any command not on an allow list of the docker
// commands plimsoll uses, each in its shape, and any run or exec whose command does not start with
// the guard, names it twice, or mounts another file at its path (checkGuardedCommand), so a
// fourth place cannot start anything unguarded either. The guard runs once per command: a cell's interpreter is started by the
// guarded launcher and inherits its filter, so Interpreters.Start does not name it.
//
// A session's first process is the guard too (finding guest-guard-10, decision 10 B): docker's
// own init (--init), which docker started outside the guard, is gone, and the refusing point
// refuses a run that asks for it. In its place the session's docker run starts the guard in its
// process-1 mode (guestGuardPID1, launchPID1), which puts its filter on itself, starts the main
// process as its child and stays as process 1 to collect every process that ends in the
// container, so no process of the container runs outside the filter.

// guestGuardTarget is where the guard file is mounted, read-only, in every container the
// provider starts. A fresh name at the root of the image's read-only root filesystem: not on any
// writable mount (/tmp, /work and /dev/shm are the only ones), inside no directory an image
// ships, so no file of an image is hidden by the mount (a dot-name carrying plimsoll's prefix is
// in no public image), one path component, so docker makes only the empty file it mounts over;
// and not the path the design names for a guard built into an image
// (/usr/local/libexec/plimsoll-guard), so a later image that carries its own copy is never hidden
// by this mount either.
const guestGuardTarget = "/.plimsoll-guest-guard"

// guestGuardPID1 is the guard's one mode word: "guard --pid1 -- PROGRAM [ARG...]" stays as
// process 1 of a session's container, behind its own filter, and collects every process that
// ends there (program/guard.c; finding guest-guard-10, decision 10 B).
const guestGuardPID1 = "--pid1"

// dockerNoInit is the docker run word that keeps docker's own init out of every container
// plimsoll starts, whatever the daemon's default (lockdownFlags; finding guest-guard-39).
const dockerNoInit = "--init=false"

// guardFirst is the one place a container command is built: argv behind the guard. It refuses an
// empty command and one that already names the guard anywhere, so no command passes through the
// guard twice.
func guardFirst(argv []string) ([]string, error) {
	if len(argv) == 0 {
		return nil, fmt.Errorf("docker: no command to start behind the guest guard")
	}
	if slices.Contains(argv, guestGuardTarget) {
		return nil, fmt.Errorf("docker: the command already names the guest guard; it is put first once, by guardFirst")
	}
	out := append([]string{guestGuardTarget, "--"}, argv...)
	if seam := guardFirstSeam.Load(); seam != nil {
		if program := (*seam)(argv); program != "" {
			out[2] = program
		}
	}
	return out, nil
}

// guardFirstSeam is nil except in the docker tests of docker_guestguard_later_refusal_docker_test.go
// (findings guest-guard-15, 16 and 24): a function that names, for a command, another program for
// the guard to start in its place ("" for none). A test sets it for one command (a session's
// main process, a call's own command, the sweep after a call) to a path no image has, so the
// real guard's exec step fails and the guard refuses, which no real run can make it do once
// the session is open (the guard file and /usr/bin/env are on read-only mounts), or to the
// guard's own path, which the refusing point refuses before docker starts. It can change only
// the program after "--", never move or drop the guard, and the refusing point still checks the
// command it is in (checkGuardedCommand). Nothing outside the package's tests sets it.
var guardFirstSeam atomic.Pointer[func(argv []string) string]

// guardedPID1 is the command line of a session's process 1 as launchPID1 starts it: the guard in
// its process-1 mode, then argv.
func guardedPID1(argv []string) []string {
	return append([]string{guestGuardTarget, guestGuardPID1, "--"}, argv...)
}

// processOneIs reads the lister's output (stdout) and requires process 1's command line to be
// argv exactly, as /proc/1/cmdline holds it: each argument followed by a NUL.
func processOneIs(stdout []byte, argv []string) error {
	l, err := sessionkit.ParseListing(stdout)
	if err != nil {
		return err
	}
	want := hex.EncodeToString([]byte(strings.Join(argv, "\x00") + "\x00"))
	for _, pr := range l.Procs {
		if pr.PID != 1 {
			continue
		}
		if pr.CmdHex != want {
			return fmt.Errorf("process 1 of the session's container is %q, not the guest guard as plimsoll started it (%s %s); nothing in it may run outside the guard", truncateForError(pr.Cmd), guestGuardTarget, guestGuardPID1)
		}
		return nil
	}
	return errors.New("the process list of the session's container has no process 1")
}

// guestGuardMount is the --mount value that hands the guard file at host path guard (written by
// writeGuestGuard at Preflight) into a container at guestGuardTarget, read-only.
func guestGuardMount(guard string) string { return bindMountSpec(guard, guestGuardTarget) }

// dockerShape is one docker CLI command plimsoll starts and the shape it must have: the flags it
// may carry (each mapped to whether it takes a value, written as the next word: a flag joined to
// its value with = is not on the list, so it is refused), and how many other words (names, IDs)
// it takes.
type dockerShape struct {
	flags    map[string]bool
	min, max int
}

// dockerShapes is the allow list of checkGuardedCommand: every docker command the provider starts
// through dockerCommand, read from its callers (2026-11-19), and nothing else. A command that is
// not here, a flag of docker's own in front of it, or a flag of the command that is not in its
// shape is refused, so a later builder that needs another one adds it here, with a row in
// TestCheckGuardedCommand. run and exec, the two that start a container's processes, have shapes
// of their own (checkGuardedRun, checkGuardedExec). The callers:
//
//   - version --format: dockerSelectedPlatform and dockerDaemonPlatform (docker_preflight.go).
//   - info --format: verifyDockerDaemon and dockerUsesContainerdStore (docker_preflight.go).
//   - image inspect --format [--platform] IMAGE: verifyImageForRun and inspectPlatformImage
//     (docker_preflight.go).
//   - ps -a [-q --no-trunc] --filter [--format]: containerGone (docker_run.go), a session's
//     state check and the reaper's listing (docker_session.go); ps alone in
//     TestDockerCommandGetsNoDaemonEnvironment.
//   - inspect [--type | --format] NAME: a session's state check (docker_session.go), the
//     smoke test's process-limit check (docker_smoke.go) and unpauseForRemoval's state read
//     (docker_run.go).
//   - rm -f NAME: removeContainer (docker_run.go).
//   - pause NAME and unpause NAME: a session's suspend (docker_session.go); unpause also
//     unpauseForRemoval (docker_run.go).
//   - save ID: saveImage (docker_image_archive.go).
var dockerShapes = map[string]dockerShape{
	"version":       {flags: map[string]bool{"--format": true}},
	"info":          {flags: map[string]bool{"--format": true}},
	"image inspect": {flags: map[string]bool{"--format": true, "--platform": true}, min: 1, max: 1},
	"ps":            {flags: map[string]bool{"-a": false, "-q": false, "--no-trunc": false, "--filter": true, "--format": true}},
	"inspect":       {flags: map[string]bool{"--type": true, "--format": true}, min: 1, max: 1},
	"rm":            {flags: map[string]bool{"-f": false}, min: 1, max: 1},
	"pause":         {min: 1, max: 1},
	"unpause":       {min: 1, max: 1},
	"save":          {min: 1, max: 1},
}

// dockerRunFlags are the docker run flags the provider writes (lockdownArgs, lockdownFlags,
// labelArgs, a session's open, brokerForRun's mount, the smoke test's detached run, launch), each
// mapped to whether it takes a value. The first word that is neither one of them nor a flag's
// value is the image; docker reads every word after it as the container's command. docker's
// --init is not among them: it would start docker's own init as process 1, outside the guard
// (finding guest-guard-10); a session's process 1 is the guard (launchPID1). Its one form here
// is dockerNoInit, the word --init=false whole, which every run must carry once (checkGuardedRun),
// so a daemon's own init setting never applies (finding guest-guard-39); --init and --init=true
// are refused, as every other joined flag is.
var dockerRunFlags = map[string]bool{
	"--rm": false, "-i": false, "-d": false, "--read-only": false, "--no-healthcheck": false, dockerNoInit: false,
	"--name": true, "--log-driver": true, "--label": true, "--runtime": true, "--memory": true, "--memory-swap": true,
	"--pids-limit": true, "--cpus": true, "--tmpfs": true, "--user": true, "--cap-drop": true, "--security-opt": true,
	"--ulimit": true, "--ipc": true, "--network": true, "--mount": true, "--workdir": true, "--platform": true,
	"--entrypoint": true,
}

// dockerExecFlags are the docker exec flags execAs and attach write. The first word that is
// neither one of them nor a flag's value is the container; docker reads every word after it as
// the command.
var dockerExecFlags = map[string]bool{"-i": false, "-w": true, "--user": true, dockerEnvFlagWord: true}

// dockerFlags splits words into the flags of flags (with their values, in order) and the other
// words. stopAtFirst: run and exec end their own flags at the image or the container, and the
// words from there on are returned whole; every other command has no command of its own, so a
// flag after a name is still read as a flag. A word starting with - that is not in flags is
// refused, and so is a flag missing its value.
func dockerFlags(cmd string, words []string, flags map[string]bool, stopAtFirst bool) (opts [][2]string, rest []string, err error) {
	for i := 0; i < len(words); i++ {
		w := words[i]
		if !strings.HasPrefix(w, "-") {
			if stopAtFirst {
				return opts, words[i:], nil
			}
			rest = append(rest, w)
			continue
		}
		takes, ok := flags[w]
		if !ok {
			return nil, nil, fmt.Errorf("docker %s: plimsoll does not write the flag %q there; only the flags of the command's shape are allowed (docker_guestguard.go)", cmd, w)
		}
		if !takes {
			opts = append(opts, [2]string{w, ""})
			continue
		}
		if i+1 >= len(words) {
			return nil, nil, fmt.Errorf("docker %s: the flag %s has no value", cmd, w)
		}
		opts = append(opts, [2]string{w, words[i+1]})
		i++
	}
	return opts, rest, nil
}

// checkGuardedCommand is the refusing point dockerCommand applies to every docker CLI command it
// starts (findings guest-guard-19 and 20). args are what follows docker's --config: dockerArgs'
// one --host and its value, then the command. The command must be on the allow list
// (dockerShapes, run, exec), in its shape; a flag of docker's own in front of it, or any other
// command, is refused. A container's processes are started only by run and exec, and then only
// behind the guard: a run says --init=false once (dockerNoInit), so docker starts no init of its
// own, its entrypoint is the guard, once, the guard is mounted read-only from
// guard, the exact file Preflight verified, and no other flag names its path, and the image is
// followed by "--" and the command (checkGuardedRun); an exec's first word after the container
// is the guard, then "--" and the command (checkGuardedExec). guard is "" when no guard file is
// known for this machine, and then every run is refused. check is the guard check
// writeGuestGuardCheck writes beside the guard (guestGuardCheckPath): a run may also carry, once,
// its read-only mount at guestGuardCheckTarget from exactly that file, the startup smoke test's
// (smokeGuestGuard); any other mount there is refused. check is "" when no check is known for
// this machine, and then no run may mount one.
func checkGuardedCommand(args []string, guard, check string) error {
	if err := checkDockerShape(args, guard, check); err != nil {
		return dockerRefusal{err}
	}
	return nil
}

// dockerRefusal is every refusal of checkGuardedCommand, so a caller or a test can tell it from
// docker's own failure: a refused command never started docker.
type dockerRefusal struct{ error }

func (r dockerRefusal) Unwrap() error { return r.error }

// errDockerRefused is the words a caller gets for a command the refusing point refused: plimsoll's
// own, never the refusal's text, which names host paths and the command's words; plimsolld's log
// carries that (refusedCommand).
const errDockerRefused = "the docker command plimsoll built for this run does not pass the guest guard's refusing point, so docker was never started; plimsolld's log names the refusal"

// refusedCommandError is a refusal of the refusing point as it leaves the provider: its text is
// errDockerRefused, and it unwraps to the dockerRefusal.
type refusedCommandError struct{ refusal dockerRefusal }

func (e refusedCommandError) Error() string { return errDockerRefused }
func (e refusedCommandError) Unwrap() error { return e.refusal }

// refusedCommand is the refusal cmd carries from dockerCommand, logged with its text, or nil
// when cmd is not refused (finding guest-guard-24). Such a command never started docker, so the
// run paths return it marked not dispatched (reason environment): a fresh run, a project or
// module run, a session's open. In a session already handed to a caller it ends the session
// instead (dockerSession.refused).
func refusedCommand(cmd *exec.Cmd) *refusedCommandError { return refusalIn(cmd.Err) }

// refusalIn is refusedCommand for an error a command's Run or Output returned (dockerOutput's,
// for one): the refusal it carries, logged with its text, or nil when it carries none.
func refusalIn(err error) *refusedCommandError {
	var r dockerRefusal
	if err == nil || !errors.As(err, &r) {
		return nil
	}
	slog.Error("docker: the refusing point refused a command plimsoll built; docker was not started", "refusal", r.Error())
	return &refusedCommandError{refusal: r}
}

func checkDockerShape(args []string, guard, check string) error {
	if len(args) >= 2 && args[0] == "--host" {
		args = args[2:]
	}
	if len(args) == 0 {
		return nil // docker with no command prints its usage and starts nothing
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "run":
		return checkGuardedRun(rest, guard, check)
	case "exec":
		return checkGuardedExec(rest)
	case "image":
		if len(rest) == 0 || rest[0] != "inspect" {
			return fmt.Errorf("docker image: plimsoll uses only docker image inspect")
		}
		cmd, rest = "image inspect", rest[1:]
	}
	shape, ok := dockerShapes[cmd]
	if !ok {
		if strings.HasPrefix(cmd, "-") {
			return fmt.Errorf("docker: %q in front of the command; plimsoll writes no flag of docker's own but one --host", cmd)
		}
		return fmt.Errorf("docker %s: not a command plimsoll starts; it starts container commands only with run and exec, behind the guest guard, and its other commands are listed in dockerShapes (docker_guestguard.go)", cmd)
	}
	_, words, err := dockerFlags(cmd, rest, shape.flags, false)
	if err != nil {
		return err
	}
	if len(words) < shape.min || len(words) > shape.max {
		return fmt.Errorf("docker %s: %d names or IDs, not %d to %d", cmd, len(words), shape.min, shape.max)
	}
	return nil
}

// checkGuardedRun is checkGuardedCommand for a docker run, after the word run.
func checkGuardedRun(words []string, guard, check string) error {
	if guard == "" {
		return fmt.Errorf("docker run: no guest guard file is known for this machine; nothing starts without it")
	}
	opts, rest, err := dockerFlags("run", words, dockerRunFlags, true)
	if err != nil {
		return err
	}
	mount := guestGuardMount(guard)
	checkMount := ""
	if check != "" {
		checkMount = bindMountSpec(check, guestGuardCheckTarget)
	}
	entry, mounted, checks, noInit := 0, 0, 0, 0
	for _, o := range opts {
		switch {
		case o[0] == dockerNoInit:
			noInit++
		case o[0] == "--entrypoint":
			if o[1] != guestGuardTarget {
				return fmt.Errorf("docker run: the entrypoint is not the guest guard")
			}
			entry++
		case o[0] == "--mount" && o[1] == mount:
			mounted++
		case o[0] == "--mount" && checkMount != "" && o[1] == checkMount:
			// The startup smoke test's guard check, read-only, from the one file
			// writeGuestGuardCheck writes, at its one path (smokeGuestGuard).
			checks++
		case strings.Contains(o[1], guestGuardTarget):
			// A mount of another file there, a second mount over it (the later one would hide
			// the verified file), a tmpfs, a work directory, the check's path from another
			// source or writable: none is plimsoll's. guestGuardCheckTarget begins with
			// guestGuardTarget, so this covers both paths.
			return fmt.Errorf("docker run: %s %q names the guest guard's path; only its one read-only mount of the verified file does", o[0], o[1])
		}
	}
	if entry != 1 {
		return fmt.Errorf("docker run: %d entrypoints, not the one guest guard", entry)
	}
	if mounted != 1 {
		return fmt.Errorf("docker run: the guest guard is not mounted read-only at %s from the file Preflight verified, %s, once (%d)", guestGuardTarget, guard, mounted)
	}
	if checks > 1 {
		return fmt.Errorf("docker run: the guard check is mounted at %s %d times, not at most once", guestGuardCheckTarget, checks)
	}
	if noInit != 1 {
		// Without it, a daemon whose default is init puts docker's init in as process 1,
		// outside the guard (finding guest-guard-39).
		return fmt.Errorf("docker run: %s is written %d times, not once, so the daemon's own init setting could start docker's init as process 1", dockerNoInit, noInit)
	}
	// rest: the image, the guard's mode word (a session's, launchPID1) or none, --, the command.
	if len(rest) >= 2 && rest[1] == guestGuardPID1 {
		rest = rest[1:]
	}
	if len(rest) < 3 || rest[1] != "--" {
		return fmt.Errorf("docker run: the image is not followed by \"--\" (or %s --) and a command for the guest guard to start", guestGuardPID1)
	}
	if rest[2] == guestGuardPID1 {
		return fmt.Errorf("docker run: the guest guard's %s stands before its \"--\", never as the command", guestGuardPID1)
	}
	if slices.Contains(rest, guestGuardTarget) {
		return fmt.Errorf("docker run: the command names the guest guard again; it is started once, as the entrypoint")
	}
	return nil
}

// checkGuardedExec is checkGuardedCommand for a docker exec, after the word exec. Each -e is
// NAME=value (dockerEnvFlag): for a bare NAME docker copies a variable of its own into the
// container.
func checkGuardedExec(words []string) error {
	opts, rest, err := dockerFlags("exec", words, dockerExecFlags, true)
	if err != nil {
		return err
	}
	for _, o := range opts {
		if o[0] == dockerEnvFlagWord && !isDockerEnvPair(o[1]) {
			return fmt.Errorf("docker exec: -e %q is not NAME=value, so docker would copy a variable of its own into the container", o[1])
		}
	}
	// rest: the container, the guard, --, the command.
	if len(rest) < 4 || rest[1] != guestGuardTarget || rest[2] != "--" {
		return fmt.Errorf("docker exec: the first word after the container is not the guest guard followed by --, so the guard does not start the command")
	}
	if slices.Contains(rest[3:], guestGuardTarget) {
		return fmt.Errorf("docker exec: the command names the guest guard again; it is started once, first")
	}
	return nil
}

// exitCodeOf is the exit code a docker CLI command's error carries, -1 when it carries none.
func exitCodeOf(err error) int {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}

// guestGuardExit is each failure of the guard program by the step its line names: in each, the
// guard started nothing (program/guard.c).
var guestGuardExit = map[string]int{"usage": 120, "no_new_privs": 121, "install": 122, "self-check": 123, "exec": 124}

// guestGuardLine is the guard's one line, the last thing on standard error: "plimsoll guest
// guard: STEP[: DETAIL]: errno N".
var guestGuardLine = regexp.MustCompile(`(?:^|\n)plimsoll guest guard: (usage|no_new_privs|install|self-check|exec)(?:: [^\n]*)?: errno ([0-9]{1,4})\n$`)

// guestGuardRefusal reads a command that exited code with stderr as the guard's refusal: the code
// of a step, and as the last line of stderr the guard's line naming that same step. It is the
// reading only for a command no code of a caller's can reach: a session's main process and its
// process list at open, and the startup smoke test's check, where no code of a caller's exists
// yet. A fresh run's command and a held session's call are not read with it: their code can write
// the line, pick the code and, under runc, take the start marker off their standard error, so a
// guard-shaped end there is never marked (unstartedRun, dockerSession.callRefusal). The answer is
// plimsoll's own words from the step and errno it parsed, never the line itself.
func guestGuardRefusal(code int, stderr string) (string, bool) {
	step, errno, ok := guestGuardShape(code, stderr)
	if !ok {
		return "", false
	}
	return fmt.Sprintf("the guest guard refused to start the command, so nothing was started: step %s, errno %d (exit %d)", step, errno, code), true
}

// guestGuardShape reports whether a command that exited code with stderr ends as the guard
// ends when it refuses: the guard's line as the last line of stderr, naming a step whose code
// is code. It returns the step and errno the line names. It says nothing of who wrote the line
// (guestGuardRefusal is the reading for a command no code of a caller's can reach).
func guestGuardShape(code int, stderr string) (string, int, bool) {
	m := guestGuardLine.FindStringSubmatch(stderr)
	if m == nil || guestGuardExit[m[1]] != code {
		return "", 0, false
	}
	errno, _ := strconv.Atoi(m[2])
	return m[1], errno, true
}

// GuestGuardPolicyPrefix begins the guest guard's word in a policy: the guard file named by the
// SHA-256 of its bytes, the digest its file name carries (writeGuestGuard), so a record names the
// exact program its run started behind, and through program/guard.sha256 the filter inside it.
// Exported so a reader of records (examples/sdk-grants, examples/sbom's format check) uses the
// word the provider writes, never a copy of it.
const GuestGuardPolicyPrefix = "guest-guard:sha256:"

// guestGuardPolicy is the policy word of the guard file at path, as writeGuestGuard named it;
// "" for a path that is not one.
func guestGuardPolicy(path string) string {
	digest, ok := strings.CutPrefix(filepath.Base(path), "guest-guard-")
	if !ok || len(digest) != 64 || strings.Trim(digest, "0123456789abcdef") != "" {
		return ""
	}
	return GuestGuardPolicyPrefix + digest
}

// withGuard is policy followed by the guest guard's word: what a run's record and Describe state
// (docs/run-records.md, policy). Every command of the docker provider starts behind the guard,
// so every policy it states names it, under runc and gVisor alike. A run's record already covers
// policy, so the word needs no new record version and no new protocol number.
func (st dockerExecutionState) withGuard(policy string) string {
	return policy + " " + st.guardPolicy
}
