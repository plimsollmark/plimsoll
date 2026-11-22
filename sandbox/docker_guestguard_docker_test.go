package sandbox

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox/internal/guestguard"
)

// The guest guard as the docker provider runs it (docker_guestguard.go), on real docker: under
// docker's ordinary runtime with the profile SANDBOX_DOCKER_SECCOMP names (the docker suite sets
// the shipped one; unset is docker's own default) or under gVisor (SANDBOX_DOCKER_RUNTIME=runsc).

// guardedAttempts is the attempts script (testdata/guest_guard_attempts.py) in its "behind" mode,
// each request made in a child of the process it runs in, then the road of finding
// noexec-setting-3 (testdata/guest_guard_road.py), and check reads what it printed: every request
// gets the answer Table.Decide gives, and the road stops at its first step, refused.
func guardedAttempts(t *testing.T, d *DockerSandbox) (string, func(where, out string)) {
	t.Helper()
	tb, v, cases := guestGuardCases(t, d)
	filter, err := guestguard.Filter(runtime.GOARCH, v.Suffix)
	if err != nil {
		t.Fatal(err)
	}
	casesJSON, err := json.Marshal(cases)
	if err != nil {
		t.Fatal(err)
	}
	read := func(name string) string {
		b, err := os.ReadFile("testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	script := fmt.Sprintf("FILTER = bytes.fromhex(%q)\nCASES = %s\nMODES = [\"behind\"]\n", hex.EncodeToString(filter), casesJSON) +
		read("guest_guard_attempts.py") + read("guest_guard_road.py")
	check := func(where, out string) {
		t.Helper()
		rows := guestGuardRows(t, []byte(out))
		for _, c := range cases {
			r, ok := rows[c.Name+"/behind"]
			if !ok {
				t.Errorf("%s: no row for %q; the output:\n%s", where, c.Name, out)
				continue
			}
			arg0 := uint64(0)
			if len(c.Args) > 0 {
				arg0 = uint64(c.Args[0])
			}
			if want := tb.Decide(v, v.Arch.Audit(), uint32(c.Nr), arg0); r.answer() != want {
				t.Errorf("%s: %s answered %s; the guard's table says %s", where, c.Name, r.answer(), want)
			}
		}
		var road map[string]any
		for _, line := range strings.Split(out, "\n") {
			var m map[string]map[string]any
			if json.Unmarshal([]byte(line), &m) == nil && m["road"] != nil {
				road = m["road"]
			}
		}
		if len(road) != 1 || road["unshare"] != float64(-errEPERM) {
			t.Errorf("%s: the road of finding noexec-setting-3 went %v; want it stopped at its first step, unshare refused with EPERM", where, road)
		}
	}
	return script, check
}

// pythonFromNode is a snippet whose node starts python3 with script on its standard input, and
// passes on what python printed and how it exited: the guest's own program starting another.
func pythonFromNode(script string) string {
	in, _ := json.Marshal(script)
	return `const r = require("child_process").spawnSync("python3", ["-I", "-"], {input: ` + string(in) + `, encoding: "utf8"});
process.stdout.write(r.stdout || ""); process.stderr.write(r.stderr || (r.error ? String(r.error) : ""));
process.exitCode = r.status === null ? 99 : r.status;`
}

// impersonator is guest code that prints the guard's own refusal line and exits with its code:
// it must read as the guest's exit, since its output follows the call's start marker.
const impersonatorLine = "plimsoll guest guard: self-check: the guard's own answer did not come back: errno 1\n"

func impersonatorJS(code int) string {
	return fmt.Sprintf(`process.stderr.write(%q); process.exit(%d)`, impersonatorLine, code)
}

// TestDockerGuestGuardRuns: a fresh snippet, a project with steps and a module run start behind
// the guard. In the snippet the guest's node starts python, whose children make every request of
// the table and walk the road of finding noexec-setting-3; in the project a step does the same;
// each answer is the table's, and the road stops at its first step. A guest that exits 123 or 124
// and prints the guard's line is the guest's exit, a normal result, never the guard's refusal.
func TestDockerGuestGuardRuns(t *testing.T) {
	t.Parallel()
	d := testDocker()
	d.Image, d.ProjectImage, d.ModuleImage = pythonProjectImage, pythonProjectImage, simProjectImage
	requireProjectImage(t, d)
	requireModuleImage(t, d)
	script, check := guardedAttempts(t, d)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	res, err := d.RunJavaScript(ctx, Request{Code: pythonFromNode(script), Timeout: time.Minute})
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("a snippet starting python: %+v, %v", res, err)
	}
	check("a fresh snippet's python", res.Stdout)

	pres, err := d.RunProject(ctx, ProjectRequest{Files: []File{{Path: "attempts.py", Content: script}},
		Steps: []string{"python3 -I attempts.py", "unshare -U true; echo $?"}})
	if err != nil || pres.Outcome != ProjectOutcomeCompleted || len(pres.Steps) != 2 {
		t.Fatalf("a project: %+v, %v", pres, err)
	}
	check("a project step", pres.Steps[0].Stdout)
	if got := strings.TrimSpace(pres.Steps[1].Stdout); got != "1" {
		t.Errorf("the unshare tool in a project step exited %q (stderr %q); want 1, the namespace refused", got, pres.Steps[1].Stderr)
	}

	mres, err := d.RunModule(ctx, ModuleRequest{Model: "vanderpol", Rows: sweepRows(2, 0.1, 5.0, 2.0, 0.0), EndTime: simVanDerPolTEnd, Step: 0.01})
	if err != nil || len(mres.Runs) != 2 {
		t.Fatalf("a module run behind the guard: %+v, %v", mres, err)
	}

	for _, code := range []int{123, 124} {
		r, err := d.RunJavaScript(ctx, Request{Code: impersonatorJS(code)})
		if err != nil || r.ExitCode != code || r.Stderr != impersonatorLine {
			t.Errorf("guest code exiting %d with the guard's line: %+v, %v; want the guest's own result", code, r, err)
		}
	}
	ip, err := d.RunProject(ctx, ProjectRequest{Steps: []string{`printf 'plimsoll guest guard: exec: errno 2\n' >&2; exit 124`}})
	if err != nil || ip.Outcome != ProjectOutcomeCompleted || len(ip.Steps) != 1 || ip.Steps[0].ExitCode != 124 {
		t.Errorf("a step exiting 124 with the guard's line: %+v, %v; want the step's own exit", ip, err)
	}
}

// TestDockerGuestGuardSession: a session's container starts behind the guard and so does every
// call: a snippet, a project call, and Python cells through a kept interpreter and its relay,
// each making every request of the table and walking the road; the session goes on working
// after each (its sweep, quiesce, process lister, identity check, launcher and relays are
// plimsoll's own programs behind the guard), and a guest that impersonates the guard's refusal
// in a session gets its own exit and keeps its session.
func TestDockerGuestGuardSession(t *testing.T) {
	t.Parallel()
	d := testDocker()
	d.ProjectImage = pythonProjectImage
	requireProjectImage(t, d)
	script, check := guardedAttempts(t, d)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := d.Preflight(ctx); err != nil {
		t.Fatal(err)
	}
	s, err := d.OpenSession(ctx, SessionOptions{Lifetime: 4 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close(ctx)

	r, err := s.RunJavaScript(ctx, Request{Code: pythonFromNode(script), Timeout: time.Minute})
	if err != nil || r.ExitCode != 0 {
		t.Fatalf("a session snippet: %+v, %v", r, err)
	}
	check("a session snippet's python", r.Stdout)
	p, err := s.RunProject(ctx, ProjectRequest{Files: []File{{Path: "attempts.py", Content: script}}, Steps: []string{"python3 -I attempts.py"}})
	if err != nil || p.Outcome != ProjectOutcomeCompleted || len(p.Steps) != 1 {
		t.Fatalf("a session project call: %+v, %v", p, err)
	}
	check("a session project step", p.Steps[0].Stdout)
	c, err := s.RunCell(ctx, CellRequest{Language: LanguagePython, Code: script})
	if err != nil || c.ExitCode != 0 {
		t.Fatalf("a Python cell: %+v, %v", c, err)
	}
	check("a Python cell", c.Stdout)
	c2, err := s.RunCell(ctx, CellRequest{Language: LanguagePython, Code: "print(len(CASES))"})
	if err != nil || c2.ExitCode != 0 || strings.TrimSpace(c2.Stdout) == "" {
		t.Fatalf("a second cell in the kept interpreter: %+v, %v", c2, err)
	}
	for _, code := range []int{123, 124} {
		r, err := s.RunJavaScript(ctx, Request{Code: impersonatorJS(code)})
		if err != nil || r.ExitCode != code || r.Stderr != impersonatorLine {
			t.Errorf("session code exiting %d with the guard's line: %+v, %v; want the guest's own result", code, r, err)
		}
	}
	if r, err := s.RunJavaScript(ctx, Request{Code: `console.log("still open")`}); err != nil || strings.TrimSpace(r.Stdout) != "still open" || s.Err() != nil {
		t.Fatalf("the session after the impersonations: %+v, %v, %v; want it open", r, err, s.Err())
	}
}

// TestDockerGuestGuardRefusalIsMarkedOnlyAtOpen: an image without /usr/bin/env, the program the
// guard starts every command with, so the guard's exec fails (exit 124, "plimsoll guest guard:
// exec: errno 2") and nothing starts. A session open, whose main process exits 124 before any
// code of a caller's exists, is refused not dispatched, reason environment, naming the guard's
// step. A fresh snippet and a project run get an unmarked error naming the step and saying
// whether the run's code ran is not known: their own code can write that line and exit with that
// code (unstartedRun; TestDockerFreshRunGuardLineIsNeverMarked does it).
func TestDockerGuestGuardRefusalIsMarkedOnlyAtOpen(t *testing.T) {
	t.Parallel()
	requireDocker(t)
	img := throwawayTag("no-env-image")
	build := exec.Command("docker", "build", "-q", "-t", img, "-")
	build.Stdin = strings.NewReader("FROM plimsoll/sandbox:latest\nUSER root\nRUN rm /usr/bin/env\nUSER node\n")
	if out, err := build.CombinedOutput(); err != nil {
		infraSkip(t, "cannot build throwaway image: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rmi", "-f", img).Run() })
	d := testDocker()
	d.Image, d.ProjectImage = img, img
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	if err := d.Preflight(ctx); err != nil {
		t.Fatal(err)
	}
	refused := func(what string, err error) {
		t.Helper()
		reason, marked := NotDispatchedReason(err)
		if !marked || reason != RefusalEnvironment || !strings.Contains(err.Error(), "guest guard") || !strings.Contains(err.Error(), "exec") {
			t.Errorf("%s: %v (marked %v, reason %v); want not dispatched, reason environment, naming the guard's exec step", what, err, marked, reason)
		}
		if err != nil && strings.Contains(err.Error(), "plimsoll guest guard:") {
			t.Errorf("%s: %q carries the guard's line itself; want plimsoll's own words", what, err)
		}
	}
	unmarked := func(what string, err error) {
		t.Helper()
		if reason, marked := NotDispatchedReason(err); marked {
			t.Errorf("%s: marked not dispatched (reason %v): %v; a fresh run is never marked from its own standard error", what, reason, err)
		}
		if err == nil || !strings.Contains(err.Error(), "guest guard") || !strings.Contains(err.Error(), "step exec") || !strings.Contains(err.Error(), "is not known") {
			t.Errorf("%s: %v; want an error naming the guard's exec step and saying whether the code ran is not known", what, err)
		}
		if err != nil && strings.Contains(err.Error(), "plimsoll guest guard:") {
			t.Errorf("%s: %q carries the guard's line itself; want plimsoll's own words", what, err)
		}
	}
	_, err := d.RunJavaScript(ctx, Request{Code: `console.log("unreached")`})
	unmarked("a snippet", err)
	_, err = d.RunProject(ctx, ProjectRequest{Steps: []string{"echo unreached"}})
	unmarked("a project", err)
	s, err := d.OpenSession(ctx, SessionOptions{Lifetime: time.Minute})
	if err == nil {
		s.Close(ctx)
	}
	refused("a session open", err)
}
