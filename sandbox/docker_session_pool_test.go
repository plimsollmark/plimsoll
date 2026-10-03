package sandbox_test

import (
	"context"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandbox/sessiontest"
)

// sessionContainers names the session containers on the docker host now.
func sessionContainers(t *testing.T) []string {
	t.Helper()
	out, err := exec.Command("docker", "ps", "-a", "--filter", "label=io.plimsoll.session", "--format", "{{.Names}}").Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.Fields(string(out))
}

// newContainers is the session containers present now that were not in before.
func newContainers(t *testing.T, before []string) []string {
	t.Helper()
	var added []string
	for _, name := range sessionContainers(t) {
		if !slices.Contains(before, name) {
			added = append(added, name)
		}
	}
	return added
}

// commandLines lists the command line of every process in a container.
func commandLines(t *testing.T, name string) string {
	t.Helper()
	out, err := exec.Command("docker", "exec", name, "sh", "-c",
		`for p in /proc/[0-9]*; do tr '\0' ' ' < "$p/cmdline" 2>/dev/null; echo; done`).Output()
	if err != nil {
		t.Fatalf("listing processes in %s: %v", name, err)
	}
	return string(out)
}

// startPool starts d's session pool and drains d when the test ends.
func startPool(t *testing.T, d *sandbox.DockerSandbox, size int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := d.SmokeTest(ctx); err != nil {
		t.Fatalf("SmokeTest: %v", err)
	}
	if err := d.StartSessionPool(ctx, size, 10*time.Minute); err != nil {
		t.Fatalf("StartSessionPool: %v", err)
	}
	t.Cleanup(func() {
		dctx, dcancel := context.WithTimeout(context.Background(), time.Minute)
		defer dcancel()
		if err := d.Drain(dctx); err != nil {
			t.Errorf("Drain: %v", err)
		}
	})
}

// A pool member is made before any session asks, with an interpreter for every
// language already running, and the next session is that member: its first cell in
// each language answers and says its interpreter is new, since no cell has defined
// anything there. The pool then makes a replacement, and Drain removes both the
// replacement and the session's container.
func TestDockerSessionPoolHandsOverAWarmMember(t *testing.T) {
	d := pythonSessionDocker(t)
	before := sessionContainers(t)
	startPool(t, d, 1)
	members := newContainers(t, before)
	if len(members) != 1 {
		t.Fatalf("the pool made %v; want one member", members)
	}
	member := members[0]
	procs := commandLines(t, member)
	if !strings.Contains(procs, "node --expose-internals -e") || !strings.Contains(procs, "python3 -I -c") {
		t.Fatalf("the member's processes before any session:\n%s\nwant a node and a python3 interpreter", procs)
	}

	s := openDockerSession(t, d)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, c := range []struct {
		lang       sandbox.Language
		code, want string
	}{{sandbox.LanguageJavaScript, "6 * 7", "42"}, {sandbox.LanguagePython, "6 * 7", "42"}} {
		start := time.Now()
		res, err := s.RunCell(ctx, sandbox.CellRequest{Language: c.lang, Code: c.code})
		if err != nil || res.ExitCode != 0 || !res.InterpreterStarted || strings.TrimSpace(res.Stdout) != c.want {
			t.Fatalf("first %s cell: %+v, %v; want %s from an interpreter reported as new", c.lang, res, err, c.want)
		}
		t.Logf("first %s cell of a claimed member: %v", c.lang, time.Since(start))
		if res, err = s.RunCell(ctx, sandbox.CellRequest{Language: c.lang, Code: c.code}); err != nil || res.InterpreterStarted {
			t.Fatalf("second %s cell: %+v, %v; want the same interpreter", c.lang, res, err)
		}
	}
	if name := sessionContainer(t, s, "pool-claim-marker"); name != member {
		t.Fatalf("the session runs in %s; want the pool member %s", name, member)
	}

	var replacement string
	for deadline := time.Now().Add(2 * time.Minute); replacement == "" && time.Now().Before(deadline); time.Sleep(250 * time.Millisecond) {
		for _, name := range newContainers(t, before) {
			if name != member {
				replacement = name
			}
		}
	}
	if replacement == "" {
		t.Fatal("the pool made no replacement after the claim")
	}
	dctx, dcancel := context.WithTimeout(context.Background(), time.Minute)
	defer dcancel()
	if err := d.Drain(dctx); err != nil {
		t.Fatal(err)
	}
	if left := newContainers(t, before); len(left) != 0 {
		t.Fatalf("after Drain: %v remain", left)
	}
}

// A member that stopped while it waited is never handed over: the next session gets a
// container of its own that works, and the dead member is removed.
func TestDockerSessionPoolPassesOverADeadMember(t *testing.T) {
	d := sessionDocker(t)
	before := sessionContainers(t)
	startPool(t, d, 1)
	members := newContainers(t, before)
	if len(members) != 1 {
		t.Fatalf("the pool made %v; want one member", members)
	}
	if out, err := exec.Command("docker", "kill", members[0]).CombinedOutput(); err != nil {
		t.Fatalf("docker kill: %v: %s", err, out)
	}
	// The member's relays are docker exec streams, which end within milliseconds of
	// the container; two seconds is ample for the pool to see it.
	time.Sleep(2 * time.Second)
	s := openDockerSession(t, d)
	res, err := sessionJS(t, s, `console.log("alive")`)
	if err != nil || strings.TrimSpace(res.Stdout) != "alive" {
		t.Fatalf("the session after a dead member: %+v, %v", res, err)
	}
	if name := sessionContainer(t, s, "pool-dead-marker"); name == members[0] {
		t.Fatal("the session was given the dead member")
	}
	for deadline := time.Now().Add(time.Minute); ; time.Sleep(250 * time.Millisecond) {
		if !slices.Contains(sessionContainers(t), members[0]) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the dead member was not removed")
		}
	}
}

// Every session the conformance suite opens comes from the pool while the pool keeps
// up, so pooled sessions keep every promise new ones do.
func TestDockerSessionPoolConformance(t *testing.T) {
	d := pythonSessionDocker(t)
	startPool(t, d, 2)
	langs := d.SessionEnvironments().Project.Languages
	sessiontest.Run(t, d, sessiontest.Config{Lifetime: 5 * time.Minute, ShortLifetime: 20 * time.Second, Languages: langs})
}

// Sessions that hint Python move the pool: after five of them, one of its two members
// warms Python alone (a node interpreter would only cost memory), and the next
// Python-hinted session is handed that member, whose first Python cell is warm. A
// JavaScript cell in it still runs: a hint changes latency, never behavior.
func TestDockerSessionPoolFollowsLanguageHints(t *testing.T) {
	d := pythonSessionDocker(t)
	before := sessionContainers(t)
	// 5 is the smallest pool that divides its members across language sets.
	startPool(t, d, 5)
	python := []sandbox.Language{sandbox.LanguagePython}
	open := func() sandbox.Session {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		s, err := d.OpenSession(ctx, sandbox.SessionOptions{Lifetime: 5 * time.Minute, DiskBytes: 64 << 20, Languages: python})
		if err != nil {
			t.Fatalf("OpenSession: %v", err)
		}
		t.Cleanup(func() { _ = s.Close(context.Background()) })
		return s
	}
	for range 5 {
		s := open()
		if err := s.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	// Closed sessions' containers are removed off the caller's path, and one of them
	// can look like a Python member, so wait until only the pool's five members are left:
	// one warming Python alone, four warming every language. A member joins the pool
	// once its relays are attached, after its interpreters start; a relay's command
	// line ends with its interpreter's directory and the work directory, so wait for
	// that, on two polls in a row.
	var member, seen string
	for deadline := time.Now().Add(3 * time.Minute); member == "" && time.Now().Before(deadline); time.Sleep(500 * time.Millisecond) {
		names := newContainers(t, before)
		if len(names) != 5 {
			seen = ""
			continue
		}
		var py, all []string
		for _, name := range names {
			out, err := exec.Command("docker", "exec", name, "sh", "-c",
				`for p in /proc/[0-9]*; do tr '\0' ' ' < "$p/cmdline" 2>/dev/null; echo; done`).Output()
			procs := string(out)
			switch {
			case err != nil || !strings.Contains(procs, ".plimsoll-interp/python /work"):
			case strings.Contains(procs, "node --expose-internals -e"):
				all = append(all, name)
			default:
				py = append(py, name)
			}
		}
		switch {
		case len(py) != 1 || len(all) != 4:
			seen = ""
		case py[0] == seen:
			member = seen
		default:
			seen = py[0]
		}
	}
	if member == "" {
		t.Fatalf("after five Python-hinted sessions the pool is not one member warming Python alone and four warming both: %v", newContainers(t, before))
	}
	s := open()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	res, err := s.RunCell(ctx, sandbox.CellRequest{Language: sandbox.LanguagePython, Code: "6 * 7"})
	if err != nil || strings.TrimSpace(res.Stdout) != "42" || !res.InterpreterStarted {
		t.Fatalf("first Python cell: %+v, %v", res, err)
	}
	if name := sessionContainer(t, s, "pool-hint-marker"); name != member {
		t.Fatalf("the Python-hinted session runs in %s; want the Python member %s", name, member)
	}
	if res, err := s.RunCell(ctx, sandbox.CellRequest{Language: sandbox.LanguageJavaScript, Code: "6 * 7"}); err != nil || strings.TrimSpace(res.Stdout) != "42" {
		t.Fatalf("a JavaScript cell in a Python member: %+v, %v", res, err)
	}
}
