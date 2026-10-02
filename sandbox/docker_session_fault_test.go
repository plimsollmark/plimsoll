package sandbox_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// dockerFaults puts a docker CLI on PATH that runs the real one, except where a
// trigger file in the returned directory makes it fail the way a daemon or another
// operator can: a call's exec (the one whose last argument is "-", a snippet's node)
// failing with 125, alone or after pausing the container; a container inspect failing,
// or removing the container first and then failing in words docker never used; a
// container inspect taking 3 seconds. The faults are what the daemon does, not what
// guest code does, so no other way to cause them from a test exists.
func dockerFaults(t *testing.T) (trigger func(name, content string), clear func(name string)) {
	t.Helper()
	real, err := exec.LookPath("docker")
	if err != nil {
		t.Skip("docker not available")
	}
	bin, ctl := t.TempDir(), t.TempDir()
	script := fmt.Sprintf(`#!/bin/sh
real=%q
ctl=%q
cfg= host= sub= prev=
for a in "$@"; do
  case "$prev" in
  --config) cfg=$a; prev=; continue ;;
  --host) host=$a; prev=; continue ;;
  esac
  case "$a" in
  --config|--host) prev=$a ;;
  *) sub=$a; break ;;
  esac
done
last=
for a in "$@"; do last=$a; done
if [ "$sub" = exec ] && [ "$last" = - ]; then
  if [ -e "$ctl/call-exec-125" ]; then
    echo "Error response from daemon: injected failure" >&2
    exit 125
  fi
  if [ -e "$ctl/call-exec-pause" ]; then
    name=$(cat "$ctl/call-exec-pause"); rm -f "$ctl/call-exec-pause"
    "$real" --config "$cfg" --host "$host" pause "$name" >/dev/null
    echo "Error response from daemon: injected failure after a pause" >&2
    exit 125
  fi
fi
if [ "$sub" = ps ] && [ -e "$ctl/ps-flood" ]; then
  head -c 6000000 /dev/zero | tr '\0' x
  exit 0
fi
if [ "$sub" = inspect ]; then
  if [ -e "$ctl/inspect-fail" ]; then
    echo "injected: the daemon did not answer" >&2
    exit 1
  fi
  if [ -e "$ctl/inspect-remove" ]; then
    name=$(cat "$ctl/inspect-remove"); rm -f "$ctl/inspect-remove"
    "$real" --config "$cfg" --host "$host" rm -f "$name" >/dev/null 2>&1
    "$real" "$@" 2>/dev/null && exit 0
    echo "injected: wording docker never used" >&2
    exit 1
  fi
  if [ -e "$ctl/inspect-slow" ]; then sleep 3; fi
fi
exec "$real" "$@"
`, real, ctl)
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	trigger = func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(ctl, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	clear = func(name string) { _ = os.Remove(filepath.Join(ctl, name)) }
	return trigger, clear
}

// A snippet's own exit 125 is its result; docker's exit 125 for an exec that never
// started node is an error, never the caller's exit code with docker's words in its
// stderr.
func TestDockerSessionExecFailureIsNotTheCallsExit(t *testing.T) {
	d := sessionDocker(t)
	trigger, clear := dockerFaults(t)
	s := openDockerSession(t, d)
	res, err := sessionJS(t, s, `process.exit(125)`)
	if err != nil || res.ExitCode != 125 {
		t.Fatalf("a snippet's own exit 125: %+v, %v", res, err)
	}
	trigger("call-exec-125", "")
	res, err = sessionJS(t, s, `console.log("never")`)
	clear("call-exec-125")
	if err == nil {
		t.Fatalf("docker's failed exec came back as the call's result: exit %d, stderr %q", res.ExitCode, res.Stderr)
	}
	if _, marked := sandbox.NotDispatchedReason(err); marked {
		t.Fatalf("an exec docker may have started is marked not dispatched: %v", err)
	}
}

// A container paused while a call runs (the session pauses only between calls, with
// its turn held) ends the session as changed; docker's refusal to exec into it is not
// the call's exit code.
func TestDockerSessionPausedDuringACallEndsTheSession(t *testing.T) {
	d := sessionDocker(t)
	trigger, _ := dockerFaults(t)
	s := openDockerSession(t, d)
	name := sessionContainer(t, s, "pause-marker")
	trigger("call-exec-pause", name)
	res, err := sessionJS(t, s, `console.log("never")`)
	if err == nil {
		t.Fatalf("a call into a paused container came back as a result: exit %d, stderr %q", res.ExitCode, res.Stderr)
	}
	if got := sandbox.SessionEndReason(s.Err()); got != sandbox.SessionSandboxChanged {
		t.Fatalf("the session ended with %v, want sandbox_changed (call error %v)", got, err)
	}
}

// A container removed from outside is found gone whatever words docker's inspect
// uses, and the session ends as changed, the call refused before dispatch.
func TestDockerSessionGoneContainerIsFoundWithoutDockersWording(t *testing.T) {
	d := sessionDocker(t)
	trigger, _ := dockerFaults(t)
	s := openDockerSession(t, d)
	name := sessionContainer(t, s, "gone-marker")
	trigger("inspect-remove", name)
	_, err := sessionJS(t, s, `console.log("never")`)
	if !errors.Is(err, sandbox.ErrSessionEnded) || sandbox.SessionEndReason(s.Err()) != sandbox.SessionSandboxChanged {
		t.Fatalf("a call after the container was removed: %v (session %v)", err, s.Err())
	}
	if _, marked := sandbox.NotDispatchedReason(err); !marked {
		t.Fatalf("the refusal is not marked as not dispatched: %v", err)
	}
}

// A read-back that fails ran nothing: the call is refused before dispatch, reason
// environment, and the session goes on.
func TestDockerSessionFailedReadBackIsNotDispatched(t *testing.T) {
	d := sessionDocker(t)
	trigger, clear := dockerFaults(t)
	s := openDockerSession(t, d)
	if _, err := sessionJS(t, s, `require("fs").writeFileSync("/work/ran", "")`); err != nil {
		t.Fatal(err)
	}
	trigger("inspect-fail", "")
	_, err := sessionJS(t, s, `require("fs").writeFileSync("/work/ran", "again")`)
	clear("inspect-fail")
	if reason, marked := sandbox.NotDispatchedReason(err); !marked || reason != sandbox.RefusalEnvironment {
		t.Fatalf("a call whose read-back failed: %v (marked %v, reason %v)", err, marked, reason)
	}
	res, err := sessionJS(t, s, `process.stdout.write(require("fs").readFileSync("/work/ran", "utf8") || "empty")`)
	if err != nil || res.Stdout != "empty" {
		t.Fatalf("after the refusal: %+v, %v (the refused call must not have run)", res, err)
	}
}

// A grant whose credential cannot be minted is refused before dispatch, reason
// permission, and the call's code never runs.
func TestDockerSessionFailedMintIsNotDispatched(t *testing.T) {
	d := sessionDocker(t)
	s := openDockerSession(t, d)
	grant := &sandbox.HostAPIGrant{
		BaseURL:         "http://127.0.0.1:1",
		Allow:           []sandbox.HostRoute{{Method: "GET", Path: "/items/*"}},
		Minter:          failingMinter{},
		AllowInSessions: true,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_, err := s.RunJavaScript(ctx, sandbox.Request{Code: `require("fs").writeFileSync("/work/ran", "")`, Grant: grant, Timeout: 10 * time.Second})
	if reason, marked := sandbox.NotDispatchedReason(err); !marked || reason != sandbox.RefusalPermission {
		t.Fatalf("a call whose mint failed: %v (marked %v, reason %v)", err, marked, reason)
	}
	res, err := sessionJS(t, s, `console.log(require("fs").existsSync("/work/ran"))`)
	if err != nil || strings.TrimSpace(res.Stdout) != "false" {
		t.Fatalf("after the refusal: %+v, %v (the refused call must not have run)", res, err)
	}
}

type failingMinter struct{}

func (failingMinter) Mint(context.Context, sandbox.MintScope) (sandbox.MintedToken, error) {
	return sandbox.MintedToken{}, errors.New("injected: the token service is down")
}

// An open still in flight when Drain starts does not outlive it: Drain waits for it,
// and it either fails or hands over a session that has ended, its container removed.
func TestDockerSessionDrainCoversAnOpenInFlight(t *testing.T) {
	d := sessionDocker(t)
	trigger, clear := dockerFaults(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := d.Preflight(ctx); err != nil {
		t.Fatal(err)
	}
	before := sessionContainers(t)
	trigger("inspect-slow", "")
	type opened struct {
		s   sandbox.Session
		err error
	}
	got := make(chan opened, 1)
	go func() {
		s, err := d.OpenSession(ctx, sandbox.SessionOptions{Lifetime: 5 * time.Minute})
		got <- opened{s, err}
	}()
	var started []string
	for deadline := time.Now().Add(60 * time.Second); len(started) == 0; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the open never created its container")
		}
		for _, name := range sessionContainers(t) {
			if !slices.Contains(before, name) {
				started = append(started, name)
			}
		}
	}
	if err := d.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	clear("inspect-slow")
	for _, name := range sessionContainers(t) {
		if slices.Contains(started, name) {
			t.Errorf("container %s outlived Drain", name)
		}
	}
	o := <-got
	if o.err == nil {
		defer func() { _ = o.s.Close(context.Background()) }()
		if o.s.Err() == nil {
			t.Fatal("an open in flight during Drain handed over a live session")
		}
	}
}

// Orphan reconciliation parses docker's listing, so an answer past the bound plimsoll
// reads is an error, not a listing read in part (or held whole in memory).
func TestDockerReconcileOrphansRefusesAnUnboundedListing(t *testing.T) {
	d := sessionDocker(t)
	trigger, clear := dockerFaults(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := d.Preflight(ctx); err != nil {
		t.Fatal(err)
	}
	trigger("ps-flood", "")
	_, err := d.ReconcileOrphans(ctx)
	clear("ps-flood")
	if err == nil {
		t.Fatal("a 6 MB docker ps answer was read as a listing")
	}
}
