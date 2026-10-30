package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox/internal/sessionkit"
)

// A session's call whose stderr holds no start marker fails in plimsoll's own words:
// session code can write into the new process's stderr before the marker, so what
// docker exec left there is never in the error, which the daemon writes to the
// operator's log (the 2026-10-29 public-source scan, finding 2). A docker that reads the
// container back as running, answers every exec (the call and the sweep after it) with a
// canary on stderr and exit 1, and removes the container stands in for both. The failed
// sweep ends the session, and the test waits for its teardown with that docker still
// first on PATH.
func TestDockerSessionUnmarkedCallErrorQuotesNoStderr(t *testing.T) {
	const canary = "CANARY-guest-wrote-this-4d1f"
	const running = `[{"State":{"Running":true},"HostConfig":{}}]`
	dir := t.TempDir()
	fake := "#!/bin/sh\nfor a; do\n  case $a in\n    inspect) printf '%s' '" + running + "'; exit 0 ;;\n    rm) exit 0 ;;\n    exec) break ;;\n  esac\ndone\n" +
		"cat >/dev/null\nprintf '%s\\n' '" + canary + "' >&2\nexit 1\n"
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	var insp []dockerInspect
	if err := json.Unmarshal([]byte(running), &insp); err != nil {
		t.Fatal(err)
	}
	broker, err := startDockerSessionBroker()
	if err != nil {
		t.Fatal(err)
	}
	s := &dockerSession{d: DefaultDocker(""), name: "plsm-session-test", host: "unix:///nonexistent.sock", snapshot: insp[0].securitySnapshot(), broker: broker}
	s.life = sessionkit.NewLife("plsm-session-test", s.hooks())
	defer func() {
		s.life.Close()
		select {
		case <-s.life.Done():
		case <-time.After(30 * time.Second):
			t.Error("the session's teardown did not finish")
		}
	}()
	_, err = s.RunJavaScript(context.Background(), Request{Code: "1", Timeout: 5 * time.Second})
	if err == nil || !strings.Contains(err.Error(), "docker could not run the call in the session's container (exit 1)") {
		t.Fatalf("an unmarked call: %v; want the session's no-marker error", err)
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("the error quotes stderr: %v", err)
	}
}

// A call that gives up waiting for the turn, held here as the previous call's sweep
// holds it, ran nothing: it is marked so, as the daemon's own busy refusal is.
func TestDockerSessionGivingUpOnTheTurnIsNotDispatched(t *testing.T) {
	t.Parallel()
	s := &dockerSession{d: DefaultDocker("")}
	s.life = sessionkit.NewLife("plsm-session-test", s.hooks())
	release, err := s.life.Hold(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err = s.RunJavaScript(ctx, Request{Code: "1", Timeout: time.Second})
	if reason, ok := NotDispatchedReason(err); !ok || reason != RefusalCapacity || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a call behind a held turn: %v (reason %v, marked %v); want the deadline, not dispatched, capacity", err, reason, ok)
	}
}

// An interpreter that cannot start on a session that has ended failed because of
// the end, and the caller is told the end; on a live session it is the image.
func TestRefuseCellReportsTheSessionsEnd(t *testing.T) {
	launch := fmt.Errorf("%w: the javascript interpreter exited at start", sessionkit.ErrLaunch)
	end := &SessionEndedError{Reason: SessionExpired}

	var se *SessionEndedError
	err, _ := RefuseCell(context.Background(), launch, end)
	if reason, ok := NotDispatchedReason(err); !ok || reason != RefusalRequest || !errors.As(err, &se) || se.Reason != SessionExpired {
		t.Fatalf("launch on an ended session: %v; want the session's end, not dispatched", err)
	}
	err, _ = RefuseCell(context.Background(), launch, nil)
	if reason, ok := NotDispatchedReason(err); !ok || reason != RefusalEnvironment || !errors.Is(err, ErrUnsupported) {
		t.Fatalf("launch on a live session: %v; want unsupported, not dispatched, environment", err)
	}
	// The launch error can carry an exec's stderr, so it travels marked private, and is
	// still the launch error.
	var pe *PrivateError
	if !errors.As(err, &pe) || pe.Error() != launch.Error() || !errors.Is(err, sessionkit.ErrLaunch) {
		t.Fatalf("launch on a live session: %v; want the launch error marked private", err)
	}

	// A caller whose context ended while the interpreter started gave up; the image is
	// not to blame.
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	err, _ = RefuseCell(gone, launch, nil)
	if reason, ok := NotDispatchedReason(err); !ok || reason != RefusalCapacity || errors.Is(err, ErrUnsupported) {
		t.Fatalf("launch cut off by the caller: %v (reason %q); want not dispatched, capacity, not unsupported", err, reason)
	}

	// docker's cell path asks the session whether it ended.
	_, err = SessionCellResult(context.Background(), CellResult{}, sessionkit.CellOutcome{}, launch, 0, "", "",
		func() error { return end }, func() error { return nil }, func(e error) error { return e })
	if !errors.As(err, &se) {
		t.Fatalf("docker cell whose launch met the session's end: %v; want the end", err)
	}
}

// A cell whose interpreter ended on a session that has ended is reported as the
// session's end, not as the cell's outcome: the teardown closing the relay can reach the
// cell before the cancelled context does, and a container whose removal has not landed
// still reads as running. Execution may
// have happened, so the end is not marked. A cell that ended its own interpreter on a
// live session is its result, as before.
func TestACellCutOffByTheSessionsEndIsTheEnd(t *testing.T) {
	end := &SessionEndedError{Reason: SessionExpired}
	cut := sessionkit.CellOutcome{Started: true, Ended: true, Raised: true}
	var se *SessionEndedError
	_, err := SessionCellResult(context.Background(), CellResult{}, cut, nil, 0, "", "",
		func() error { return end }, func() error { return nil }, func(e error) error { return e })
	if !errors.As(err, &se) {
		t.Fatalf("a cell cut off by the session's end: %v; want the end", err)
	}
	if _, marked := NotDispatchedReason(err); marked {
		t.Fatalf("the end of a cell that may have run is marked not dispatched: %v", err)
	}
	res, err := SessionCellResult(context.Background(), CellResult{}, cut, nil, 0, "", "",
		func() error { return nil }, func() error { return nil }, func(e error) error { return e })
	if err != nil || res.ExitCode != 1 || !res.InterpreterEnded {
		t.Fatalf("a cell that ended its interpreter on a live session: %+v, %v; want its result", res, err)
	}
}
