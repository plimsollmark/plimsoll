package sandbox

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox/internal/sessionkit"
)

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
