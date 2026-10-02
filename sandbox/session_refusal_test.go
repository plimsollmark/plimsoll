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
	s := &dockerSession{turn: make(chan struct{}, 1), done: make(chan struct{})}
	s.turn <- struct{}{}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := s.acquire(ctx)
	if reason, ok := NotDispatchedReason(err); !ok || reason != RefusalCapacity || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("acquire behind a held turn: %v (reason %v, marked %v); want the deadline, not dispatched, capacity", err, reason, ok)
	}
}

// An interpreter that cannot start on a session that has ended failed because of
// the end, and the caller is told the end; on a live session it is the image.
func TestRefuseCellReportsTheSessionsEnd(t *testing.T) {
	launch := fmt.Errorf("%w: the javascript interpreter exited at start", sessionkit.ErrLaunch)
	end := &SessionEndedError{Reason: SessionExpired}

	var se *SessionEndedError
	err, _ := RefuseCell(launch, end)
	if reason, ok := NotDispatchedReason(err); !ok || reason != RefusalRequest || !errors.As(err, &se) || se.Reason != SessionExpired {
		t.Fatalf("launch on an ended session: %v; want the session's end, not dispatched", err)
	}
	err, _ = RefuseCell(launch, nil)
	if reason, ok := NotDispatchedReason(err); !ok || reason != RefusalEnvironment || !errors.Is(err, ErrUnsupported) {
		t.Fatalf("launch on a live session: %v; want unsupported, not dispatched, environment", err)
	}

	// docker's cell path asks the session whether it ended.
	_, err = cellResult(CellResult{}, sessionkit.CellOutcome{}, launch, 0, "", "",
		func() error { return end }, func() error { return nil }, func(e error) error { return e })
	if !errors.As(err, &se) {
		t.Fatalf("docker cell whose launch met the session's end: %v; want the end", err)
	}
}
