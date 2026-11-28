package sandbox

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox/internal/sessionkit"
)

// failingMinter fails the way an issuer does when its request is cut: with its own words,
// not the context's error.
type failingMinter struct{}

func (failingMinter) Mint(context.Context, MintScope) (MintedToken, error) {
	return MintedToken{}, errors.New("token issuer: the request was cut short")
}

// A refusal raised because the call's own context ended before any of it was sent states
// the deadline limit, never queue or provider (finding release-122), on every path that
// raises one, and carries the context's error, so the daemon answers it deadline_exceeded
// or canceled.
func TestADeadlineRefusalStatesTheDeadlineLimit(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, cancelExpired := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelExpired()

	cellUnsent, _ := RefuseCell(expired, fmt.Errorf("%w: the deadline came first", sessionkit.ErrUnsent), nil)
	cellLaunch, _ := RefuseCell(canceled, fmt.Errorf("%w: docker exec was cut", sessionkit.ErrLaunch), nil)
	_, brokerErr := brokerSessionForGrant(canceled, &HostAPIGrant{BaseURL: "https://api.example.com", Minter: failingMinter{}}, time.Minute, nil)
	staged := &e2bSession{life: sessionkit.NewLife("e2b-test", sessionkit.Hooks{})}

	for _, c := range []struct {
		name  string
		err   error
		cause error
	}{
		{"a session call that gave up waiting for its turn", RefuseGaveUp(canceled), context.Canceled},
		{"a cell whose code was never sent", cellUnsent, context.DeadlineExceeded},
		{"a cell whose interpreter was starting when the caller gave up", cellLaunch, context.Canceled},
		{"an e2b call whose input staging met the deadline", staged.unsent(expired, errors.New("staging: cut")), context.DeadlineExceeded},
		{"a grant whose token was being issued", brokerErr, context.Canceled},
		{"a docker check cut by the caller's context", notReady(canceled, errors.New("docker info: cut")), context.Canceled},
	} {
		t.Run(c.name, func(t *testing.T) {
			if reason, marked := NotDispatchedReason(c.err); !marked || reason != RefusalCapacity {
				t.Fatalf("marked %v %v, want capacity: %v", marked, reason, c.err)
			}
			if got := CapacityLimitOf(c.err); got != CapacityDeadline {
				t.Fatalf("states limit %v, want deadline", got)
			}
			if !errors.Is(c.err, c.cause) {
				t.Fatalf("%v does not carry %v, so the daemon would not answer it as the call's own timeout", c.err, c.cause)
			}
		})
	}
}

// RefuseDeadline keeps a mark its error already carries, and a refusal asked of a context
// that has not ended (a deadline that has passed on a timer not yet fired) still reads as
// the deadline.
func TestRefuseDeadlineKeepsAnExistingMarkAndAnUnfiredDeadline(t *testing.T) {
	ended := RefuseEndedSession(&SessionEndedError{Reason: SessionExpired})
	if got := RefuseDeadline(context.Background(), ended); got != ended {
		t.Fatalf("a marked error was marked again: %v", got)
	}
	err := RefuseDeadline(context.Background(), errors.New("cut"))
	if CapacityLimitOf(err) != CapacityDeadline || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v, limit %v", err, CapacityLimitOf(err))
	}
}
