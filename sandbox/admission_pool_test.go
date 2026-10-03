package sandbox

import (
	"context"
	"errors"
	"testing"
	"time"
)

// poolStartGate is a provider whose StartSessionPool, while gated, reports that a
// start has entered and returns what the test sends; ungated it returns nil. Only what
// admission calls is defined: the embedded Sandbox is nil.
type poolStartGate struct {
	Sandbox
	entered chan struct{}
	result  chan error
}

func (g *poolStartGate) Name() string { return "pool-start-gate" }

func (g *poolStartGate) StartSessionPool(context.Context, int, time.Duration) error {
	if g.entered == nil {
		return nil
	}
	g.entered <- struct{}{}
	return <-g.result
}

func (g *poolStartGate) Drain(context.Context) error { return nil }

// A session pool's reservation is given back once whatever the order of its start's
// end and Drain: a Drain can finish while a start is still inside the provider, which
// then refuses it. Given back twice, the budget would admit a pool's worth of runs
// more than it holds.
func TestAdmissionGivesAPoolReservationBackOnce(t *testing.T) {
	refused := errors.New("refused: the provider is draining")
	for _, tc := range []struct {
		name string
		run  func(t *testing.T, wrapped Sandbox, gate *poolStartGate)
	}{
		{"drain finishes while the start is in the provider, then the start fails", func(t *testing.T, wrapped Sandbox, gate *poolStartGate) {
			done := startGated(wrapped, gate)
			if err := wrapped.(Drainer).Drain(context.Background()); err != nil {
				t.Fatal(err)
			}
			gate.result <- refused
			if err := <-done; !errors.Is(err, refused) {
				t.Fatalf("the start: %v, want the provider's refusal", err)
			}
		}},
		{"the start fails, then drain", func(t *testing.T, wrapped Sandbox, gate *poolStartGate) {
			done := startGated(wrapped, gate)
			gate.result <- refused
			if err := <-done; !errors.Is(err, refused) {
				t.Fatalf("the start: %v, want the provider's refusal", err)
			}
			if err := wrapped.(Drainer).Drain(context.Background()); err != nil {
				t.Fatal(err)
			}
		}},
		{"the pool starts, then drain", func(t *testing.T, wrapped Sandbox, gate *poolStartGate) {
			done := startGated(wrapped, gate)
			gate.result <- nil
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if err := wrapped.(Drainer).Drain(context.Background()); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gate := &poolStartGate{entered: make(chan struct{}), result: make(chan error)}
			wrapped, err := WithAdmission(gate, AdmissionConfig{TotalMemoryMB: 512, PerRunMemoryMB: 256})
			if err != nil {
				t.Fatal(err)
			}
			tc.run(t, wrapped, gate)
			// The gated start has returned (its done channel was read), so ungating
			// does not race it.
			gate.entered, gate.result = nil, nil
			ctx := context.Background()
			if err := wrapped.(SessionPool).StartSessionPool(ctx, 3, time.Minute); err == nil {
				t.Fatal("a pool of 3 runs' memory started within a budget of 2: a reservation was given back twice")
			}
			if err := wrapped.(SessionPool).StartSessionPool(ctx, 2, time.Minute); err != nil {
				t.Fatalf("the whole budget of 2 runs is free once the pool is gone, but a pool of 2 was refused: %v", err)
			}
		})
	}
}

// startGated starts a one-member pool through wrapped and returns once the start is
// inside the provider, with a channel that carries its result.
func startGated(wrapped Sandbox, gate *poolStartGate) <-chan error {
	done := make(chan error, 1)
	go func() { done <- wrapped.(SessionPool).StartSessionPool(context.Background(), 1, time.Minute) }()
	<-gate.entered
	return done
}
