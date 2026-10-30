package rpc

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/sandbox"
)

func warmOpen(owner string) *connect.Request[plimsollv1.OpenSessionRequest] {
	r := ownerOpen(owner)
	r.Msg.WarmOnly = true
	return r
}

// refusedNoWarm is a refusal as the client reads it: ResourceExhausted, marked not
// dispatched, reason capacity.
func refusedNoWarm(err error) bool { return refusedCapacity(err) }

// Describe states the pool with sessions on, and nothing without them.
func TestDescribeStatesTheSessionPool(t *testing.T) {
	svc, _ := sessionService()
	svc.Sessions.Pool = 3
	resp, err := svc.Describe(context.Background(), connect.NewRequest(&plimsollv1.DescribeRequest{}))
	if err != nil || resp.Msg.GetSessionPool() != 3 {
		t.Fatalf("Describe = %d, %v; want a pool of 3", resp.Msg.GetSessionPool(), err)
	}
	svc.Sessions.MaxSessions = 0
	if resp, _ := svc.Describe(context.Background(), connect.NewRequest(&plimsollv1.DescribeRequest{})); resp.Msg.GetSessionPool() != 0 {
		t.Fatalf("with sessions off Describe states a pool of %d", resp.Msg.GetSessionPool())
	}
}

// A warm-only open on a daemon that keeps no pool is refused before the provider is
// asked, and takes no place.
func TestWarmOnlyOpenWithoutAPoolNeverReachesTheProvider(t *testing.T) {
	svc, p := sessionService()
	p.Warm = 5 // the provider would hand one over; the daemon states no pool
	_, err := svc.OpenSession(authenticatedContext("alice"), warmOpen(""))
	if !refusedNoWarm(err) || len(p.Opened()) != 0 {
		t.Fatalf("a warm-only open with no pool = %v, %d opened; want refused before the provider", err, len(p.Opened()))
	}
}

// With a pool, a warm-only open reaches the provider marked warm only; one the
// provider refuses (no member waiting) is refused, not dispatched, and gives its place
// back.
func TestWarmOnlyOpenReachesThePoolAndGivesItsPlaceBack(t *testing.T) {
	svc, p := sessionService()
	svc.Sessions.Pool, svc.Sessions.MaxSessions = 2, 1
	p.Warm = 1
	alice := authenticatedContext("alice")
	o, err := svc.OpenSession(alice, warmOpen(""))
	if err != nil {
		t.Fatal(err)
	}
	if opened := p.Opened(); len(opened) != 1 || !opened[0].Options.WarmOnly {
		t.Fatalf("the provider saw %d opens; want one, warm only", len(opened))
	}
	if _, err := svc.CloseSession(alice, closeReq(o.Msg.GetSessionId())); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.OpenSession(alice, warmOpen("")); !refusedNoWarm(err) || !errors.Is(err, sandbox.ErrAtCapacity) {
		t.Fatalf("a warm-only open with none waiting = %v; want refused, capacity", err)
	}
	// The refused open's place came back: the daemon's one place is free.
	if _, err := svc.OpenSession(alice, openReq()); err != nil {
		t.Fatalf("an open after the refused warm-only one: %v", err)
	}
}

// A warm-only open never closes another session of the owner to make room: at the
// owner's cap it is refused, and the owner's session stays open.
func TestWarmOnlyOpenClosesNoSessionOfTheOwner(t *testing.T) {
	svc, p := sessionService()
	svc.Sessions.Pool, svc.Sessions.MaxPerOwner = 2, 1
	p.Warm = 5
	alice := authenticatedContext("alice")
	held, err := svc.OpenSession(alice, ownerOpen("u1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.OpenSession(alice, warmOpen("u1")); !refusedNoWarm(err) {
		t.Fatalf("a warm-only open at the owner's cap = %v; want refused, capacity", err)
	}
	if _, err := svc.SessionRun(alice, callReq(held.Msg.GetSessionId(), "1")); err != nil {
		t.Fatalf("the owner's session after a warm-only open at the cap: %v; want it still open", err)
	}
	if len(p.Opened()) != 1 {
		t.Fatalf("the provider saw %d opens; want only the owner's first", len(p.Opened()))
	}
}
