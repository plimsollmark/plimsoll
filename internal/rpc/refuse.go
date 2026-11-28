package rpc

import (
	"errors"

	"connectrpc.com/connect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/internal/wireenum"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// refuse builds the Connect error for a refusal raised before any code was
// dispatched and attaches the NotDispatched detail saying so. Every handler-side
// refusal goes through it; an error built any other way carries no detail and
// reads as "may have run", which is the safe default for a site that forgets.
//
// A capacity refusal goes through refuseCapacity instead, which states the limit that
// shed it; TestEveryCapacityRefusalStatesItsLimit fails a refuse call with
// sandbox.RefusalCapacity.
func refuse(code connect.Code, reason sandbox.Refusal, err error) *connect.Error {
	return withNotDispatched(connect.NewError(code, err), reason, sandbox.CapacityUnstated)
}

// refuseCapacity is refuse for a capacity refusal (ResourceExhausted, reason capacity),
// stating which limit shed it, so a client can tell a limit a close of its own sessions
// frees from one no close cures without reading the text (finding release-115).
func refuseCapacity(limit sandbox.CapacityLimit, err error) *connect.Error {
	return withNotDispatched(connect.NewError(connect.CodeResourceExhausted, err), sandbox.RefusalCapacity, limit)
}

// withNotDispatched adds the mark, and on a capacity refusal its limit (unspecified on
// every other reason).
func withNotDispatched(ce *connect.Error, reason sandbox.Refusal, limit sandbox.CapacityLimit) *connect.Error {
	nd := &plimsollv1.NotDispatched{Reason: wireenum.RefusalToWire(reason)}
	if reason == sandbox.RefusalCapacity {
		nd.Limit = wireenum.CapacityLimitToWire(limit)
	}
	detail, derr := connect.NewErrorDetail(nd)
	if derr == nil {
		ce.AddDetail(detail)
	}
	return ce
}

// notDispatchedOf reads the not-dispatched mark off an error the handler returns, as
// a client reads it: from the error detail, which refuse and mapSandboxErr both add.
// sandbox.NotDispatchedReason does not see a mark refuse made, since refuse marks
// only the wire.
func notDispatchedOf(err error) (plimsollv1.NotDispatchedReason, bool) {
	var ce *connect.Error
	if !errors.As(err, &ce) {
		return 0, false
	}
	for _, d := range ce.Details() {
		v, derr := d.Value()
		if derr != nil {
			continue
		}
		if nd, ok := v.(*plimsollv1.NotDispatched); ok {
			return nd.GetReason(), true
		}
	}
	return 0, false
}
