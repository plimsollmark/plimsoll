package rpc

import (
	"errors"

	"connectrpc.com/connect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// refuse builds the Connect error for a refusal raised before any code was
// dispatched and attaches the NotDispatched detail saying so. Every handler-side
// refusal goes through it; an error built any other way carries no detail and
// reads as "may have run", which is the safe default for a site that forgets.
func refuse(code connect.Code, reason sandbox.Refusal, err error) *connect.Error {
	return withNotDispatched(connect.NewError(code, err), reason)
}

func withNotDispatched(ce *connect.Error, reason sandbox.Refusal) *connect.Error {
	detail, derr := connect.NewErrorDetail(&plimsollv1.NotDispatched{Reason: reasonWire(reason)})
	if derr == nil {
		ce.AddDetail(detail)
	}
	return ce
}

func reasonWire(r sandbox.Refusal) plimsollv1.NotDispatchedReason {
	switch r {
	case sandbox.RefusalRequest:
		return plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_REQUEST
	case sandbox.RefusalPermission:
		return plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_PERMISSION
	case sandbox.RefusalProtocol:
		return plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_PROTOCOL
	case sandbox.RefusalUnsupported:
		return plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_UNSUPPORTED
	case sandbox.RefusalIsolation:
		return plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_ISOLATION
	case sandbox.RefusalCapacity:
		return plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_CAPACITY
	case sandbox.RefusalEnvironment:
		return plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_ENVIRONMENT
	default:
		return plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_UNSPECIFIED
	}
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
