package sandbox

import "errors"

// Refusal says why a run was refused before any code executed, in the terms a
// caller (or a router choosing among backends) acts on: whether another backend
// could take the same request, or whether the request itself is the problem.
type Refusal int

const (
	// RefusalUnknown is never attached; it is the zero value NotDispatchedReason
	// returns alongside false.
	RefusalUnknown Refusal = iota
	// RefusalRequest: the request is malformed or out of bounds. Every backend
	// would refuse it the same way; do not reselect.
	RefusalRequest
	// RefusalPermission: authentication, scope, or a grant profile's caller ACL; or
	// the run's grant could not be issued (an invalid grant, a failed mint). Do not
	// reselect.
	RefusalPermission
	// RefusalProtocol: the backend serves another wire protocol number.
	RefusalProtocol
	// RefusalUnsupported: this backend cannot perform the operation (including a
	// disabled provider). Another backend may.
	RefusalUnsupported
	// RefusalIsolation: the backend's current evidence is below the request's
	// isolation floor. Another backend may meet it.
	RefusalIsolation
	// RefusalCapacity: shed by admission, a rate limit, or a spent daily allowance on
	// a provider billed by the second (which the refusal's text says lasts until
	// 00:00 UTC). Retry later or elsewhere.
	RefusalCapacity
	// RefusalEnvironment: the selected software cannot meet the caller's rule
	// (another backend may have an approved image), or the sandbox a call was to run
	// in could not be shown to be the one stated: an interpreter that could not start,
	// a session's read-back that failed.
	RefusalEnvironment
)

var refusalNames = [...]string{
	RefusalUnknown:     "unknown",
	RefusalRequest:     "request",
	RefusalPermission:  "permission",
	RefusalProtocol:    "protocol",
	RefusalUnsupported: "unsupported",
	RefusalIsolation:   "isolation",
	RefusalCapacity:    "capacity",
	RefusalEnvironment: "environment",
}

func (r Refusal) String() string {
	if r < 0 || int(r) >= len(refusalNames) {
		return refusalNames[RefusalUnknown]
	}
	return refusalNames[r]
}

// NotDispatchedError marks an error returned before any code was dispatched:
// nothing executed, so retrying or sending the request elsewhere cannot run it
// twice. Only code that provably ran nothing attaches it. Its absence means the
// run MAY have executed, which is why an unmarked error is never a safe
// automatic-retry signal. Unwrap keeps errors.Is working on the underlying
// sentinel (ErrInvalidRequest, ErrUnsupported, ...).
type NotDispatchedError struct {
	Reason Refusal
	Err    error
}

func (e *NotDispatchedError) Error() string { return e.Err.Error() }
func (e *NotDispatchedError) Unwrap() error { return e.Err }

// NotDispatched marks err as a refusal that ran nothing. A nil err stays nil, so a
// validation result can be passed through unconditionally.
func NotDispatched(reason Refusal, err error) error {
	if err == nil {
		return nil
	}
	return &NotDispatchedError{Reason: reason, Err: err}
}

// NotDispatchedReason reports whether err is a marked pre-dispatch refusal and
// why. false means execution may have occurred.
func NotDispatchedReason(err error) (Refusal, bool) {
	var nd *NotDispatchedError
	if errors.As(err, &nd) {
		return nd.Reason, true
	}
	return RefusalUnknown, false
}

// refused marks a pre-dispatch refusal whose reason follows from the sentinel it
// wraps. Call it only where no code has run. An error wrapping none of the
// pre-dispatch sentinels is returned unmarked, so the conservative reading ("may
// have run") is kept for anything this function does not recognize.
func refused(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrInvalidRequest):
		return NotDispatched(RefusalRequest, err)
	case errors.Is(err, ErrUnsupported), errors.Is(err, ErrDisabled):
		return NotDispatched(RefusalUnsupported, err)
	case errors.Is(err, ErrInsufficientIsolation):
		return NotDispatched(RefusalIsolation, err)
	case errors.Is(err, ErrAtCapacity):
		return NotDispatched(RefusalCapacity, err)
	case errors.Is(err, ErrSoftwareMismatch):
		return NotDispatched(RefusalEnvironment, err)
	default:
		return err
	}
}
