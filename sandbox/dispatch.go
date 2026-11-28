package sandbox

import (
	"context"
	"errors"
	"fmt"
)

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
	// 00:00 UTC). Retry later or elsewhere. Its CapacityLimit says which limit.
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

// CapacityLimit says which limit shed a RefusalCapacity refusal, so a caller can tell a
// limit that closing one of its own sessions frees from one no close cures, without
// reading the refusal's text (finding release-115: the rate limit and full session places
// were one refusal, and a client that closed a session for each lost one per retry).
type CapacityLimit int

const (
	// CapacityUnstated: not a capacity refusal, or one whose limit was not stated (a
	// daemon before the limit was stated, or a provider's refusal outside plimsolld).
	CapacityUnstated CapacityLimit = iota
	// CapacitySessions: the daemon's session places are all taken.
	CapacitySessions
	// CapacityCallerSessions: the caller holds as many sessions as one caller may.
	CapacityCallerSessions
	// CapacityOwnerSessions: the open's owner is at its cap and none of its sessions
	// could be closed for it (each running a call, or a warm-only open).
	CapacityOwnerSessions
	// CapacityRuns: the daemon's runs in flight are at their cap; a running session
	// holds one.
	CapacityRuns
	// CapacityCallerRuns: the caller's runs in flight are at their cap; a running
	// session holds one.
	CapacityCallerRuns
	// CapacityRate: the caller's runs per minute are spent; only time gives them back.
	CapacityRate
	// CapacityPaidSeconds: today's paid seconds are spent, the caller's or the daemon's.
	CapacityPaidSeconds
	// CapacityQueue: a short line is full (requests being decoded, calls waiting for the
	// ship scan, a call already waiting for its session's turn).
	CapacityQueue
	// CapacityProvider: the provider shed it by its own capacity (a quota, a warm pool
	// with none waiting, a provider shutting down).
	CapacityProvider
	// CapacityDeadline: the call's own context ended (its deadline passed, or its caller
	// canceled it) before any of it was sent: while it waited for its session's turn or
	// for a place, or while the sandbox, its grant or the provider's checks were made
	// ready for it. No limit of the daemon's or the provider's was met. Set only by
	// RefuseDeadline.
	CapacityDeadline
)

var capacityLimitNames = [...]string{
	CapacityUnstated:       "unknown",
	CapacitySessions:       "sessions",
	CapacityCallerSessions: "caller_sessions",
	CapacityOwnerSessions:  "owner_sessions",
	CapacityRuns:           "runs",
	CapacityCallerRuns:     "caller_runs",
	CapacityRate:           "rate",
	CapacityPaidSeconds:    "paid_seconds",
	CapacityQueue:          "queue",
	CapacityProvider:       "provider",
	CapacityDeadline:       "deadline",
}

func (l CapacityLimit) String() string {
	if l < 0 || int(l) >= len(capacityLimitNames) {
		return capacityLimitNames[CapacityUnstated]
	}
	return capacityLimitNames[l]
}

// AtCapacity marks err as a capacity refusal that ran nothing, shed by limit.
func AtCapacity(limit CapacityLimit, err error) error {
	if err == nil {
		return nil
	}
	return &NotDispatchedError{Reason: RefusalCapacity, Limit: limit, Err: err}
}

// RefuseDeadline is the refusal of a call none of whose work was sent because its own
// context, ctx, ended first (its deadline passed, or its caller canceled it): marked not
// dispatched, reason capacity, limit CapacityDeadline (finding release-122: these were
// labeled queue on some paths and provider on others). err says what was cut, nil for the
// context's error alone; it is wrapped with ctx's error when it carries no context error,
// so the daemon answers the call deadline_exceeded or canceled, as its own timeout. A ctx
// that has not ended (a deadline that has passed on a timer not yet fired) reads as
// DeadlineExceeded. An err already marked not dispatched (a session's end) keeps its mark.
//
// Every refusal for the caller's own deadline goes through it:
// TestEveryCapacityRefusalStatesItsLimit (internal/rpc) fails a capacity refusal built
// anywhere in the module without a stated limit, and the deadline limit set anywhere else.
func RefuseDeadline(ctx context.Context, err error) error {
	if _, marked := NotDispatchedReason(err); marked {
		return err
	}
	cause := ctx.Err()
	if cause == nil {
		cause = context.DeadlineExceeded
	}
	switch {
	case err == nil:
		err = cause
	case !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled):
		err = fmt.Errorf("%w: %w", cause, err)
	}
	return AtCapacity(CapacityDeadline, err)
}

// CapacityLimitOf is the limit a marked capacity refusal states; CapacityUnstated for
// any other error.
func CapacityLimitOf(err error) CapacityLimit {
	var nd *NotDispatchedError
	if errors.As(err, &nd) && nd.Reason == RefusalCapacity {
		return nd.Limit
	}
	return CapacityUnstated
}

// NotDispatchedError marks an error returned before any code was dispatched:
// nothing executed, so retrying or sending the request elsewhere cannot run it
// twice. Only code that provably ran nothing attaches it. Its absence means the
// run MAY have executed, which is why an unmarked error is never a safe
// automatic-retry signal. Unwrap keeps errors.Is working on the underlying
// sentinel (ErrInvalidRequest, ErrUnsupported, ...).
type NotDispatchedError struct {
	Reason Refusal
	// Limit is the limit a RefusalCapacity refusal met; CapacityUnstated otherwise.
	Limit CapacityLimit
	Err   error
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
// have run") is kept for anything this function does not recognize. A capacity refusal
// is not among them: it states its limit where it is raised (AtCapacity, RefuseDeadline).
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
	case errors.Is(err, ErrSoftwareMismatch):
		return NotDispatched(RefusalEnvironment, err)
	default:
		return err
	}
}
