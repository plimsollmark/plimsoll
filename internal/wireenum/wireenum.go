// Package wireenum is the one table between package sandbox's typed values and their
// protocol enums: project outcomes, session ends, refusal reasons. The daemon writes
// through it and the Go client reads through it, so the two directions cannot disagree,
// and its test fails when the protocol gains a value the table lacks. The two sides once
// kept a switch each (review D4, 2026-10-23): a session end missing from the daemon's
// went out as unspecified, which clients read as a session still open.
package wireenum

import (
	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/sandbox"
)

var outcomes = []struct {
	s sandbox.ProjectOutcome
	w plimsollv1.ProjectOutcome
}{
	{sandbox.ProjectOutcomeCompleted, plimsollv1.ProjectOutcome_PROJECT_OUTCOME_COMPLETED},
	{sandbox.ProjectOutcomeSetupFailed, plimsollv1.ProjectOutcome_PROJECT_OUTCOME_SETUP_FAILED},
	{sandbox.ProjectOutcomeTimedOut, plimsollv1.ProjectOutcome_PROJECT_OUTCOME_TIMED_OUT},
	{sandbox.ProjectOutcomeProtocolError, plimsollv1.ProjectOutcome_PROJECT_OUTCOME_PROTOCOL_ERROR},
	{sandbox.ProjectOutcomeRunnerFailed, plimsollv1.ProjectOutcome_PROJECT_OUTCOME_RUNNER_FAILED},
}

var sessionEnds = []struct {
	s sandbox.SessionEnd
	w plimsollv1.SessionEnd
}{
	{sandbox.SessionClosed, plimsollv1.SessionEnd_SESSION_END_CLOSED},
	{sandbox.SessionExpired, plimsollv1.SessionEnd_SESSION_END_EXPIRED},
	{sandbox.SessionDiskExceeded, plimsollv1.SessionEnd_SESSION_END_DISK_EXCEEDED},
	{sandbox.SessionMainProcessEnded, plimsollv1.SessionEnd_SESSION_END_MAIN_PROCESS_ENDED},
	{sandbox.SessionBoundaryFailed, plimsollv1.SessionEnd_SESSION_END_BOUNDARY_FAILED},
	{sandbox.SessionSandboxChanged, plimsollv1.SessionEnd_SESSION_END_SANDBOX_CHANGED},
	{sandbox.SessionShutdown, plimsollv1.SessionEnd_SESSION_END_SHUTDOWN},
	{sandbox.SessionReplaced, plimsollv1.SessionEnd_SESSION_END_REPLACED},
	{sandbox.SessionNotFound, plimsollv1.SessionEnd_SESSION_END_NOT_FOUND},
	{sandbox.SessionUnclaimed, plimsollv1.SessionEnd_SESSION_END_UNCLAIMED},
}

var refusals = []struct {
	s sandbox.Refusal
	w plimsollv1.NotDispatchedReason
}{
	{sandbox.RefusalRequest, plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_REQUEST},
	{sandbox.RefusalPermission, plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_PERMISSION},
	{sandbox.RefusalProtocol, plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_PROTOCOL},
	{sandbox.RefusalUnsupported, plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_UNSUPPORTED},
	{sandbox.RefusalIsolation, plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_ISOLATION},
	{sandbox.RefusalCapacity, plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_CAPACITY},
	{sandbox.RefusalEnvironment, plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_ENVIRONMENT},
}

// OutcomeToWire is o's enum; unspecified for one the protocol has no value for.
func OutcomeToWire(o sandbox.ProjectOutcome) plimsollv1.ProjectOutcome {
	for _, e := range outcomes {
		if e.s == o {
			return e.w
		}
	}
	return plimsollv1.ProjectOutcome_PROJECT_OUTCOME_UNSPECIFIED
}

// OutcomeFromWire is w's outcome; Unspecified for a value this code does not know,
// which strict consumers treat as a protocol mismatch, never guessed at.
func OutcomeFromWire(w plimsollv1.ProjectOutcome) sandbox.ProjectOutcome {
	for _, e := range outcomes {
		if e.w == w {
			return e.s
		}
	}
	return sandbox.ProjectOutcomeUnspecified
}

// SessionEndToWire is e's enum; unspecified (still open) for SessionOpen.
func SessionEndToWire(end sandbox.SessionEnd) plimsollv1.SessionEnd {
	for _, e := range sessionEnds {
		if e.s == end {
			return e.w
		}
	}
	return plimsollv1.SessionEnd_SESSION_END_UNSPECIFIED
}

// SessionEndFromWire is w's end: SessionOpen for unspecified, and SessionUnknown for a
// newer daemon's end, which is an end all the same, never read as still open.
func SessionEndFromWire(w plimsollv1.SessionEnd) sandbox.SessionEnd {
	if w == plimsollv1.SessionEnd_SESSION_END_UNSPECIFIED {
		return sandbox.SessionOpen
	}
	for _, e := range sessionEnds {
		if e.w == w {
			return e.s
		}
	}
	return sandbox.SessionUnknown
}

// RefusalToWire is r's enum; unspecified for one the protocol has no value for.
func RefusalToWire(r sandbox.Refusal) plimsollv1.NotDispatchedReason {
	for _, e := range refusals {
		if e.s == r {
			return e.w
		}
	}
	return plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_UNSPECIFIED
}

// RefusalFromWire is w's reason; RefusalUnknown for a value this code does not know.
func RefusalFromWire(w plimsollv1.NotDispatchedReason) sandbox.Refusal {
	for _, e := range refusals {
		if e.w == w {
			return e.s
		}
	}
	return sandbox.RefusalUnknown
}
