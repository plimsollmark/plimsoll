// Package egress reads the outcome of a connection a sandbox's boundary test tried to
// make, one rule for every provider whose test connects out from inside the sandbox
// (agentsandbox, openshell). Three providers once read the same outcomes three ways: one
// counted only an established connection as open, so a refusal or a TLS failure, both
// answers from outside, passed as closed (review, 2026-10-23).
package egress

import "slices"

// Closed reports whether outcome, the error code a connection attempt ended in ("open"
// when it connected, "timeout" when nothing answered in time), shows the attempt did not
// leave the sandbox: nothing answered, the sandbox has no route or address for it, its
// own kernel refused it before it left, or the name never resolved. Every other outcome
// means something outside answered and counts as egress: an open connection, a refusal
// or reset (a destination, or a filter past the boundary, answered), a TLS failure (a
// proxy answered), an error this list does not name.
func Closed(outcome string) bool {
	switch outcome {
	case "timeout", "UND_ERR_CONNECT_TIMEOUT", // nothing answered
		"EHOSTUNREACH", "ENETUNREACH", "ENETDOWN", "EADDRNOTAVAIL", // no route, or no address of that family
		"EACCES", "EPERM", // refused before it left
		"ENOTFOUND", "EAI_AGAIN": // the name never resolved
		return true
	}
	return false
}

// Left lists, sorted, the attempts in outcomes (target to outcome) that left the sandbox.
func Left(outcomes map[string]string) []string {
	var left []string
	for target, outcome := range outcomes {
		if !Closed(outcome) {
			left = append(left, target+" "+outcome)
		}
	}
	slices.Sort(left)
	return left
}
