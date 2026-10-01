package sessionkit

import "testing"

// The launcher's identity line: gVisor can report a negative start time for a
// process started right after its sandbox booted (measured 2026-10-01), which a
// first version of the pattern refused, failing one Python launch in thirty.
func TestIdentityPattern(t *testing.T) {
	for _, ok := range []string{"16:1234:707974686f6e33", "16:-146:707974686f6e33", "1:0:00"} {
		if !identityPattern.MatchString(ok) {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", "16::70", "16:12:", "x:1:70", "16:1:70\n", "16:1:7G", "16:--1:70"} {
		if identityPattern.MatchString(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}
