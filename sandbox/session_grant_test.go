package sandbox

import (
	"errors"
	"testing"
)

// A session refuses a granted call, before anything runs, unless the grant allows
// sessions; a call without a grant passes.
func TestCheckSessionGrant(t *testing.T) {
	if err := CheckSessionGrant(nil); err != nil {
		t.Fatalf("no grant: %v", err)
	}
	if err := CheckSessionGrant(&HostAPIGrant{AllowInSessions: true}); err != nil {
		t.Fatalf("a grant that allows sessions: %v", err)
	}
	err := CheckSessionGrant(&HostAPIGrant{})
	reason, ok := NotDispatchedReason(err)
	if !errors.Is(err, ErrGrantNotForSessions) || !ok || reason != RefusalPermission {
		t.Fatalf("a grant that does not allow sessions: %v (reason %v, marked %v)", err, reason, ok)
	}
}
