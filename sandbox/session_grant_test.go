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
	// The local address for standard client libraries (sdk_env) is not served in a
	// session, whatever allow_in_sessions says: refused as unsupported, not half-served.
	err = CheckSessionGrant(&HostAPIGrant{AllowInSessions: true, SDKEnv: map[string]string{"OPENAI_BASE_URL": "{origin}/v1"}})
	reason, ok = NotDispatchedReason(err)
	if !errors.Is(err, ErrUnsupported) || !ok || reason != RefusalUnsupported {
		t.Fatalf("a grant with sdk_env in a session: %v (reason %v, marked %v)", err, reason, ok)
	}
}
