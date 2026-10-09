package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"time"
)

// Grants in an E2B session. The guest reaches the guard only through E2B's proxy, which
// gives its requests the guard credential outside the guest. E2B_SESSION_GRANTS chooses
// how the credential gets there, once, at startup:
//
//   - "" (the default): no way; a granted session call is refused, not dispatched,
//     reason unsupported.
//   - "session": the sandbox is created with the guard's rule and one credential for
//     the session's life, whose slot serves the grant of the call in progress, as
//     docker's session broker socket does. Between calls the guard is reachable and
//     refuses.
//   - "call": the sandbox is created deny-all; a granted call puts the guard's rule on
//     it, with a fresh credential, through E2B's network update, and takes it off after.
//     Between calls the guard is unreachable; a granted call costs two more requests to
//     E2B's control plane.
//
// Both pass against the live service (make e2b-guard-live, 2026-10-08): E2B's read-back
// shows the rule's header, its update takes rules, and the rule survives a pause.
const (
	E2BSessionGrantsSession = "session"
	E2BSessionGrantsCall    = "call"
)

func validateE2BSessionGrants(v, guardURL string) error {
	switch {
	case v != "" && v != E2BSessionGrantsSession && v != E2BSessionGrantsCall:
		return fmt.Errorf("E2B_SESSION_GRANTS must be %q or %q, or unset", E2BSessionGrantsSession, E2BSessionGrantsCall)
	case v != "" && guardURL == "":
		return fmt.Errorf("E2B_SESSION_GRANTS needs E2B_GUARD_URL: a granted session call reaches its grant through the guard")
	}
	return nil
}

// e2bGrantChannel is how a session call's grant reaches the guard.
type e2bGrantChannel interface {
	// guard is the rule the session's sandbox is created with, nil for none.
	guard() *e2bGuardConfig
	// check refuses a grant the channel cannot serve, before the call takes its turn
	// (which can resume a suspended sandbox, billed).
	check(grant *HostAPIGrant) error
	// lend serves grant for one call of s; the release ends it and is idempotent.
	lend(ctx context.Context, s *e2bSession, grant *HostAPIGrant, timeout time.Duration) (*brokerSession, func(), error)
	// close ends the channel with its session.
	close()
}

// grantChannel is a new session's channel, by E2B_SESSION_GRANTS.
func (e *E2B) grantChannel() (e2bGrantChannel, error) {
	endpoint := e.guardConfig()
	switch {
	case endpoint == nil || e.SessionGrants == "":
		return e2bNoGrants{}, nil
	case e.SessionGrants == E2BSessionGrantsCall:
		return e2bCallRule{endpoint: endpoint}, nil
	}
	token, slot, unregister, err := e.guards.register()
	if err != nil {
		return nil, err
	}
	return &e2bSessionRule{cfg: &e2bGuardConfig{Endpoint: endpoint, Token: token}, slot: slot, unregister: unregister}, nil
}

// e2bNoGrants refuses every granted call.
type e2bNoGrants struct{}

func (e2bNoGrants) guard() *e2bGuardConfig { return nil }
func (e2bNoGrants) close()                 {}
func (e2bNoGrants) check(grant *HostAPIGrant) error {
	if grant == nil {
		return nil
	}
	return refused(fmt.Errorf("%w: e2b session grants need E2B_GUARD_URL and E2B_SESSION_GRANTS", ErrUnsupported))
}
func (n e2bNoGrants) lend(_ context.Context, _ *e2bSession, grant *HostAPIGrant, _ time.Duration) (*brokerSession, func(), error) {
	return nil, nil, n.check(grant)
}

// e2bSessionRule is E2B_SESSION_GRANTS=session.
type e2bSessionRule struct {
	cfg        *e2bGuardConfig
	slot       *grantSlot
	unregister func()
}

func (r *e2bSessionRule) guard() *e2bGuardConfig    { return r.cfg }
func (r *e2bSessionRule) close()                    { r.unregister() }
func (r *e2bSessionRule) check(*HostAPIGrant) error { return nil }
func (r *e2bSessionRule) lend(ctx context.Context, s *e2bSession, grant *HostAPIGrant, timeout time.Duration) (*brokerSession, func(), error) {
	core, err := brokerSessionForGrant(ctx, grant, timeout, s.routes)
	if err != nil {
		return nil, nil, err
	}
	return core, r.slot.lend(core), nil
}

// e2bCallRule is E2B_SESSION_GRANTS=call.
type e2bCallRule struct{ endpoint *guardEndpoint }

func (e2bCallRule) guard() *e2bGuardConfig    { return nil }
func (e2bCallRule) close()                    {}
func (e2bCallRule) check(*HostAPIGrant) error { return nil }

// lend registers a fresh credential for the call and puts the guard's rule carrying it
// on the sandbox. The release unregisters the credential first, so the guard refuses it
// at once, then takes the rule off. A rule left on, by a failed update either way, is
// found by the next call's read-back, which ends the session: its network is no longer
// the one verified at open.
func (r e2bCallRule) lend(ctx context.Context, s *e2bSession, grant *HostAPIGrant, timeout time.Duration) (*brokerSession, func(), error) {
	token, core, cleanup, err := s.e.guards.open(ctx, grant, timeout, s.routes)
	if err != nil {
		return nil, nil, err
	}
	id := s.machine().id
	if err := s.e.setNetwork(ctx, id, &e2bGuardConfig{Endpoint: r.endpoint, Token: token}); err != nil {
		cleanup()
		return nil, nil, NotDispatched(RefusalEnvironment, err)
	}
	var once sync.Once
	release := func() {
		once.Do(func() {
			cleanup()
			ctx, cancel := context.WithTimeout(context.Background(), e2bNetworkBudget)
			defer cancel()
			_ = s.e.setNetwork(ctx, id, nil)
		})
	}
	return core, release, nil
}

// e2bNetworkBudget bounds one network update.
const e2bNetworkBudget = 15 * time.Second

// setNetwork replaces a running sandbox's egress (PUT /sandboxes/{id}/network): the
// guard's rule for cfg, plain deny-all for nil. E2B replaces rather than merges, so
// what the body omits is cleared.
func (e *E2B) setNetwork(ctx context.Context, id string, cfg *e2bGuardConfig) error {
	code, body, err := e.control(ctx, http.MethodPut, "/sandboxes/"+id+"/network", guardNetwork(cfg))
	if err != nil {
		return fmt.Errorf("e2b update network: %w", err)
	}
	if code != http.StatusNoContent && code != http.StatusOK {
		return fmt.Errorf("e2b update network: HTTP %d: %s", code, truncateForError(body))
	}
	return nil
}

// matches reports whether n allows egress to the guard's host alone, with one rule
// there that sets the guard header to this credential and nothing else.
func (cfg *e2bGuardConfig) matches(n *e2bNetwork) bool {
	if !slices.Equal(n.AllowOut, []string{cfg.Endpoint.Host}) || len(n.Rules) != 1 {
		return false
	}
	var rules []struct {
		Transform struct {
			Headers map[string]string `json:"headers"`
		} `json:"transform"`
	}
	if json.Unmarshal(n.Rules[cfg.Endpoint.Host], &rules) != nil || len(rules) != 1 {
		return false
	}
	headers := rules[0].Transform.Headers
	return len(headers) == 1 && headers[EgressGuardHeader] == cfg.Token
}
