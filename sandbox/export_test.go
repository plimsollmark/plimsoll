package sandbox

import (
	"context"
	"net/url"
)

// Unexported values the external tests (package sandbox_test) need.

// DockerRemoveBudget is the longest a docker session's container removal takes, so
// the longest its Done can trail its end (sessiontest.Config.Teardown).
const DockerRemoveBudget = dockerRemoveBudget

// HeavyDockerTest admits one of the docker suite's heaviest tests (heavyDockerTest).
var HeavyDockerTest = heavyDockerTest

// E2BTeardown is the longest E2B's delete of a sandbox takes, retries included.
const E2BTeardown = meteredTeardown

// E2BSessionSandbox is the ID of an E2B session's sandbox.
func E2BSessionSandbox(s Session) string { return s.(*e2bSession).machine().id }

// E2BSessionSandboxes lists the session sandboxes e's key can see, running or paused,
// as ID to state: what ReconcileOrphans reads for its expiry rule.
func E2BSessionSandboxes(ctx context.Context, e *E2B) (map[string]string, error) {
	listed, err := e.listSandboxes(ctx, url.Values{"session": {"1"}})
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, sb := range listed {
		out[sb.id] = sb.state
	}
	return out, nil
}

// E2BOwnSandboxes lists every sandbox stamped with e's instance, running or paused, as
// ID to state: what a test that must leave nothing behind checks last.
func E2BOwnSandboxes(ctx context.Context, e *E2B) (map[string]string, error) {
	listed, err := e.listSandboxes(ctx, url.Values{"instance": {e.instance()}})
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, sb := range listed {
		out[sb.id] = sb.state
	}
	return out, nil
}
