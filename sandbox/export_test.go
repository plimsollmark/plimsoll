package sandbox

import (
	"context"
	"net/url"
)

// Unexported values the external tests (package sandbox_test) need.

// DockerInstance is the id d labels its containers with (io.plimsoll.instance), so a
// test lists its own containers and not another run's on the same docker host.
func DockerInstance(d *DockerSandbox) string { return d.instance() }

// DockerRemoveBudget is the longest a docker session's container removal takes, so
// the longest its Done can trail its end (sessiontest.Config.Teardown).
const DockerRemoveBudget = dockerRemoveBudget

// HeavyDockerTest admits one of the docker suite's heaviest tests (heavyDockerTest).
var HeavyDockerTest = heavyDockerTest

// DockerPoolReady names the pool members of d ready to be handed over now.
func DockerPoolReady(d *DockerSandbox) []string { return d.pool.Load().Members() }

// DockerSessionContainer names a docker session's container, so a test finds its own
// without listing every session container on the host (which a parallel test's would join).
func DockerSessionContainer(s Session) string { return s.(*dockerSession).name }

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

// E2BLive and DockerCloudLive are the live suites' providers, skipping unless their
// make target opted in to spend (e2bClient, dockerCloudLive).
var (
	E2BLive         = e2bClient
	DockerCloudLive = dockerCloudLive
)
