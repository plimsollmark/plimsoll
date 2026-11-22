package sandbox

import (
	"context"
	"maps"
	"net/url"
)

// Unexported values the external tests (package sandbox_test) need.

// DockerOOMRecorded and DockerOOMLikely are the words a docker session's end uses for a kill
// by the memory limit that docker recorded, and for the probable one under gVisor
// (dockerExitDetail).
const (
	DockerOOMRecorded = dockerOOMRecorded
	DockerOOMLikely   = dockerOOMLikely
)

// DockerInstance is the id d labels its containers with (io.plimsoll.instance), so a
// test lists its own containers and not another run's on the same docker host.
func DockerInstance(d *DockerSandbox) string { return d.instance() }

// DrainAtExit has TestMain drain d after every test has run, and returns it (drainAtExit):
// the external tests' docker sandboxes are drained as testDocker's are.
var DrainAtExit = drainAtExit

// DockerRemoveBudget is the longest a docker session's container removal takes, so
// the longest its Done can trail its end (sessiontest.Config.Teardown).
const DockerRemoveBudget = dockerRemoveBudget

// DockerProjectRunner is the project runner's command line d starts (runnerCommand),
// so a test that looks for the runner, or a call that starts it, keys on the runner
// plimsoll starts and not on a file name a replacement runner would not have (review
// finding rust-native-helper-10).
func DockerProjectRunner(d *DockerSandbox) []string { return d.runnerCommand() }

// HeavyDockerTest admits one of the docker suite's heaviest tests (heavyDockerTest).
var HeavyDockerTest = heavyDockerTest

// HeavyDockerPlace admits a test that is heavy for a part of its run, and returns the
// place's release (heavyDockerPlace).
var HeavyDockerPlace = heavyDockerPlace

// DockerPoolReady names the pool members of d ready to be handed over now.
func DockerPoolReady(d *DockerSandbox) []string { return d.pool.Load().Members() }

// DockerSessionContainer names a docker session's container, so a test finds its own
// without listing every session container on the host (which a parallel test's would join).
func DockerSessionContainer(s Session) string { return s.(*dockerSession).name }

// E2BTeardown is the longest E2B's delete of a sandbox takes, retries included.
const E2BTeardown = meteredTeardown

// E2BSessionSandbox is the ID of an E2B session's sandbox.
func E2BSessionSandbox(s Session) string { return s.(*e2bSession).machine().id }

// E2BSessionRoot runs argv as root in an E2B session's sandbox, in /, straight through
// envd: a test's stand-in for what an operator's template would carry. It returns the
// output and the exit code. It takes the session's turn for as long as argv runs, as a
// call does: the sweep after a call runs off the caller's path and ends every process
// that is not of the untouched machine, so a root command started just after a call
// returned was killed mid-run when it took longer than a moment (ldconfig on a glibc
// machine, in the first live run of the roads check, 2026-11-20).
func E2BSessionRoot(ctx context.Context, s Session, argv ...string) (stdout, stderr string, exit int, err error) {
	es := s.(*e2bSession)
	release, err := es.life.Hold(ctx)
	if err != nil {
		return "", "", -1, err
	}
	defer release()
	out, err := es.e.envdRun(ctx, es.machine(), envdProcess{user: e2bRootUser, cmd: argv[0], args: argv[1:], cwd: e2bControlDir}, 1<<20, 1<<16)
	return out.stdout, out.stderr, out.exitCode, err
}

// E2BSmokeNodes is what e's last startup check kept of the template's two nodes: the
// version of the steps' node, the version of the node a session's own programs use ("" when
// the closed PATH holds none), and whether the check could tell about the second at all.
func E2BSmokeNodes(e *E2B) (step, session string, sessionRead bool) {
	n := e.smokeSessionNode()
	return e.smokeStepNode(), n.version, n.read
}

// E2BSessionBins is each program an E2B session's open pinned, by the path it found.
func E2BSessionBins(s Session) map[string]string { return maps.Clone(s.(*e2bSession).bins) }

// E2BSessionUsrLocal is what an E2B session's open reported of closing /usr/local: the
// files and folders the session's user was checked against, how many lost a write
// permission, and the milliseconds it took.
func E2BSessionUsrLocal(s Session) struct {
	Entries, Changed int
	MS               float64
} {
	u := s.(*e2bSession).usrLocal
	return struct {
		Entries, Changed int
		MS               float64
	}{u.Entries, u.Changed, u.MS}
}

// E2BSessionGuestUID is the uid an E2B session's code runs as.
func E2BSessionGuestUID(s Session) int { return s.(*e2bSession).uid }

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
