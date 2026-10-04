package sandbox

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/net/netutil"
)

// containerSocketPath is where the broker socket is mounted inside the container.
const containerSocketPath = "/run/host-api.sock"

// dockerBroker is the Unix-socket transport adapter for one provider-neutral
// brokerSession. The container stays on --network none and the socket contains no
// credential; the shared Go core authorizes every raw target and injects the token.
type dockerBroker struct {
	*unixBroker
	core *brokerSession
}

// unixBroker is a host-API broker served on a Unix socket in a fresh private directory,
// which a container mounts: a run's broker (dockerBroker) and a session's
// (dockerSessionBroker) differ only in which core answers a request. The socket is
// world-writable because the container runs as another uid, so the directory is what
// keeps other host users out; at most 32 connections are served at once.
type unixBroker struct {
	dir      string
	sock     string
	listener net.Listener
	srv      *http.Server
}

// startUnixBroker serves current's core (nil answers 503) on host-api.sock in a new
// private directory named with prefix, which reapDeadHostDirs knows.
func startUnixBroker(prefix string, current func() *brokerSession) (*unixBroker, error) {
	dir, err := os.MkdirTemp("", prefix)
	if err != nil {
		return nil, err
	}
	sock := filepath.Join(dir, "host-api.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	if err := os.Chmod(sock, 0o666); err != nil { // the container runs as the guest uid
		_ = l.Close()
		_ = os.RemoveAll(dir)
		return nil, err
	}
	b := &unixBroker{dir: dir, sock: sock, srv: newBrokerServerFor(current), listener: netutil.LimitListener(l, 32)}
	go func() { _ = b.srv.Serve(b.listener) }()
	return b, nil
}

// close stops serving and removes the socket's directory.
func (b *unixBroker) close() {
	_ = b.listener.Close()
	_ = b.srv.Close()
	_ = os.RemoveAll(b.dir)
}

// traceSnapshot returns the run's bounded, metadata-only CallTrace, or nil when the
// run brokered no calls. Nil-safe so RunJavaScript can call it unconditionally
// (a run with no grant has a nil broker).
func (b *dockerBroker) traceSnapshot() *CallTrace {
	if b == nil {
		return nil
	}
	return b.core.traceSnapshot()
}

// finalTrace ends the run's authority and returns its complete trace: the run is
// over, so a call in flight is cut off upstream and waited for.
func (b *dockerBroker) finalTrace() *CallTrace {
	if b == nil {
		return nil
	}
	b.core.End()
	return b.core.traceSnapshot()
}

// Close stops the broker and removes its socket dir. Safe to call on a nil broker.
func (b *dockerBroker) Close() {
	if b == nil {
		return
	}
	b.unixBroker.close()
	b.core.Close()
}

// startDockerBroker is the test seam that binds a known token to a grant.
// Production uses brokerSessionForGrant, so the minted token never leaves the
// provider-neutral lifecycle.
func startDockerBroker(grant *HostAPIGrant, token string) (*dockerBroker, error) {
	core, err := newBrokerSession(grant, token, nil)
	if err != nil {
		return nil, err
	}
	b, err := startDockerBrokerWithCore(core)
	if err != nil {
		core.Close()
	}
	return b, err
}

func startDockerBrokerWithCore(core *brokerSession) (*dockerBroker, error) {
	if core == nil {
		return nil, errors.New("docker broker: core is nil")
	}
	u, err := startUnixBroker("crsbx-broker", func() *brokerSession { return core })
	if err != nil {
		return nil, err
	}
	return &dockerBroker{unixBroker: u, core: core}, nil
}

// brokerForRun starts a per-run broker when the run carries a host-API grant and
// returns the docker flags that mount its socket and the variable that tells the
// guest where it is (guestArgv hands it on). The credential is minted here and
// injected by the broker, never put in the guest's environment. Returns a nil broker
// (and nil flags and variables) when there is no grant. The caller must defer
// broker.Close().
func (d *DockerSandbox) brokerForRun(ctx context.Context, grant *HostAPIGrant, timeout time.Duration) (*dockerBroker, []string, []string, error) {
	if grant == nil {
		return nil, nil, nil, nil
	}
	core, err := brokerSessionForGrant(ctx, grant, timeout)
	if err != nil {
		return nil, nil, nil, err
	}
	b, err := startDockerBrokerWithCore(core)
	if err != nil {
		core.Close()
		return nil, nil, nil, err
	}
	return b, []string{"-v", b.sock + ":" + containerSocketPath}, []string{"HOST_API_SOCKET=" + containerSocketPath}, nil
}
