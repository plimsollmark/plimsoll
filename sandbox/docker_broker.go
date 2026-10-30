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

// hostAPIListen is the loopback address inside a granted run's container on which
// plimsoll's own forwarder (the runner's child for a project, the injected client's
// listener for a snippet) passes each TCP connection to the broker's socket, byte for
// byte, so a standard HTTP client in any language reaches the broker through an ordinary
// base URL. A --network none container has only the loopback interface, so the address
// is reachable from the container alone. HostAPIListenEnv tells the forwarder where to
// listen; a run without a grant sets neither variable and starts no forwarder.
const (
	hostAPIListen    = "127.0.0.1:8471"
	HostAPIListenEnv = "HOST_API_LISTEN"
)

// hostAPIListenAddr is the loopback address this provider's forwarders listen on:
// hostAPIListen unless a test set loopbackListen to one the guest cannot bind.
func (d *DockerSandbox) hostAPIListenAddr() string {
	if d.loopbackListen != "" {
		return d.loopbackListen
	}
	return hostAPIListen
}

// hostForwarderWrapperJS is the program a run with sdk_env starts in place of the bare
// guest command, for projects and snippets alike: node, with the forwarder listening on
// the address at argv[1] and passing each connection to the socket at argv[2], and the
// guest command as its child with this process's stdin, stdout and stderr (a project's
// plan comes in and its signed report goes out exactly as before; a snippet's code comes
// in on stdin for `node -`). The rest of argv is "--", the child's environment entries,
// "--", the child's command. With no entries the child inherits this process's
// environment (a project's runner: the control environment and its guard); with
// entries the child gets PATH, HOME and HOSTNAME from this process and the entries (a
// snippet: the image's environment and the grant's), and this process, plimsoll's own,
// never starts with the image's environment. It is delivered with the daemon in the
// container command, so the image needs no change; the runner's step loop is
// synchronous (spawnSync holds node's event loop), which is why the forwarder is not
// the runner itself. It prints nothing on success. The child starts once the listener is
// up; if listening fails the wrapper writes hostForwarderFailedMarker to stderr and
// exits hostForwarderFailedExit without starting it, so no guest code runs. A guest that
// kills the forwarder ends its own run.
const hostForwarderWrapperJS = `const net=require("node:net"),cp=require("node:child_process"),os=require("node:os");
const a=process.argv.slice(1),listen=a[0],sock=a[1],s1=a.indexOf("--",2),s2=a.indexOf("--",s1+1);
const entries=a.slice(s1+1,s2),child=a.slice(s2+1),at=listen.lastIndexOf(":");
let env=process.env;if(entries.length){env={PATH:process.env.PATH,HOME:process.env.HOME,HOSTNAME:process.env.HOSTNAME};
for(const e of entries){const i=e.indexOf("=");env[e.slice(0,i)]=e.slice(i+1)}}
const srv=net.createServer(g=>{const u=net.connect(sock);const end=()=>{g.destroy();u.destroy()};
g.on("error",end);u.on("error",end);g.on("close",end);u.on("close",end);g.pipe(u);u.pipe(g)});
srv.on("error",e=>{process.stderr.write("` + hostForwarderFailedMarker + ` "+listen+": "+(e&&e.code||e)+"\n");process.exit(` + "126" + `)});
srv.listen(+listen.slice(at+1),listen.slice(0,at),()=>{
const c=cp.spawn(child[0],child.slice(1),{stdio:"inherit",env});
c.on("error",()=>process.exit(1));
c.on("exit",(code,sig)=>process.exit(code??(sig?128+(os.constants.signals[sig]||0):1)));});`

// grantGuestEnv is the environment a granted docker run hands its guest processes: the
// socket, and for a grant that asks for the local address (sdk_env) the forwarder's
// address and the profile's sdk_env rendered for the loopback origin (a client
// library's base URL and placeholder key). A grant without sdk_env gets the socket
// alone: no forwarder listens and no IPv4 socket is needed, so the run keeps the
// default seccomp profile.
func (d *DockerSandbox) grantGuestEnv(grant *HostAPIGrant) []string {
	env := []string{HostAPISocketEnv + "=" + containerSocketPath}
	if !grant.WantsLoopback() {
		return env
	}
	listen := d.hostAPIListenAddr()
	env = append(env, HostAPIListenEnv+"="+listen)
	return append(env, grant.sdkEnv("http://"+listen)...)
}

// hostForwarderFailedMarker is what the forwarder (the project wrapper, the snippet
// client's listener) writes to stderr before exiting hostForwarderFailedExit when it
// cannot listen: the run fails before any guest code starts, and the message says why.
const (
	hostForwarderFailedMarker = "plimsoll: the host API forwarder could not listen on"
	hostForwarderFailedExit   = 126
)

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
	core, err := brokerSessionForGrant(ctx, grant, timeout, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	b, err := startDockerBrokerWithCore(core)
	if err != nil {
		core.Close()
		return nil, nil, nil, err
	}
	return b, []string{"--mount", bindMount(b.sock, containerSocketPath, false)}, d.grantGuestEnv(grant), nil
}
