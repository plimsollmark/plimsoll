// Command plimsoll-sandboxd-tls is the agent-sandbox image's entrypoint
// (docker/agentsandbox.Dockerfile): it puts TLS in front of sandboxd, the runtime daemon
// of Kubernetes agent-sandbox, which serves none (its v1.0.7 user guide: "sandboxd does
// not terminate TLS"). plimsolld sends sandboxd's bearer token, the guest's code, each
// project's plan with the runner's report key, and reads every result over this one
// connection, so without it all of that crosses the pod network in the clear
// (docs/agentsandbox.md, "The control channel").
//
// It takes sandboxd's arguments, refuses them unless sandboxd will listen on loopback
// alone (exactly one --listen-host=127.0.0.1 and one --grpc-port=9091, every argument in
// the --name=value form and a flag the pinned sandboxd takes), checks that the pod's own
// key is closed to every user but root, starts /usr/local/bin/sandboxd with them, waits
// for its gRPC port to accept, and then listens on :9090. Each connection must complete a
// TLS 1.3 handshake within 10 seconds and negotiate HTTP/2 by ALPN; only then is a
// connection to sandboxd opened, and the decrypted bytes are copied both ways unchanged
// (sandboxd's gRPC server accepts HTTP/2 with prior knowledge), each side ended in order
// so the last bytes arrive whole (pipe). It parses no HTTP. The certificate and key are
// read again at every handshake, so a certificate the issuer renewed takes effect in a
// pod already running.
//
// The pair is the pod's own: an issuer in the cluster signs a certificate for this pod
// alone, naming its UID, and the key is made on the node and mounted at
// /etc/plimsoll/sandboxd-tls, mode 0440 for owner root and group root (cert-manager's CSI
// driver, measured 2026-11-24). plimsolld checks the UID in the handshake, so this pod's
// key proves this pod and no other.
// It exits with sandboxd's status, forwarding SIGTERM and SIGINT to it.
//
// The standard library only: this process holds the TLS key and faces the pod network.
package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	// listenAddr is where plimsolld connects: the pod's address, port 9090, the port the
	// template's network policy admits plimsolld to.
	listenAddr = ":9090"
	// backendHost and backendPort are where sandboxd's gRPC server must listen: loopback,
	// so nothing outside the pod reaches it except through the TLS here.
	backendHost = "127.0.0.1"
	backendPort = "9091"
	// guardDir must be closed to every user but its owner (the image makes it root's,
	// mode 0700), so the guest cannot even reach the key volume mounted inside it, whose
	// own directory the driver makes 0550.
	guardDir = "/etc/plimsoll"
	certFile = "/etc/plimsoll/sandboxd-tls/tls.crt"
	keyFile  = "/etc/plimsoll/sandboxd-tls/tls.key"

	sandboxdPath = "/usr/local/bin/sandboxd"

	// handshakeTimeout bounds a connection that has not finished its handshake, as
	// sandboxd's own ReadHeaderTimeout (10 s) bounds a request's headers.
	handshakeTimeout = 10 * time.Second
	// backendWait bounds sandboxd's start: it binds its ports within milliseconds, and the
	// pod is not ready (nothing listens on :9090) until it has.
	backendWait = 60 * time.Second
	dialTimeout = 5 * time.Second
	// maxLogged bounds the lines failed handshakes can write to the container's log in one
	// logWindow, which the kubelet keeps on the node's disk; anyone in the pod can connect.
	// A window, not a lifetime: a guest's burst must not silence a real failure later.
	maxLogged = 16
	logWindow = time.Minute
)

// tokenDigest is sandboxd's --auth-token-sha256 value: a SHA-256 in lowercase hex.
var tokenDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

func main() {
	code, err := run(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "plimsoll-sandboxd-tls:", err)
	}
	os.Exit(code)
}

func run(args []string) (int, error) {
	if err := checkArgs(args); err != nil {
		return 2, err
	}
	keys := keyFiles{guard: guardDir, cert: certFile, key: keyFile, owner: 0, group: 0}
	if _, err := keys.load(); err != nil {
		return 1, err
	}
	// Orphans come to this process even where a runtime puts an init of its own first.
	_ = setChildSubreaper()
	cmd := exec.Command(sandboxdPath, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		return 1, fmt.Errorf("start sandboxd: %w", err)
	}
	var waitErr error
	exited := make(chan struct{})
	go func() { waitErr = statusErr(reap(cmd.Process.Pid, nil)); close(exited) }()
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		for s := range sigs {
			_ = cmd.Process.Signal(s)
		}
	}()
	stop := func(err error) (int, error) {
		_ = cmd.Process.Kill()
		<-exited
		return 1, err
	}
	backend := net.JoinHostPort(backendHost, backendPort)
	if err := waitFor(backend, backendWait, exited); err != nil {
		if isClosed(exited) {
			return exitCode(waitErr), fmt.Errorf("sandboxd exited before its port accepted: %v", waitErr)
		}
		return stop(err)
	}
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return stop(err)
	}
	logger := log.New(os.Stderr, "plimsoll-sandboxd-tls: ", log.LstdFlags)
	go serve(ln, keys.config(), backend, limitedLog(logger.Printf, time.Now))
	<-exited
	_ = ln.Close()
	if waitErr != nil {
		return exitCode(waitErr), fmt.Errorf("sandboxd: %v", waitErr)
	}
	return 0, nil
}

// prSetChildSubreaper is PR_SET_CHILD_SUBREAPER from linux/prctl.h.
const prSetChildSubreaper = 36

func setChildSubreaper() error {
	if _, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, prSetChildSubreaper, 1, 0); e != 0 {
		return e
	}
	return nil
}

// reap waits for every child of this process and returns sandboxd's wait status when sandboxd
// (pid) exits. As the container's first process the terminator inherits every orphan in the pod,
// a guest's double-forked processes among them; one never waited for stays a zombie that holds a
// pid against the pod's limit for the rest of a warm pod's life (found in review, 2026-11-05).
// It replaces exec.Cmd.Wait, which would race this loop for sandboxd's own status. onOrphan,
// when set, hears each other pid reaped (the tests).
func reap(pid int, onOrphan func(int)) syscall.WaitStatus {
	for {
		var ws syscall.WaitStatus
		got, err := syscall.Wait4(-1, &ws, 0, nil)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			// ECHILD with sandboxd unreaped cannot happen while it runs; report it as a failure
			return syscall.WaitStatus(1 << 8)
		}
		if got == pid {
			return ws
		}
		if onOrphan != nil {
			onOrphan(got)
		}
	}
}

// statusErr is a wait status as exec's error: nil for exit 0, else an error naming it.
func statusErr(ws syscall.WaitStatus) error {
	switch {
	case ws.Exited() && ws.ExitStatus() == 0:
		return nil
	case ws.Exited():
		return exitStatus(ws.ExitStatus())
	case ws.Signaled():
		return fmt.Errorf("killed by %v", ws.Signal())
	default:
		return fmt.Errorf("wait status %#x", uint32(ws))
	}
}

// exitStatus is a nonzero exit, which run passes on as its own.
type exitStatus int

func (e exitStatus) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

func isClosed(c <-chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}

func exitCode(err error) int {
	var es exitStatus
	if errors.As(err, &es) && es > 0 {
		return int(es)
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() > 0 {
		return ee.ExitCode()
	}
	if err != nil {
		return 1
	}
	return 0
}

// sandboxdFlag is the one form a sandboxd argument may take, the read-back's rule
// (sandbox/agentsandbox/readback.go): sandboxd parses its arguments with Go's flag
// package, which stops at "--" or a bare word and lets a flag without "=" take the next
// argument as its value, so any other form could make it listen elsewhere than checked.
var sandboxdFlag = regexp.MustCompile(`^--?[A-Za-z][A-Za-z0-9_.-]*=`)

// sandboxdFlagsCommit is the agent-sandbox commit whose sandboxd sandboxdFlags was read
// from: docker/agentsandbox.Dockerfile's AGENT_SANDBOX_COMMIT, which a test holds it to.
const sandboxdFlagsCommit = "807cc37107bd7c012115afac9fa9c3b77b8365c2"

// sandboxdFlags is every flag that sandboxd takes, as its own -h listed them (2026-11-24,
// the image built from sandboxdFlagsCommit): its packages/sandboxd/cmd/sandboxd flags,
// controller-runtime's zap logging flags and its kubeconfig flag. An argument naming any
// other is refused, so a flag a later sandboxd adds (one that loosens its token check,
// say) cannot pass this check unread. Moving the pin means reading the new sandboxd's -h
// and this list again; sandbox/agentsandbox's read-back keeps the same list, and a test
// there holds the two lists and the pin together.
var sandboxdFlags = map[string]bool{
	"auth-token-file": true, "auth-token-sha256": true, "grpc-port": true, "http-idle-timeout": true,
	"kubeconfig": true, "listen-host": true, "metadata-env-prefix": true, "rest-port": true,
	"root-dir": true, "shutdown-timeout": true, "stream-chunk-size": true, "version": true,
	"zap-devel": true, "zap-encoder": true, "zap-log-level": true, "zap-stacktrace-level": true,
	"zap-time-encoding": true,
}

// checkArgs requires sandboxd's gRPC server on loopback port 9091 and nothing else that
// could move it: one --listen-host=127.0.0.1, one --grpc-port=9091, every argument a
// --name=value flag of the pinned sandboxd's (sandboxdFlags); and a token it checks, one
// --auth-token-sha256 and no token file, so the image never starts a root sandboxd that
// answers anyone on loopback (plimsolld's read-back also requires the digest to be its
// own token's; this is the image's own floor, for any other consumer of it).
func checkArgs(args []string) error {
	listen, port, token := 0, 0, 0
	for _, a := range args {
		if !sandboxdFlag.MatchString(a) {
			return fmt.Errorf("sandboxd's argument %q is not a --name=value flag", a)
		}
		name, value, _ := strings.Cut(strings.TrimPrefix(strings.TrimPrefix(a, "-"), "-"), "=")
		if !sandboxdFlags[name] {
			return fmt.Errorf("sandboxd's flag --%s is not one the pinned sandboxd takes", name)
		}
		switch name {
		case "listen-host":
			if value != backendHost {
				return fmt.Errorf("sandboxd must listen on %s alone, not %q", backendHost, value)
			}
			listen++
		case "grpc-port":
			if value != backendPort {
				return fmt.Errorf("sandboxd's gRPC port must be %s, not %q", backendPort, value)
			}
			port++
		case "auth-token-sha256":
			if !tokenDigest.MatchString(value) {
				return errors.New("sandboxd's --auth-token-sha256 is not a SHA-256 in lowercase hex")
			}
			token++
		case "auth-token-file":
			return errors.New("sandboxd must check a token digest given as --auth-token-sha256, not read one from a file")
		}
	}
	if listen != 1 || port != 1 {
		return fmt.Errorf("sandboxd needs exactly one --listen-host=%s and one --grpc-port=%s (got %d and %d)", backendHost, backendPort, listen, port)
	}
	if token != 1 {
		return fmt.Errorf("sandboxd needs exactly one --auth-token-sha256 (got %d): without one, anything in the pod could call it as root on loopback", token)
	}
	return nil
}

// waitFor dials addr until it accepts, sandboxd exits (done closes) or budget passes.
func waitFor(addr string, budget time.Duration, done <-chan struct{}) error {
	deadline := time.Now().Add(budget)
	for {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			return c.Close()
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("sandboxd's port %s did not accept within %s: %w", addr, budget, err)
		}
		select {
		case <-done:
			return errors.New("sandboxd exited")
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// keyFiles names the serving certificate and key, the directory that must keep the guest
// away from them, and the uid and gid that must own them (root's in the image; the test's
// own in tests).
type keyFiles struct {
	guard, cert, key string
	owner, group     uint32
}

// pairMode is the one mode the key and the certificate may have: readable by their owner
// and their group, root and root, as the driver writes them. No other process in the pod
// holds group root: plimsoll starts every guest process with its supplementary groups
// cleared, and its smoke test fails a guest holding any (sandbox/agentsandbox).
const pairMode = 0o440

// owned reads path's mode, uid and gid.
func owned(path string) (os.FileMode, uint32, uint32, error) {
	st, err := os.Stat(path)
	if err != nil {
		return 0, 0, 0, err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, 0, fmt.Errorf("%s: no owner information", path)
	}
	return st.Mode().Perm(), sys.Uid, sys.Gid, nil
}

// closedDir checks that the guard directory is owned by owner with no permission bit for
// group or other, so no other uid can reach the files inside it.
func (k keyFiles) closedDir() error {
	mode, uid, _, err := owned(k.guard)
	if err != nil {
		return err
	}
	if uid != k.owner || mode&0o077 != 0 {
		return fmt.Errorf("%s is owned by uid %d with mode %#o; it must be uid %d's with no group or other permission (the image makes it 0700), so the guest cannot reach the key", k.guard, uid, mode, k.owner)
	}
	return nil
}

// pairFile checks that the key or certificate at path has exactly pairMode, owner and
// group: anything else is not the pod's own key volume as plimsoll accepts it.
func (k keyFiles) pairFile(path string) error {
	mode, uid, gid, err := owned(path)
	if err != nil {
		return err
	}
	if mode != pairMode || uid != k.owner || gid != k.group {
		return fmt.Errorf("%s is owned by uid %d and gid %d with mode %#o; it must be uid %d's and gid %d's with mode %#o exactly (the pod's key volume, under a 0700 directory), so the guest cannot read the key", path, uid, gid, mode, k.owner, k.group, pairMode)
	}
	return nil
}

// load checks the guard directory, the key and the certificate, then reads the pair. The
// driver, as a Kubernetes Secret volume does, swaps both files at once by one symlink, so
// a read that straddled the swap (a certificate that does not match its key) is tried
// once more.
func (k keyFiles) load() (*tls.Certificate, error) {
	if err := k.closedDir(); err != nil {
		return nil, err
	}
	if err := k.pairFile(k.key); err != nil {
		return nil, err
	}
	if err := k.pairFile(k.cert); err != nil {
		return nil, err
	}
	pair, err := tls.LoadX509KeyPair(k.cert, k.key)
	if err != nil {
		pair, err = tls.LoadX509KeyPair(k.cert, k.key)
	}
	if err != nil {
		return nil, fmt.Errorf("the TLS key pair: %w", err)
	}
	return &pair, nil
}

// config is the server's TLS: 1.3 only, HTTP/2 the one application protocol, and the pair
// read again at every handshake.
func (k keyFiles) config() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS13,
		NextProtos:     []string{"h2"},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return k.load() },
	}
}

// limitedLog logs at most maxLogged lines in each logWindow, then one notice, then nothing
// until the next window.
func limitedLog(logf func(string, ...any), now func() time.Time) func(string, ...any) {
	var mu sync.Mutex
	var start time.Time
	n := 0
	return func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		if t := now(); start.IsZero() || t.Sub(start) >= logWindow {
			start, n = t, 0
		}
		n++
		switch {
		case n <= maxLogged:
			logf(format, args...)
		case n == maxLogged+1:
			logf("further connection failures in this minute are not logged")
		}
	}
}

// handshakeFailure names a failed handshake without its error text: Go's TLS errors can
// quote what the client sent (an ALPN mismatch lists the offered protocols), and anyone
// in the pod can connect, so a logged error would carry bytes of the guest's choosing.
func handshakeFailure(err error) string {
	var rh tls.RecordHeaderError
	var ne net.Error
	switch {
	case errors.As(err, &rh):
		return "not TLS (a cleartext client?)"
	case errors.As(err, &ne) && ne.Timeout():
		return "timed out"
	case strings.Contains(err.Error(), "application protocol"):
		return "no protocol in common (HTTP/2 is the only one served)"
	}
	// A client that refuses this pod's certificate says why in a TLS alert, whose text comes from a
	// fixed table by alert number (crypto/tls), never from bytes the client chose: the operator's
	// clue to a wrong CA or name (found in review, 2026-11-05). Anything outside that shape is
	// not logged.
	if m := remoteAlert.FindStringSubmatch(err.Error()); m != nil {
		return "the client refused this pod's certificate (" + m[1] + ")"
	}
	return "refused by TLS"
}

// remoteAlert is crypto/tls's text for an alert the peer sent: "remote error: tls: " and the alert's
// name from its table, or alert(N) for a number it has no name for.
var remoteAlert = regexp.MustCompile(`remote error: tls: ([a-z][a-z ]{2,40}|alert\([0-9]{1,3}\))$`)

// serve accepts until ln is closed.
func serve(ln net.Listener, cfg *tls.Config, backend string, logf func(string, ...any)) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			logf("accept: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go handle(c, cfg, backend, logf)
	}
}

// handle completes the handshake, requires HTTP/2 by ALPN, and only then connects to
// sandboxd and copies the decrypted bytes both ways. A connection that fails any of it
// reaches nothing.
func handle(raw net.Conn, cfg *tls.Config, backend string, logf func(string, ...any)) {
	defer raw.Close()
	c := tls.Server(raw, cfg)
	_ = raw.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := c.Handshake(); err != nil {
		// A TCP readiness probe connects and closes: that is an EOF, not news.
		if !errors.Is(err, io.EOF) {
			logf("handshake from %s: %s", raw.RemoteAddr(), handshakeFailure(err))
		}
		return
	}
	if p := c.ConnectionState().NegotiatedProtocol; p != "h2" {
		logf("connection from %s negotiated %q, not h2; closed", raw.RemoteAddr(), p)
		return
	}
	_ = raw.SetDeadline(time.Time{})
	b, err := net.DialTimeout("tcp", backend, dialTimeout)
	if err != nil {
		logf("sandboxd: %v", err)
		return
	}
	defer b.Close()
	pipe(c, b)
}

// endLinger bounds how long a connection whose answer has ended waits for the client to
// read the end and close its side, and how long sandboxd gets to finish answering once
// the client has ended its side: the bytes are already sent, so a client on a loaded pod
// network reads them well within it, and a client that never closes holds this
// connection's goroutines and its sandboxd connection only that long.
const endLinger = 5 * time.Second

// pipe copies both ways and ends each side in order, so the last bytes either side wrote
// arrive whole (finding release-59):
//   - sandboxd's side ends (its last answer written): the client's side is ended after
//     everything copied (a TLS close_notify, then a TCP FIN), and the client gets
//     endLinger to read it and close, while what it still sends goes on to sandboxd or is
//     dropped. Closing at once once did this: with bytes of the client's still unread, the
//     kernel resets the connection and drops the answer's end still in the send buffer,
//     and when the client's next bytes met a sandboxd already gone, both sides were closed
//     with the answer's end still being copied.
//   - the client's side ends: its end is passed to sandboxd (a TCP FIN), and sandboxd gets
//     endLinger to finish answering.
//   - sandboxd stops taking bytes (it has gone): what the client sends is read and dropped,
//     so it cannot reset the connection, until sandboxd's side ends.
//   - the client's side fails: both are closed at once.
func pipe(a, b net.Conn) {
	var once sync.Once
	closeBoth := func() { once.Do(func() { _ = a.Close(); _ = b.Close() }) }
	defer closeBoth()
	up := make(chan struct{})
	go func() {
		defer close(up)
		readErr, writeErr := copyEnds(b, a)
		switch {
		case writeErr != nil:
			_, _ = io.Copy(io.Discard, a)
		case errors.Is(readErr, io.EOF):
			closeWrite(b)
			_ = b.SetReadDeadline(time.Now().Add(endLinger))
		default:
			closeBoth()
		}
	}()
	_, _ = copyEnds(a, b)
	closeWrite(a)
	linger := time.NewTimer(endLinger)
	defer linger.Stop()
	select {
	case <-up:
	case <-linger.C:
	}
	closeBoth()
	<-up
}

// copyEnds copies src to dst until either fails, and says which: a read error (io.EOF at
// src's end) or a write error.
func copyEnds(dst io.Writer, src io.Reader) (readErr, writeErr error) {
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return nil, werr
			}
		}
		if err != nil {
			return err, nil
		}
	}
}

// closeWrite ends c's sending side after everything written to it: for TLS a close_notify
// alert, then the TCP FIN under it.
func closeWrite(c net.Conn) {
	if t, ok := c.(*tls.Conn); ok {
		_ = t.CloseWrite()
		c = t.NetConn()
	}
	if w, ok := c.(interface{ CloseWrite() error }); ok {
		_ = w.CloseWrite()
	}
}
