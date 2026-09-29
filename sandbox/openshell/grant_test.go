package openshell

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/plimsollmark/plimsoll/gen/go/openshell/openshellv1"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// fakeForwarding adds CreateSshSession, RevokeSshSession and ForwardTcp to the fake
// gateway, with v0.1.2's per-token limit of three live connections, and a Go
// stand-in for the relay that the relay exec starts on this machine: its port and
// socket are remapped from the sandbox's names to real ones.
type fakeForwarding struct {
	t   *testing.T
	dir string

	mu        sync.Mutex
	tokens    map[string]*fakeToken
	ports     map[uint32]string // the relay's port in the sandbox -> its real address
	sockets   map[string]string // the relay's socket in the sandbox -> its real path
	most      int               // the most live connections any token had
	refused   int               // streams refused at the per-token limit
	refuseAll bool              // refuse every stream, as a gateway that keeps failing
	streams   int               // streams accepted and not yet ended
	peak      int               // the most streams accepted at once
	// forge, when set, writes to the relay's output before its "ready" line, as a
	// process in the sandbox that opens the relay's stdout could.
	forge func(write func([]byte))
}

type fakeToken struct {
	sandbox string
	live    int
	revoked bool
}

func withForwarding(t *testing.T, f *fakeGateway) *fakeForwarding {
	// A short path, not t.TempDir(): a Unix socket's path is capped at 108 bytes, and
	// the test's name plus a deep checkout overruns it (the export's staged tree did).
	dir, err := os.MkdirTemp("", "plr")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	fw := &fakeForwarding{t: t, dir: dir, tokens: map[string]*fakeToken{}, ports: map[uint32]string{}, sockets: map[string]string{}}
	f.forward = fw
	return fw
}

func (fw *fakeForwarding) revokedAll() bool {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	for _, tok := range fw.tokens {
		if !tok.revoked {
			return false
		}
	}
	return len(fw.tokens) > 0
}

func (f *fakeGateway) CreateSshSession(_ context.Context, req *connect.Request[openshellv1.CreateSshSessionRequest]) (*connect.Response[openshellv1.CreateSshSessionResponse], error) {
	f.record("CreateSshSession")
	fw := f.forward
	fw.mu.Lock()
	defer fw.mu.Unlock()
	tok := "tok-" + randHex(6)
	fw.tokens[tok] = &fakeToken{sandbox: req.Msg.GetSandbox()}
	return connect.NewResponse(&openshellv1.CreateSshSessionResponse{Token: tok, SandboxId: req.Msg.GetSandbox() + "-id"}), nil
}

func (f *fakeGateway) RevokeSshSession(_ context.Context, req *connect.Request[openshellv1.RevokeSshSessionRequest]) (*connect.Response[openshellv1.RevokeSshSessionResponse], error) {
	f.record("RevokeSshSession")
	fw := f.forward
	fw.mu.Lock()
	defer fw.mu.Unlock()
	if tok, ok := fw.tokens[req.Msg.GetToken()]; ok {
		tok.revoked = true
	}
	return connect.NewResponse(&openshellv1.RevokeSshSessionResponse{}), nil
}

func (f *fakeGateway) ForwardTcp(ctx context.Context, stream *connect.BidiStream[openshellv1.TcpForwardFrame, openshellv1.TcpForwardFrame]) error {
	f.record("ForwardTcp")
	fw := f.forward
	first, err := stream.Receive()
	if err != nil {
		return err
	}
	init := first.GetInit()
	if init == nil || init.GetTcp() == nil || init.GetTcp().GetHost() != "127.0.0.1" {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("first frame must be a loopback tcp init"))
	}
	fw.mu.Lock()
	tok, ok := fw.tokens[init.GetAuthorizationToken()]
	switch {
	case !ok || tok.revoked || tok.sandbox != init.GetSandbox():
		fw.mu.Unlock()
		return connect.NewError(connect.CodeUnauthenticated, errors.New("invalid ssh session token"))
	case tok.live >= perTokenConns || fw.refuseAll:
		fw.refused++
		fw.mu.Unlock()
		return connect.NewError(connect.CodeResourceExhausted, errors.New("SSH session connection limit reached"))
	}
	tok.live++
	fw.most = max(fw.most, tok.live)
	fw.streams++
	fw.peak = max(fw.peak, fw.streams)
	addr := fw.ports[init.GetTcp().GetPort()]
	fw.mu.Unlock()
	defer func() {
		fw.mu.Lock()
		tok.live--
		fw.streams--
		fw.mu.Unlock()
	}()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return connect.NewError(connect.CodeUnavailable, err)
	}
	defer conn.Close()
	go func() {
		buf := make([]byte, 32<<10)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				if stream.Send(&openshellv1.TcpForwardFrame{Payload: &openshellv1.TcpForwardFrame_Data{Data: append([]byte(nil), buf[:n]...)}}) != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	for {
		fr, err := stream.Receive()
		if err != nil {
			return nil
		}
		if _, err := conn.Write(fr.GetData()); err != nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		default:
		}
	}
}

// relay is the Go stand-in for relayScript: the same pairing and the same "ready" and
// "need" lines, on a real port and socket.
func (fw *fakeForwarding) relay(e *fakeExec) error {
	cmd := e.start.GetCommand()
	port64, _ := strconv.ParseUint(cmd[3], 10, 32)
	up, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer up.Close()
	sock := filepath.Join(fw.dir, fmt.Sprintf("relay-%d.sock", port64))
	down, err := net.Listen("unix", sock)
	if err != nil {
		return err
	}
	defer down.Close()
	fw.mu.Lock()
	fw.ports[uint32(port64)] = up.Addr().String()
	fw.sockets[cmd[4]] = sock
	fw.mu.Unlock()
	var mu sync.Mutex
	var idle []net.Conn
	var waiting []net.Conn
	var sendMu sync.Mutex
	say := func(s string) { sendMu.Lock(); _ = e.stdout([]byte(s + "\n")); sendMu.Unlock() }
	pair := func(g, u net.Conn) {
		go func() { _, _ = io.Copy(u, g); _ = u.Close(); _ = g.Close() }()
		go func() { _, _ = io.Copy(g, u); _ = g.Close(); _ = u.Close() }()
	}
	go func() {
		for {
			u, err := up.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			if len(waiting) > 0 {
				g := waiting[0]
				waiting = waiting[1:]
				mu.Unlock()
				pair(g, u)
				continue
			}
			idle = append(idle, u)
			mu.Unlock()
		}
	}()
	go func() {
		for {
			g, err := down.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			if len(idle) > 0 {
				u := idle[0]
				idle = idle[1:]
				mu.Unlock()
				pair(g, u)
				continue
			}
			waiting = append(waiting, g)
			mu.Unlock()
			say("need")
		}
	}()
	if fw.forge != nil {
		fw.forge(func(b []byte) { sendMu.Lock(); _ = e.stdout(b); sendMu.Unlock() })
	}
	say("ready")
	<-e.ctx.Done()
	return e.ctx.Err()
}

// guestSocket is the relay socket the guest's injected client would use, "" if none.
func (fw *fakeForwarding) guestSocket(e *fakeExec) string {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	return fw.sockets[e.start.GetEnvironment()[sandbox.HostAPISocketEnv]]
}

// guestGet is the Go stand-in for guest code: n concurrent GETs of path over the socket
// the injected client would use, each reply's status and body on stdout.
func (fw *fakeForwarding) guestGet(e *fakeExec, path string, n int) error {
	sock := fw.guestSocket(e)
	if sock == "" {
		return e.exit(9)
	}
	if err := e.stdout([]byte(strings.Join(getLines(sock, path, n), "\n") + "\n")); err != nil {
		return err
	}
	return e.exit(0)
}

// getLines makes n concurrent GETs of path over sock: each reply's status and body.
func getLines(sock, path string, n int) []string {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var lines []string
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := net.Dial("unix", sock)
			if err != nil {
				mu.Lock()
				lines = append(lines, "dial: "+err.Error())
				mu.Unlock()
				return
			}
			defer c.Close()
			fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: host\r\nConnection: close\r\n\r\n", path)
			resp, err := http.ReadResponse(bufio.NewReader(c), nil)
			line := ""
			if err != nil {
				line = "read: " + err.Error()
			} else {
				body, _ := io.ReadAll(resp.Body)
				line = fmt.Sprintf("%d %s", resp.StatusCode, strings.TrimSpace(string(body)))
			}
			mu.Lock()
			lines = append(lines, line)
			mu.Unlock()
		}()
	}
	wg.Wait()
	return lines
}

// grantScript runs the relay stand-in for the relay exec and guest for the payload.
func grantScript(fw *fakeForwarding, guest func(e *fakeExec) error) func(e *fakeExec) error {
	return func(e *fakeExec) error {
		cmd := e.start.GetCommand()
		if len(cmd) >= 3 && cmd[0] == "node" && cmd[1] == "-e" && cmd[2] == relayScript {
			return fw.relay(e)
		}
		return guest(e)
	}
}

func grantFor(base string) *sandbox.HostAPIGrant {
	return &sandbox.HostAPIGrant{
		BaseURL: base,
		Allow:   []sandbox.HostRoute{{Method: "GET", Path: "/items/*"}},
		Minter:  sandbox.StaticToken(liveSecret),
	}
}

func TestGrantedSnippetReachesTheBrokerThroughTheRelay(t *testing.T) {
	f, p := newFake(t)
	fw := withForwarding(t, f)
	up, calls := liveUpstream(t)
	var code string
	f.run = grantScript(fw, func(e *fakeExec) error {
		code = string(e.readAll())
		return fw.guestGet(e, "/items/42", 1)
	})
	res, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: `console.log("user code")`, Grant: grantFor(up.URL)})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Stdout, `200 {"authorized":true,"path":"/items/42"}`) || calls.Load() != 1 {
		t.Fatalf("result %+v, upstream calls %d", res, calls.Load())
	}
	if !strings.Contains(code, "HOST_API_SOCKET") || !strings.Contains(code, `console.log("user code")`) {
		t.Fatalf("the payload did not carry the injected client and the code: %.200q", code)
	}
	if res.CallTrace == nil || len(res.CallTrace.Calls) != 1 || res.CallTrace.Calls[0].Status != 200 {
		t.Fatalf("trace %+v", res.CallTrace)
	}
	if !fw.revokedAll() {
		t.Fatal("a session token outlived the run")
	}
	// The sandbox read back as the no-grant policy (the run would have been refused
	// otherwise), and it is deleted after the run like any other.
	waitGone(t, f)
}

func TestGrantBrokerRefusesAnUngrantedRoute(t *testing.T) {
	f, p := newFake(t)
	fw := withForwarding(t, f)
	up, calls := liveUpstream(t)
	f.run = grantScript(fw, func(e *fakeExec) error {
		e.readAll()
		return fw.guestGet(e, "/admin/keys", 1)
	})
	res, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "x", Grant: grantFor(up.URL)})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(strings.TrimSpace(res.Stdout), "403") || calls.Load() != 0 {
		t.Fatalf("result %+v, upstream calls %d", res, calls.Load())
	}
}

// Eight calls held open at once need three gateway session tokens, since a token
// carries at most three live connections.
func TestGrantPoolSpreadsConnectionsOverTokens(t *testing.T) {
	f, p := newFake(t)
	fw := withForwarding(t, f)
	// The upstream answers nothing until all eight calls are in flight together.
	var arrived sync.WaitGroup
	arrived.Add(8)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrived.Done()
		arrived.Wait()
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(up.Close)
	f.run = grantScript(fw, func(e *fakeExec) error {
		e.readAll()
		return fw.guestGet(e, "/items/1", 8)
	})
	res, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "x", Grant: grantFor(up.URL), Timeout: 20 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(res.Stdout, "200 "); n != 8 {
		t.Fatalf("%d of 8 calls succeeded: %s", n, res.Stdout)
	}
	fw.mu.Lock()
	tokens, most := len(fw.tokens), fw.most
	fw.mu.Unlock()
	if tokens < 3 || most > perTokenConns {
		t.Fatalf("%d tokens, at most %d connections on one", tokens, most)
	}
	if !fw.revokedAll() {
		t.Fatal("a session token outlived the run")
	}
}

func TestGrantedProjectPreloadsTheClient(t *testing.T) {
	f, p := newFake(t)
	fw := withForwarding(t, f)
	up, _ := liveUpstream(t)
	var plan string
	var env map[string]string
	f.run = grantScript(fw, func(e *fakeExec) error {
		plan = string(e.readAll())
		env = e.start.GetEnvironment()
		return e.exit(0)
	})
	if _, err := p.RunProject(context.Background(), sandbox.ProjectRequest{Steps: []string{"node main.js"}, Grant: grantFor(up.URL)}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan, `"hostSDK":`) || env[sandbox.HostAPISocketEnv] == "" || env["PLIMSOLL_WORK"] != workDir {
		t.Fatalf("plan carries the client: %v; env %v", strings.Contains(plan, `"hostSDK":`), env)
	}
}

// Every call is answered when the guest opens more connections at once than the
// gateway allows the run (maxForwardConns), whether the answer is the upstream's or
// plimsoll's own 429 for more than 16 host calls in flight (the broker's limit,
// shared with docker). None may hang: before dial retried, a connection the cap
// deferred waited for a "need" line that had already been read, and its call hung
// until the run's deadline.
func TestGrantPoolServesMoreCallsThanItsConnectionCap(t *testing.T) {
	f, p := newFake(t)
	fw := withForwarding(t, f)
	const n = maxForwardConns + 12
	// Every call is held briefly, so all n are in flight together and the run is
	// certainly at its connection cap when the later ones ask for a connection. A
	// hold, not a barrier on all n: the broker serves at most 16 calls at once, so a
	// barrier waiting for more than that would never release. Without the hold the cap
	// is reached only when the calls happen to overlap, which is why this passed here
	// and hung in the export's loaded run.
	var calls atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		time.Sleep(700 * time.Millisecond)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(up.Close)
	f.run = grantScript(fw, func(e *fakeExec) error {
		e.readAll()
		return fw.guestGet(e, "/items/1", n)
	})
	res, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "x", Grant: grantFor(up.URL), Timeout: 25 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	answered := strings.Count(res.Stdout, "200 ") + strings.Count(res.Stdout, "429 ")
	if answered != n {
		fw.mu.Lock()
		refused := fw.refused
		fw.mu.Unlock()
		t.Fatalf("%d of %d calls answered (%d streams refused at the per-token limit):\n%s", answered, n, refused, res.Stdout)
	}
	if got := strings.Count(res.Stdout, "200 "); got == 0 || int(calls.Load()) != got {
		t.Fatalf("%d calls reached the upstream, which saw %d:\n%s", got, calls.Load(), res.Stdout)
	}
	fw.mu.Lock()
	most := fw.most
	fw.mu.Unlock()
	if most > perTokenConns {
		t.Fatalf("%d connections on one session token, the gateway allows %d", most, perTokenConns)
	}
	if !fw.revokedAll() {
		t.Fatal("a session token outlived the run")
	}
}

// The relay's output is untrusted: whatever writes to it (the relay, or anything in
// the sandbox that opens its stdout) cannot make plimsoll hold more than maxRelayLine
// bytes of an unfinished line, and a line longer than that is dropped whole.
func TestRelayLinesBoundsAnUnfinishedLine(t *testing.T) {
	var r relayLines
	var got []string
	for _, chunk := range []string{"rea", "dy\nne", "ed\n", "\n"} {
		got = append(got, r.feed([]byte(chunk))...)
	}
	if !slices.Equal(got, []string{"ready", "need", ""}) {
		t.Fatalf("lines %q", got)
	}
	for range 64 {
		if lines := r.feed(bytes.Repeat([]byte("x"), 16<<10)); len(lines) != 0 || len(r.part) > maxRelayLine {
			t.Fatalf("an unfinished 1 MiB line: lines %q, %d bytes held", lines, len(r.part))
		}
	}
	if lines := r.feed([]byte("need\nneed\n")); !slices.Equal(lines, []string{"need"}) {
		t.Fatalf("the overlong line's tail must be dropped with it: %q", lines)
	}
}

// A flood of forged "need" lines, and a megabyte with no line end, cost plimsoll a
// count and a bounded buffer, not a goroutine, a dial or a token each: the gateway
// never sees more than maxForwardConns streams, the run mints at most
// maxForwardConns/perTokenConns tokens, and the guest's own calls are still answered.
func TestGrantPoolIgnoresForgedDemand(t *testing.T) {
	f, p := newFake(t)
	fw := withForwarding(t, f)
	const forged = 2000
	fw.forge = func(write func([]byte)) {
		write(bytes.Repeat([]byte("x"), 1<<20))
		write([]byte("\n"))
		write(bytes.Repeat([]byte("need\n"), forged))
	}
	up, _ := liveUpstream(t)
	baseline := runtime.NumGoroutine()
	var during int
	f.run = grantScript(fw, func(e *fakeExec) error {
		e.readAll()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			fw.mu.Lock()
			n := fw.streams
			fw.mu.Unlock()
			if n == maxForwardConns {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		during = runtime.NumGoroutine()
		return fw.guestGet(e, "/items/1", 5)
	})
	res, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "x", Grant: grantFor(up.URL), Timeout: 20 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(res.Stdout, "200 "); n != 5 {
		t.Fatalf("%d of 5 calls succeeded: %s", n, res.Stdout)
	}
	fw.mu.Lock()
	peak, tokens := fw.peak, len(fw.tokens)
	fw.mu.Unlock()
	if peak > maxForwardConns || tokens > maxForwardConns/perTokenConns {
		t.Fatalf("%d streams at once (cap %d), %d tokens (cap %d)", peak, maxForwardConns, tokens, maxForwardConns/perTokenConns)
	}
	// Each stream costs a handful of goroutines on both sides of this in-process fake;
	// one per forged line would be thousands.
	if during-baseline > 400 {
		t.Fatalf("%d goroutines during the run, %d before it", during, baseline)
	}
	if !fw.revokedAll() {
		t.Fatal("a session token outlived the run")
	}
}

// A gateway that refuses every stream costs a few dials, not a dial every 100 ms for
// the run's lifetime: each refusal puts the guest connection's need back after a delay
// that doubles.
func TestGrantPoolBacksOffARefusingGateway(t *testing.T) {
	f, p := newFake(t)
	fw := withForwarding(t, f)
	fw.refuseAll = true
	up, _ := liveUpstream(t)
	f.run = grantScript(fw, func(e *fakeExec) error {
		e.readAll()
		return fw.guestGet(e, "/items/1", 1)
	})
	_, _ = p.RunJavaScript(context.Background(), sandbox.Request{Code: "x", Grant: grantFor(up.URL), Timeout: 3 * time.Second})
	fw.mu.Lock()
	refused := fw.refused
	fw.mu.Unlock()
	// 100, 200, 400, 800 and 1600 ms of backoff fit about five dials into 3 s; a fixed
	// 100 ms retry would make about thirty.
	if refused < 3 || refused > 8 {
		t.Fatalf("%d streams refused in a 3 s run", refused)
	}
}

// A guest that sends the broker requests and never reads the replies (a setsid child
// that outlives the payload, say) blocks the forwarded stream's writes under flow
// control. Ending the run must not wait for them: before, Close waited on the stuck
// write for good, the sandbox was never deleted, and the run held its slot forever.
func TestGrantRunEndsWhenTheGuestStopsReading(t *testing.T) {
	f, p := newFake(t)
	fw := withForwarding(t, f)
	up, _ := liveUpstream(t)
	var stuck net.Conn
	t.Cleanup(func() {
		if stuck != nil {
			_ = stuck.Close()
		}
	})
	f.run = grantScript(fw, func(e *fakeExec) error {
		e.readAll()
		c, err := net.Dial("unix", fw.guestSocket(e))
		if err != nil {
			return err
		}
		stuck = c
		batch := strings.Repeat("GET /admin/keys HTTP/1.1\r\nHost: host\r\n\r\n", 1000)
		go func() {
			for range 400 {
				if _, err := io.WriteString(c, batch); err != nil {
					return
				}
			}
		}()
		time.Sleep(2 * time.Second) // the replies back up
		return e.exit(0)
	})
	done := make(chan error, 1)
	go func() {
		_, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "x", Grant: grantFor(up.URL), Timeout: 10 * time.Second})
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(40 * time.Second):
		t.Fatal("the run did not end: closing a forwarded stream waited on a write the guest had stalled")
	}
}

// Forged "need" lines behind a gateway that refuses every stream (or a relay the guest
// killed) cost a burst of at most maxForwardConns dials and then the pool's backoff,
// not a dial per line.
func TestGrantPoolBacksOffForgedDemandPoolWide(t *testing.T) {
	f, p := newFake(t)
	fw := withForwarding(t, f)
	fw.refuseAll = true
	fw.forge = func(write func([]byte)) { write(bytes.Repeat([]byte("need\n"), 2000)) }
	up, _ := liveUpstream(t)
	f.run = grantScript(fw, func(e *fakeExec) error {
		e.readAll()
		return fw.guestGet(e, "/items/1", 1)
	})
	_, _ = p.RunJavaScript(context.Background(), sandbox.Request{Code: "x", Grant: grantFor(up.URL), Timeout: 3 * time.Second})
	fw.mu.Lock()
	refused := fw.refused
	fw.mu.Unlock()
	if refused > 2*maxForwardConns {
		t.Fatalf("%d streams refused in a 3 s run with 2000 forged lines", refused)
	}
}

// A token the gateway stops accepting mid-run is replaced, not reused: the call after
// the revocation is served on a new one.
func TestGrantPoolReplacesARevokedToken(t *testing.T) {
	f, p := newFake(t)
	fw := withForwarding(t, f)
	up, _ := liveUpstream(t)
	f.run = grantScript(fw, func(e *fakeExec) error {
		e.readAll()
		sock := fw.guestSocket(e)
		first := getLines(sock, "/items/1", 1)
		fw.mu.Lock()
		for _, tok := range fw.tokens {
			tok.revoked = true
		}
		fw.mu.Unlock()
		second := getLines(sock, "/items/1", 1)
		if err := e.stdout([]byte(strings.Join(append(first, second...), "\n") + "\n")); err != nil {
			return err
		}
		return e.exit(0)
	})
	res, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "x", Grant: grantFor(up.URL), Timeout: 15 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	fw.mu.Lock()
	tokens := len(fw.tokens)
	fw.mu.Unlock()
	if n := strings.Count(res.Stdout, "200 "); n != 2 || tokens != 2 {
		t.Fatalf("%d of 2 calls succeeded on %d tokens: %s", n, tokens, res.Stdout)
	}
}
