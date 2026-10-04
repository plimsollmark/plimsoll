package openshell

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"sync"
	"time"

	"connectrpc.com/connect"

	"github.com/plimsollmark/plimsoll/gen/go/openshell/openshellv1"
	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandbox/internal/sessionkit"
)

// Grants (phase 2). A granted run's guest gets the docker provider's injected client
// unchanged: host.* is HTTP over the Unix socket named by HOST_API_SOCKET. Inside the
// sandbox a relay listens on that socket and on a loopback port, and pairs each guest
// connection with one connection plimsoll dials in through the gateway's ForwardTcp,
// piping bytes both ways. plimsoll serves the shared broker on those connections, so
// the grant, the minted credential, the exact-route check, the budgets and the call
// trace stay in this process, and the sandbox keeps the no-grant deny-all policy.
//
// A process in the sandbox that binds the relay's port first, kills the relay, or
// writes to the relay's output gains nothing: whoever holds a connection can only
// send the broker requests, which it checks exactly as it checks the guest's. The
// relay's output is untrusted input: a "need" line only adds one to a count that a
// fixed set of maxForwardConns workers answers, at most maxForwardConns connections
// are ever live or being dialed, an unfinished line is held to maxRelayLine bytes, and
// failed dials slow the whole pool down (failedLocked). So no amount of output grows
// plimsoll's goroutines, tokens or buffers. Nor does it grow the load on the shared
// gateway past a bound: failed dials are paced by the backoff, and a run's successful
// dials are capped (forwardPool.maxDials), since a dial that succeeds and then carries
// nothing, which a process holding the relay's port can cause, triggers no backoff.

// relayScript is the in-sandbox relay: argv carries the loopback port and the Unix
// socket path. It prints "ready" once both listeners are up, and "need" whenever a
// guest connection arrives with no plimsoll connection waiting for it.
const relayScript = `const net=require("net"),fs=require("fs");const [port,sock]=process.argv.slice(1);
const idle=[],waiting=[];const say=s=>process.stdout.write(s+"\n");
function drop(list,c){const i=list.indexOf(c);if(i>=0)list.splice(i,1)}
function pair(g,u){g.pipe(u);u.pipe(g);const end=()=>{g.destroy();u.destroy()};g.on("close",end);u.on("close",end)}
const up=net.createServer(u=>{u.on("error",()=>{});const g=waiting.shift();if(g){pair(g,u);return}
idle.push(u);u.on("close",()=>drop(idle,u))});
const down=net.createServer(g=>{g.on("error",()=>{});const u=idle.shift();if(u){pair(g,u);return}
waiting.push(g);g.on("close",()=>drop(waiting,g));say("need")});
try{fs.unlinkSync(sock)}catch{}
let n=0;const ready=()=>{if(++n===2)say("ready")};
up.listen(+port,"127.0.0.1",ready);down.listen(sock,ready)`

const (
	// perTokenConns and maxForwardConns follow the gateway's limits
	// (acquire_ssh_connection_slots in v0.1.2): three live connections per session
	// token and twenty per sandbox. Eighteen leaves two for an operator's own shell.
	perTokenConns   = 3
	maxForwardConns = 18
	// relayReadyWait bounds the relay's start: a node start and two listens.
	relayReadyWait = 15 * time.Second
	// forwardChunk is the largest data frame a forwarded connection sends.
	forwardChunk = 32 << 10
	// closeGrace bounds how long a closed connection waits for the relay's side to end
	// before the stream is cancelled. The gateway counts a connection against its
	// per-token limit until then, so a long grace starves the next dial.
	closeGrace = 2 * time.Second
	// dialRetryEvery is the pool's first wait after a failed dial or refused stream;
	// it doubles with each failure in a row (failedLocked).
	dialRetryEvery = 100 * time.Millisecond
	// maxRelayLine bounds an unfinished line of the relay's output. The relay prints
	// only "ready" and "need"; a longer line is dropped whole.
	maxRelayLine = 64
)

// grantRun is one granted run's broker, relay and forwarded connections.
type grantRun struct {
	p      *Provider
	b      box
	broker *sandbox.GrantBroker
	sock   string
	port   uint32
	pool   *forwardPool
	srv    *http.Server

	relayCancel context.CancelFunc
	relayDone   chan struct{}
}

// startGrant mints the run's credential, starts the relay in the sandbox, and serves
// the broker on the connections the relay asks for. ctx bounds the start; the relay
// and the connections live until Close.
func (p *Provider) startGrant(ctx context.Context, b box, grant *sandbox.HostAPIGrant, budget time.Duration) (*grantRun, error) {
	broker, err := sandbox.NewGrantBroker(ctx, grant, budget)
	if err != nil {
		return nil, err
	}
	var r [4]byte
	var port uint32
	const portCount uint32 = 40000
	const maxUniformDraw uint64 = (1 << 32) / uint64(portCount) * uint64(portCount)
	for {
		if _, err := rand.Read(r[:]); err != nil {
			return nil, fmt.Errorf("relay port: %w", err)
		}
		draw := binary.BigEndian.Uint32(r[:])
		if uint64(draw) < maxUniformDraw {
			port = 20000 + draw%portCount
			break
		}
	}
	sock := "/tmp/.plimsoll-host-" + randHex(6) + ".sock"
	// The relay is one of plimsoll's own programs, carrying the run's brokered calls:
	// it starts under sessionkit.ControlArgv, so no variable an exec is handed reaches it.
	argv, err := sessionkit.ControlArgv(nil, "node", "-e", relayScript, strconv.FormatUint(uint64(port), 10), sock)
	if err != nil {
		broker.Close()
		return nil, err
	}
	g := &grantRun{
		p: p, b: b, broker: broker,
		sock:      sock,
		port:      port,
		relayDone: make(chan struct{}),
	}
	g.pool = newForwardPool(p, b, g.port, dialCap(grant))
	ready := make(chan struct{})
	var once sync.Once
	var lines relayLines
	watch := func(chunk []byte) {
		for _, l := range lines.feed(chunk) {
			switch l {
			case "ready":
				once.Do(func() { close(ready) })
			case "need":
				g.pool.need()
			}
		}
	}
	rctx, rcancel := context.WithCancel(context.WithoutCancel(ctx))
	g.relayCancel = rcancel
	go func() {
		defer close(g.relayDone)
		_, _ = p.execWatch(rctx, b, argv, nil, nil, 4096, 4096, watch)
	}()
	timer := time.NewTimer(relayReadyWait)
	defer timer.Stop()
	select {
	case <-ready:
	case <-g.relayDone:
		g.Close()
		return nil, errors.New("openshell grant: the relay exited before it was ready")
	case <-timer.C:
		g.Close()
		return nil, fmt.Errorf("openshell grant: the relay was not ready within %v", relayReadyWait)
	case <-ctx.Done():
		g.Close()
		return nil, ctx.Err()
	}
	g.srv = broker.Serve(g.pool)
	return g, nil
}

// env is what the guest's process needs to reach the relay.
func (g *grantRun) env() map[string]string {
	return map[string]string{sandbox.HostAPISocketEnv: g.sock}
}

// Close stops serving, closes every forwarded connection, revokes every session token,
// ends the relay and releases the broker. It is safe on a partly started run.
func (g *grantRun) Close() {
	if g.srv != nil {
		_ = g.srv.Close()
	}
	g.pool.close()
	g.relayCancel()
	select {
	case <-g.relayDone:
	case <-time.After(10 * time.Second):
	}
	g.broker.Close()
}

// forwardToken is one CreateSshSession token and its live connections.
type forwardToken struct {
	token string
	live  int
}

// relayLines splits the relay's output into lines, holding at most maxRelayLine bytes
// of an unfinished one: anything in the sandbox that can write to the relay's output
// could otherwise grow the buffer without end by never finishing a line.
type relayLines struct {
	mu   sync.Mutex
	part []byte
	skip bool // the current line overran maxRelayLine: drop it through its newline
}

func (r *relayLines) feed(chunk []byte) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for len(chunk) > 0 {
		piece, rest, done := bytes.Cut(chunk, []byte{'\n'})
		if !r.skip && len(r.part)+len(piece) > maxRelayLine {
			r.part, r.skip = r.part[:0], true
		}
		if !r.skip {
			r.part = append(r.part, piece...)
		}
		if !done {
			break
		}
		if !r.skip {
			out = append(out, string(r.part))
		}
		r.part, r.skip = r.part[:0], false
		chunk = rest
	}
	return out
}

// forwardPool is the broker server's listener: its connections are the ForwardTcp
// streams plimsoll dials into the relay, one for each "need" the relay prints, at most
// maxForwardConns live or being dialed at a time, perTokenConns per session token.
type forwardPool struct {
	p      *Provider
	b      box
	port   uint32
	accept chan net.Conn
	done   chan struct{}
	mint   sync.Mutex // serializes token creation, so dials that find no room share one

	mu      sync.Mutex
	wake    *sync.Cond // on mu: a need arrived, a slot came free, or the pool closed
	closed  bool
	pending int // "need" lines not yet answered with a connection
	held    int // slots taken by connections live or being dialed; at most maxForwardConns
	// failures counts dials and streams that failed before carrying anything since one
	// last did; no worker claims before notBefore (see failedLocked).
	failures  int
	notBefore time.Time
	tokens    []*forwardToken
	live      map[net.Conn]*forwardToken
	// dials counts connections this run has dialed or is dialing; no worker claims
	// once it reaches maxDials. A failed dial or a refused stream gives its count back,
	// since failures are paced by the backoff instead. capped says the cap was logged.
	dials, maxDials int
	capped          bool
}

// dialCap is a run's successful-dial cap: each brokered call needs at most one
// forwarded connection, so a run that makes its whole call budget needs at most that
// many, and maxForwardConns more covers connections dialed for guest connections that
// closed before they were paired.
func dialCap(grant *sandbox.HostAPIGrant) int {
	return grant.CallBudget() + maxForwardConns
}

// newForwardPool starts the pool's maxForwardConns workers; they end when it closes.
func newForwardPool(p *Provider, b box, port uint32, maxDials int) *forwardPool {
	f := &forwardPool{p: p, b: b, port: port, accept: make(chan net.Conn, maxForwardConns), done: make(chan struct{}), live: map[net.Conn]*forwardToken{}, maxDials: maxDials}
	f.wake = sync.NewCond(&f.mu)
	for range maxForwardConns {
		go f.worker()
	}
	return f
}

// need counts one "need" line: a guest connection waiting for a forwarded one. It only
// counts, so a line costs one increment however many are printed, and by whom.
func (f *forwardPool) need() {
	f.mu.Lock()
	f.pending++
	f.mu.Unlock()
	f.wake.Signal()
}

// worker answers the count one connection at a time.
func (f *forwardPool) worker() {
	for f.claim() {
		f.connect()
	}
}

// claim waits for a need, a free slot and the end of any backoff, and takes the need
// and the slot under the lock that counts them; false once the pool is closed.
func (f *forwardPool) claim() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for !f.closed && (f.pending == 0 || f.held >= maxForwardConns || f.dials >= f.maxDials || time.Now().Before(f.notBefore)) {
		if f.pending > 0 && f.dials >= f.maxDials && !f.capped {
			f.capped = true
			slog.Warn("openshell grant: the run reached its forwarded-connection cap; further needs go unanswered",
				"sandbox", f.b.name, "cap", f.maxDials)
		}
		f.wake.Wait()
	}
	if f.closed {
		return false
	}
	f.pending--
	f.held++
	f.dials++
	return true
}

// releaseLocked gives back a slot claim took.
func (f *forwardPool) releaseLocked() {
	f.held--
	f.wake.Signal()
}

// failedLocked records a dial or a stream that failed before carrying anything. The
// need it was for goes back to the count, and every worker waits dialRetryEvery,
// doubling with each failure in a row up to 64 times that, until a stream carries data
// again. The wait is the pool's, not the need's, so however many needs are counted
// (and the relay's output can count any number), failures cost at most
// maxForwardConns dials per wait: a few a second.
func (f *forwardPool) failedLocked() {
	f.pending++
	d := dialRetryEvery << min(f.failures, 6)
	f.failures++
	f.notBefore = time.Now().Add(d)
	time.AfterFunc(d, f.wake.Broadcast)
}

func (f *forwardPool) Accept() (net.Conn, error) {
	select {
	case c := <-f.accept:
		return c, nil
	case <-f.done:
		return nil, net.ErrClosed
	}
}

// Close stops Accept and the workers; the connections close with the server, and
// close revokes.
func (f *forwardPool) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.closed {
		f.closed = true
		close(f.done)
		f.wake.Broadcast()
	}
	return nil
}

func (f *forwardPool) Addr() net.Addr { return forwardAddr("openshell-forward") }

// connect makes one attempt on the slot claim took. On success the server holds the
// slot until the connection's stream ends (see ended). On failure the slot goes back
// and the need is counted again behind the pool's backoff: the reasons a dial fails
// are temporary (the gateway still counts a stream this side has closed until its
// half-close arrives), and dropping the need would leave its guest connection waiting
// for a line that has already been read, until the call's own deadline.
func (f *forwardPool) connect() {
	if f.dialOnce() {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dialFailedLocked()
}

// dialFailedLocked undoes a claim whose dial failed: the slot and the dial's count go
// back, and the need is counted again behind the backoff.
func (f *forwardPool) dialFailedLocked() {
	f.releaseLocked()
	f.dials--
	if !f.closed {
		f.failedLocked()
	}
}

// dialOnce makes one attempt, reporting whether the server now has the connection.
func (f *forwardPool) dialOnce() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tok, err := f.token(ctx)
	if err != nil {
		slog.Warn("openshell grant: creating a session token failed", "sandbox", f.b.name, "error", err)
		return false
	}
	if tok == nil {
		return false // the pool closed
	}
	c, err := openForward(f.p, f.b, tok.token, f.port, f.ended)
	f.mu.Lock()
	if err != nil || f.closed {
		tok.live--
		f.mu.Unlock()
		if c != nil {
			_ = c.Close()
		}
		return false
	}
	f.live[c] = tok
	f.mu.Unlock()
	select {
	case f.accept <- c:
		return true
	case <-f.done:
		f.mu.Lock()
		delete(f.live, c)
		tok.live--
		f.mu.Unlock()
		_ = c.Close()
		return false
	}
}

// token takes one connection's room on a session token, creating a token when none
// has room; nil once the pool is closed. Creation is serialized, so dials that find no
// room at the same moment share one new token instead of each minting their own:
// with at most maxForwardConns slots, a run holds at most
// maxForwardConns/perTokenConns tokens.
func (f *forwardPool) token(ctx context.Context) (*forwardToken, error) {
	if t, closed := f.roomy(); t != nil || closed {
		return t, nil
	}
	f.mint.Lock()
	defer f.mint.Unlock()
	if t, closed := f.roomy(); t != nil || closed {
		return t, nil // another dial made room while this one waited
	}
	resp, err := f.p.client.CreateSshSession(ctx, connect.NewRequest(&openshellv1.CreateSshSessionRequest{WorkspaceScope: ws(), Sandbox: f.b.name}))
	if err != nil {
		return nil, fmt.Errorf("openshell create ssh session: %w", err)
	}
	t := &forwardToken{token: resp.Msg.GetToken(), live: 1}
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		f.revoke([]*forwardToken{t}) // close has revoked the others already
		return nil, nil
	}
	f.tokens = append(f.tokens, t)
	f.mu.Unlock()
	return t, nil
}

// roomy takes one connection's room on an existing token, if one has it.
func (f *forwardPool) roomy() (t *forwardToken, closed bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil, true
	}
	for _, t := range f.tokens {
		if t.live < perTokenConns {
			t.live++
			return t, false
		}
	}
	return nil, false
}

// ended gives a finished connection's room back to its token and its slot back to the
// pool, so a worker waiting for one takes it. It runs when the stream is over at the
// gateway, not when the server closes the connection: the gateway counts a stream
// until its half-close arrives, so a token given back earlier is one the gateway
// still counts as full, and the next dial on it is refused. A refused stream never
// reached the relay, so the guest connection it was for still waits: it is a failure
// (failedLocked). A token the gateway no longer accepts (revoked, or past its
// lifetime) is dropped, so the next dial mints another instead of reusing it.
func (f *forwardPool) ended(c *streamConn, refused bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.live[c]
	if !ok {
		return
	}
	t.live--
	delete(f.live, c)
	f.releaseLocked()
	if c.received {
		f.failures = 0
	}
	if !refused || f.closed {
		return
	}
	f.dials--
	if code := connect.CodeOf(c.rerr); code == connect.CodeUnauthenticated || code == connect.CodePermissionDenied {
		f.tokens = slices.DeleteFunc(f.tokens, func(x *forwardToken) bool { return x == t })
	}
	f.failedLocked()
}

// close closes the listener and revokes every token, so none outlives the run.
func (f *forwardPool) close() {
	_ = f.Close()
	f.mu.Lock()
	conns := make([]net.Conn, 0, len(f.live))
	for c := range f.live {
		conns = append(conns, c)
	}
	tokens := append([]*forwardToken(nil), f.tokens...)
	f.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
	f.revoke(tokens)
}

// revoke ends tokens at the gateway.
func (f *forwardPool) revoke(tokens []*forwardToken) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, t := range tokens {
		if _, err := f.p.client.RevokeSshSession(ctx, connect.NewRequest(&openshellv1.RevokeSshSessionRequest{Token: t.token, AllowMissing: true})); err != nil {
			slog.Warn("openshell grant: revoking a session token failed; it lapses with the sandbox", "sandbox", f.b.name, "error", err)
		}
	}
}

type forwardAddr string

func (a forwardAddr) Network() string { return "openshell" }
func (a forwardAddr) String() string  { return string(a) }

// streamConn is a net.Conn over one ForwardTcp stream: data frames each way after the
// init frame. A reader goroutine drains the stream, so a read deadline interrupts a
// blocked Read with a timeout and leaves the connection open, as net.Conn requires:
// Go's HTTP server sets a past deadline to wake its own background read between
// requests, and closing the connection there would drop the guest's next reply.
type streamConn struct {
	st       *connect.BidiStreamForClient[openshellv1.TcpForwardFrame, openshellv1.TcpForwardFrame]
	cancel   context.CancelFunc
	frames   chan []byte
	rerr     error // why the stream ended; read after frames is closed
	received bool  // a data frame arrived; read after readDone is closed
	readDone chan struct{}
	closed   chan struct{}
	once     sync.Once
	ended    func(c *streamConn, refused bool) // once, when the stream is over

	rmu  sync.Mutex
	rbuf []byte
	wmu  sync.Mutex

	dmu       sync.Mutex
	rdl, wdl  time.Time
	rdlChange chan struct{} // closed and replaced whenever the read deadline changes
}

// openForward dials the relay's loopback port through the gateway with token. ended
// runs once the stream is over at the gateway too (see Close), with whether the
// gateway refused it before it carried anything.
func openForward(p *Provider, b box, token string, port uint32, ended func(c *streamConn, refused bool)) (*streamConn, error) {
	ctx, cancel := context.WithCancel(context.Background())
	st := p.client.ForwardTcp(ctx)
	err := st.Send(&openshellv1.TcpForwardFrame{Payload: &openshellv1.TcpForwardFrame_Init{Init: &openshellv1.TcpForwardInit{
		Sandbox: b.name, Workspace: workspace, AuthorizationToken: token,
		Target: &openshellv1.TcpForwardInit_Tcp{Tcp: &openshellv1.TcpRelayTarget{Host: "127.0.0.1", Port: port}},
	}}})
	if err != nil {
		cancel()
		return nil, fmt.Errorf("openshell forward tcp: %w", err)
	}
	c := &streamConn{st: st, cancel: cancel, frames: make(chan []byte, 16), readDone: make(chan struct{}), closed: make(chan struct{}), rdlChange: make(chan struct{}), ended: ended}
	go c.readLoop()
	return c, nil
}

func (c *streamConn) readLoop() {
	defer close(c.readDone)
	defer close(c.frames)
	for {
		fr, err := c.st.Receive()
		if err != nil {
			c.rerr = err
			if errors.Is(err, io.EOF) {
				c.rerr = io.EOF
			}
			return
		}
		if data := fr.GetData(); len(data) > 0 {
			c.received = true
			select {
			case c.frames <- data:
			case <-c.closed:
				c.rerr = net.ErrClosed
				return
			}
		}
	}
}

func (c *streamConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for len(c.rbuf) == 0 {
		c.dmu.Lock()
		dl, changed := c.rdl, c.rdlChange
		c.dmu.Unlock()
		var expired <-chan time.Time
		if !dl.IsZero() {
			d := time.Until(dl)
			if d <= 0 {
				return 0, os.ErrDeadlineExceeded
			}
			t := time.NewTimer(d)
			expired = t.C
			defer t.Stop()
		}
		select {
		case data, ok := <-c.frames:
			if !ok {
				return 0, c.rerr
			}
			c.rbuf = data
		case <-expired:
			return 0, os.ErrDeadlineExceeded
		case <-changed:
		case <-c.closed:
			return 0, net.ErrClosed
		}
	}
	n := copy(p, c.rbuf)
	c.rbuf = c.rbuf[n:]
	return n, nil
}

func (c *streamConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	c.dmu.Lock()
	dl := c.wdl
	c.dmu.Unlock()
	if !dl.IsZero() && !time.Now().Before(dl) {
		return 0, os.ErrDeadlineExceeded
	}
	written := 0
	for written < len(p) {
		end := min(written+forwardChunk, len(p))
		if err := c.st.Send(&openshellv1.TcpForwardFrame{Payload: &openshellv1.TcpForwardFrame_Data{Data: p[written:end]}}); err != nil {
			return written, err
		}
		written = end
	}
	return written, nil
}

// Close half-closes the stream, so every frame already sent reaches the relay before
// the end does, then cancels it once the other side has ended too, or after
// closeGrace. Cancelling first would reset the stream and could drop the tail of the
// reply the broker just wrote; Close cancels at once only when a Write is stuck.
func (c *streamConn) Close() error {
	c.once.Do(func() {
		close(c.closed)
		if c.wmu.TryLock() {
			_ = c.st.CloseRequest()
			c.wmu.Unlock()
		} else {
			// A Write holds the lock, blocked in Send because the relay has stopped
			// reading, which the guest decides: waiting for it could hang the run for
			// good. Cancelling ends that Send; what it was sending would not have
			// been read.
			c.cancel()
		}
		go func() {
			t := time.NewTimer(closeGrace)
			defer t.Stop()
			select {
			case <-c.readDone:
			case <-t.C:
			}
			c.cancel()
			_ = c.st.CloseResponse()
			<-c.readDone
			c.ended(c, c.refused())
		}()
	})
	return nil
}

// refused reports whether the gateway ended the stream with an error before it carried
// anything, which is how a refusal at its connection limit arrives: it sends no
// acknowledgement of an accepted stream. Call it after readDone is closed.
func (c *streamConn) refused() bool {
	return !c.received && c.rerr != nil && !errors.Is(c.rerr, io.EOF) &&
		connect.CodeOf(c.rerr) != connect.CodeCanceled
}

func (c *streamConn) LocalAddr() net.Addr  { return forwardAddr("plimsoll") }
func (c *streamConn) RemoteAddr() net.Addr { return forwardAddr("openshell-relay") }

func (c *streamConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

func (c *streamConn) SetReadDeadline(t time.Time) error {
	c.dmu.Lock()
	defer c.dmu.Unlock()
	c.rdl = t
	close(c.rdlChange)
	c.rdlChange = make(chan struct{})
	return nil
}

// SetWriteDeadline is checked when a write starts; a Send in progress is bounded by
// the gateway's own flow control instead.
func (c *streamConn) SetWriteDeadline(t time.Time) error {
	c.dmu.Lock()
	defer c.dmu.Unlock()
	c.wdl = t
	return nil
}
