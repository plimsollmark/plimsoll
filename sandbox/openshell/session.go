package openshell

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"

	"github.com/plimsollmark/plimsoll/gen/go/openshell/openshellv1"
	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandbox/internal/deadline"
	"github.com/plimsollmark/plimsoll/sandbox/internal/runnerwire"
)

// Sessions keep one sandbox alive across calls (sandbox.SessionProvider). What
// makes that safe, from the 2026-09-28 measurements on a v0.1.2 gateway
// (private/openshell-sessions-plan-2026-09-28.md, "Step 1 results"):
//
//   - A process a call starts outlives the call: a cancelled exec kills only the
//     command's process group, and a normal exit kills nothing. So after every call
//     the provider sweeps: one exec kills every process except the sandbox's own
//     (PID 1 and the main process, recorded when the sandbox became ready by PID,
//     start time and command line), its own
//     ancestors and itself, by PID, until a scan finds none. A process is alive while
//     any of its threads is, not while its /proc entry says so: a main thread that
//     called pthread_exit leaves the entry a zombie with its other threads running.
//     Its verdict is its exit status alone, which code in the sandbox cannot forge
//     without attaching to it, and OpenSession refuses a host whose Yama ptrace_scope
//     would allow that. The script travels in argv, not on stdin, so a leftover
//     process cannot append to it.
//   - When the sweep does not prove the boundary, a stop and start (the platform
//     killing every process) is the recovery, and when that fails the session ends.
//   - The main process is sleep, not the gateway's default login shell: a spared shell
//     reading a stream is a place leftover code could inject commands, and sleep
//     leaves on SIGTERM, so a stop takes a fraction of a second instead of the stop
//     timeout the shell waits out.
//   - Anyone who can call the gateway can change a sandbox between calls, so the
//     sandbox and its effective configuration are read back before every call.

var (
	// sessionCommand is a session sandbox's main process: 2^31-1 seconds, which every
	// sleep accepts, and far beyond any lifetime.
	sessionCommand = []string{"sleep", "2147483647"}
)

const (
	// sessionLabel marks a session's sandbox (informational; the reaper treats it as
	// any plimsoll sandbox, by its declared lifetime).
	sessionLabel = "plimsoll.session"
	// sweepBudget bounds one sweep exec: normally a node start and one /tmp walk.
	sweepBudget = 20 * time.Second
	// stopBudget bounds a stop and its wait for the stopped phase.
	stopBudget = 60 * time.Second
	// maxDiskEntries bounds the sweep's walk of /tmp: past it the session counts as
	// over its disk budget, since a walk of every entry must stay bounded.
	maxDiskEntries = 200000
)

// Sweep exit statuses; any other status, or no status, means the boundary is unproven.
const (
	sweepClean        = 0  // no process but the sandbox's own; disk within budget
	sweepOverBudget   = 10 // clean, but the session's files exceed the budget
	sweepUnmeasurable = 11 // clean, but a directory under /tmp could not be read
)

// listScript lists every process except itself and its ancestors, and reads the
// host's Yama ptrace_scope, as JSON on stdout. It runs only in a sandbox no call has
// touched yet (at open and after a start), so its output is trusted.
const listScript = liveFn + `const fs=require("fs");const self=String(process.pid);const skip=new Set([self]);
for(let p=self;;){let st;try{st=fs.readFileSync("/proc/"+p+"/stat","latin1")}catch{break}
const pp=st.slice(st.lastIndexOf(")")+2).split(" ")[1];if(!pp||pp==="0"||skip.has(pp))break;skip.add(pp);p=pp}
const procs=[];for(const d of fs.readdirSync("/proc")){if(!/^[0-9]+$/.test(d)||(skip.has(d)&&d!=="1")||!live(d))continue;
try{const st=fs.readFileSync("/proc/"+d+"/stat","latin1");const f=st.slice(st.lastIndexOf(")")+2).split(" ");
const raw=fs.readFileSync("/proc/"+d+"/cmdline","latin1");const cmd=raw.split("\0").join(" ").trim();
procs.push({pid:+d,ppid:+f[1],state:f[0],start:f[19],cmd,cmdHex:Buffer.from(raw,"latin1").toString("hex")})}catch{}}
let ptrace="";try{ptrace=fs.readFileSync("/proc/sys/kernel/yama/ptrace_scope","latin1").trim()}catch{}
process.stdout.write(JSON.stringify({ptrace,procs}))`

// sweepScript kills every process that is not the sandbox's own (argv after the
// first two: pid:starttime:cmdline-hex identities, so a process that lands on a spared
// PID in the same clock tick is spared only if its command line matches too), not an
// ancestor and not itself, until a scan
// finds none, then walks /tmp. Arguments: the disk budget in bytes (0 = none), the
// entry bound, the pairs to keep. Its exit status is the verdict (the sweep*
// constants); its stdout is a summary for the log only.
// liveFn is the liveness test both scripts use. A process whose main thread called
// pthread_exit shows in /proc as a zombie while its other threads run on (measured
// 2026-09-28 on this image's base), so a state of Z or X on the entry itself proves
// nothing: every thread under task/ must be dead before the process is. A true
// zombie (every thread dead) is left alone, because killing one does nothing and the
// sweep would never converge.
const liveFn = `function live(d){try{for(const t of fs.readdirSync("/proc/"+d+"/task")){
const st=fs.readFileSync("/proc/"+d+"/task/"+t+"/stat","latin1");
const s=st.slice(st.lastIndexOf(")")+2).split(" ")[0];if(s!=="Z"&&s!=="X")return true}}catch{return false}return false}
`

const sweepScript = liveFn + `const fs=require("fs");const [budget,maxEntries,...keepList]=process.argv.slice(1);
const keep=new Set(keepList);const self=String(process.pid);const up=new Set([self]);
for(let p=self;;){let st;try{st=fs.readFileSync("/proc/"+p+"/stat","latin1")}catch{break}
const pp=st.slice(st.lastIndexOf(")")+2).split(" ")[1];if(!pp||pp==="0"||up.has(pp))break;up.add(pp);p=pp}
const nap=()=>Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,20);
function others(){const o=[];for(const d of fs.readdirSync("/proc")){if(!/^[0-9]+$/.test(d)||up.has(d))continue;
let st;try{st=fs.readFileSync("/proc/"+d+"/stat","latin1")}catch{continue}
const f=st.slice(st.lastIndexOf(")")+2).split(" ");if(!live(d))continue;
let cmd="";try{cmd=fs.readFileSync("/proc/"+d+"/cmdline").toString("hex")}catch{}
if(!keep.has(d+":"+f[19]+":"+cmd))o.push(+d)}return o}
let rounds=0,killed=0;
for(let o=others();o.length>0;o=others()){if(++rounds>50)process.exit(1);
for(const p of o){try{process.kill(p,"SIGKILL");killed++}catch{}}nap()}
let bytes=0,entries=0;const dirs=["/tmp"];
while(dirs.length>0){const dir=dirs.pop();let names;
try{names=fs.readdirSync(dir)}catch{try{fs.chmodSync(dir,0o700);names=fs.readdirSync(dir)}catch{process.exit(11)}}
for(const n of names){const p=dir+"/"+n;let st;try{st=fs.lstatSync(p)}catch{continue}
if(++entries>+maxEntries)process.exit(10);bytes+=st.blocks*512;if(+budget>0&&bytes>+budget)process.exit(10);
if(st.isDirectory())dirs.push(p)}}
process.stdout.write(JSON.stringify({rounds,killed,bytes,entries}))`

// SupportsSessions is true: sessions need nothing beyond what runs need.
func (*Provider) SupportsSessions() bool { return true }

// session is one open session.
type session struct {
	p       *Provider
	b       box
	labels  map[string]string
	tier    sandbox.IsolationClass
	expires time.Time
	disk    int64

	ctx    context.Context // cancelled when the session ends, which stops a call in flight
	cancel context.CancelFunc
	turn   chan struct{} // one slot: holding it is the right to call, suspend or resume
	done   chan struct{}

	mu       sync.Mutex
	end      *sandbox.SessionEndedError
	stopped  bool
	baseline []string // pid:starttime:cmdline-hex of the sandbox's own processes
	life     *time.Timer
}

var _ sandbox.Session = (*session)(nil)

// OpenSession creates a session's sandbox (the run policy, sleep as the main process,
// the session's lifetime declared on it), verifies it as a run's sandbox is verified,
// checks that the host's ptrace_scope lets the sweep's verdict stand, and records the
// sandbox's own processes, which every sweep spares.
func (p *Provider) OpenSession(ctx context.Context, opts sandbox.SessionOptions) (sandbox.Session, error) {
	if opts.Lifetime <= 0 {
		return nil, sandbox.NotDispatched(sandbox.RefusalRequest, fmt.Errorf("%w: a session needs a positive lifetime", sandbox.ErrInvalidRequest))
	}
	tier, err := p.ready(ctx, nil, opts.MinimumIsolation)
	if err != nil {
		return nil, err
	}
	// No sized /tmp, whatever DiskMB says: docker discards a tmpfs when its container
	// stops, and a session is stopped to suspend it and to recover from a failed sweep,
	// so its files would vanish (measured on v0.1.2, 2026-09-29). Its disk budget is
	// measured after each call instead.
	b, labels, err := p.createBox(ctx, opts.Lifetime, sessionCommand, map[string]string{sessionLabel: "1"}, nil)
	if err != nil {
		return nil, deadlineAware(ctx, err)
	}
	sctx, cancel := context.WithCancel(context.Background())
	s := &session{
		p: p, b: b, labels: labels, tier: tier,
		expires: time.Now().Add(opts.Lifetime),
		disk:    opts.DiskBytes,
		ctx:     sctx, cancel: cancel,
		turn: make(chan struct{}, 1),
		done: make(chan struct{}),
	}
	if err := s.recordBaseline(ctx); err != nil {
		cancel()
		p.deleteLater(b)
		return nil, deadlineAware(ctx, err)
	}
	p.mu.Lock()
	p.sessions[s] = struct{}{}
	p.mu.Unlock()
	s.mu.Lock()
	s.life = time.AfterFunc(time.Until(s.expires), func() { s.finish(sandbox.SessionExpired, "") })
	s.mu.Unlock()
	return s, nil
}

func (p *Provider) openSessions() []*session {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]*session, 0, len(p.sessions))
	for s := range p.sessions {
		out = append(out, s)
	}
	return out
}

func (s *session) Isolation() sandbox.IsolationClass { return s.tier }
func (s *session) ExpiresAt() time.Time              { return s.expires }
func (s *session) Done() <-chan struct{}             { return s.done }

func (s *session) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.end == nil {
		return nil
	}
	return s.end
}

// finish ends the session once, for the first reason given: it stops a call in
// flight, and deletes the sandbox off the caller's path.
func (s *session) finish(reason sandbox.SessionEnd, detail string) {
	s.mu.Lock()
	if s.end != nil {
		s.mu.Unlock()
		return
	}
	s.end = &sandbox.SessionEndedError{Reason: reason, Detail: detail}
	if s.life != nil {
		s.life.Stop()
	}
	s.mu.Unlock()
	s.cancel()
	close(s.done)
	s.p.mu.Lock()
	delete(s.p.sessions, s)
	s.p.mu.Unlock()
	if reason != sandbox.SessionClosed && reason != sandbox.SessionShutdown {
		slog.Info("openshell: session ended", "sandbox", s.b.name, "reason", reason.String(), "detail", detail)
	}
	s.p.deleteLater(s.b)
}

// acquire takes the session's turn, bounded by ctx. A session that ended, or ends
// while waiting, refuses: nothing ran.
func (s *session) acquire(ctx context.Context) error {
	if err := s.Err(); err != nil {
		return sandbox.RefuseEndedSession(err)
	}
	select {
	case s.turn <- struct{}{}:
	case <-s.done:
		return sandbox.RefuseEndedSession(s.Err())
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := s.Err(); err != nil {
		<-s.turn
		return sandbox.RefuseEndedSession(err)
	}
	return nil
}

func (s *session) release() { <-s.turn }

// Close ends the session and deletes its sandbox. It does not wait for a call in
// flight: the call is stopped.
func (s *session) Close(context.Context) error {
	s.finish(sandbox.SessionClosed, "")
	return nil
}

// Suspend stops the sandbox: a stopped container holds no memory or CPU and keeps its
// files; the next call starts it again.
func (s *session) Suspend(ctx context.Context) error {
	if err := s.acquire(ctx); err != nil {
		return err
	}
	defer s.release()
	s.mu.Lock()
	stopped := s.stopped
	s.mu.Unlock()
	if stopped {
		return nil
	}
	if err := s.stop(ctx); err != nil {
		s.finish(sandbox.SessionBoundaryFailed, "the sandbox could not be stopped: "+err.Error())
		return s.Err()
	}
	return nil
}

func (s *session) stop(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), stopBudget)
	defer cancel()
	if _, err := s.p.client.StopSandbox(ctx, connect.NewRequest(&openshellv1.StopSandboxRequest{WorkspaceScope: ws(), Name: s.b.name})); err != nil {
		return fmt.Errorf("openshell stop sandbox: %w", err)
	}
	for {
		resp, err := s.p.client.GetSandbox(ctx, connect.NewRequest(&openshellv1.GetSandboxRequest{WorkspaceScope: ws(), Name: s.b.name}))
		if err != nil {
			return fmt.Errorf("openshell get sandbox: %w", err)
		}
		switch ph := resp.Msg.GetSandbox().GetStatus().GetPhase(); ph {
		case openshellv1.SandboxPhase_SANDBOX_PHASE_STOPPED:
			s.mu.Lock()
			s.stopped = true
			s.mu.Unlock()
			return nil
		case openshellv1.SandboxPhase_SANDBOX_PHASE_STOPPING, openshellv1.SandboxPhase_SANDBOX_PHASE_READY:
		default:
			return fmt.Errorf("openshell stop sandbox: phase %v while stopping", ph)
		}
		if err := sleepCtx(ctx, readyPoll); err != nil {
			return err
		}
	}
}

// start starts a stopped sandbox, waits until it is ready and records its processes
// again: the main process is a new one after a start.
func (s *session) start(ctx context.Context) error {
	if _, err := s.p.client.StartSandbox(ctx, connect.NewRequest(&openshellv1.StartSandboxRequest{WorkspaceScope: ws(), Name: s.b.name})); err != nil {
		return fmt.Errorf("openshell start sandbox: %w", err)
	}
	for ready := false; !ready; {
		resp, err := s.p.client.GetSandbox(ctx, connect.NewRequest(&openshellv1.GetSandboxRequest{WorkspaceScope: ws(), Name: s.b.name}))
		if err != nil {
			return fmt.Errorf("openshell get sandbox: %w", err)
		}
		switch ph := resp.Msg.GetSandbox().GetStatus().GetPhase(); ph {
		case openshellv1.SandboxPhase_SANDBOX_PHASE_READY:
			ready = true
			continue
		case openshellv1.SandboxPhase_SANDBOX_PHASE_STOPPED, openshellv1.SandboxPhase_SANDBOX_PHASE_STOPPING,
			openshellv1.SandboxPhase_SANDBOX_PHASE_STARTING, openshellv1.SandboxPhase_SANDBOX_PHASE_PROVISIONING,
			openshellv1.SandboxPhase_SANDBOX_PHASE_UNKNOWN, openshellv1.SandboxPhase_SANDBOX_PHASE_UNSPECIFIED:
		default:
			return fmt.Errorf("openshell start sandbox: phase %v instead of ready: %s", ph, conditionSummary(resp.Msg.GetSandbox()))
		}
		if err := sleepCtx(ctx, readyPoll); err != nil {
			return err
		}
	}
	s.mu.Lock()
	s.stopped = false
	s.mu.Unlock()
	return s.recordBaseline(ctx)
}

type listing struct {
	Ptrace string `json:"ptrace"`
	Procs  []struct {
		PID    int    `json:"pid"`
		PPID   int    `json:"ppid"`
		State  string `json:"state"`
		Start  string `json:"start"`
		Cmd    string `json:"cmd"`
		CmdHex string `json:"cmdHex"` // the raw command line, NUL separators included
	} `json:"procs"`
}

// recordBaseline lists the processes of a sandbox no call has touched (just created,
// or just started) and keeps them as the sandbox's own. It refuses anything but PID 1
// and one main process running the session command, and a host whose ptrace_scope is
// missing or 0: there, code in the sandbox could attach to the sweep and forge its
// exit status.
func (s *session) recordBaseline(ctx context.Context) error {
	out, err := s.p.exec(ctx, s.b, []string{"node", "-e", listScript}, nil, nil, 1<<20, maxOutputBytes)
	if err != nil {
		return fmt.Errorf("openshell session: list processes: %w", err)
	}
	if out.exitCode != 0 {
		return fmt.Errorf("openshell session: the process list exited %d: %q", out.exitCode, out.stderr)
	}
	var l listing
	if err := json.Unmarshal(out.stdout, &l); err != nil {
		return fmt.Errorf("openshell session: the process list is not JSON: %w", err)
	}
	if scope, err := strconv.Atoi(l.Ptrace); err != nil || scope < 1 {
		return fmt.Errorf("openshell session: the gateway host's kernel.yama.ptrace_scope reads %q; sessions need 1 or more, since at 0 code in the sandbox could attach to the sweep that ends each call and forge its verdict", l.Ptrace)
	}
	var keep []string
	main := 0
	for _, pr := range l.Procs {
		switch {
		case pr.PID == 1:
		case pr.PPID == 1 && pr.Cmd == strings.Join(sessionCommand, " "):
			main++
		default:
			return fmt.Errorf("openshell session: an untouched sandbox runs an unexpected process: pid %d ppid %d %q", pr.PID, pr.PPID, pr.Cmd)
		}
		keep = append(keep, strconv.Itoa(pr.PID)+":"+pr.Start+":"+pr.CmdHex)
	}
	if main != 1 || len(keep) != 2 {
		return fmt.Errorf("openshell session: an untouched sandbox runs %d processes, %d of them the main process; want PID 1 and one main process", len(keep), main)
	}
	s.mu.Lock()
	s.baseline = keep
	s.mu.Unlock()
	return nil
}

// admit is the checks a call shares before it takes its turn: no grant, the call's
// floor against the evidence measured at open, and the driver check a run makes.
func (s *session) admit(ctx context.Context, grant *sandbox.HostAPIGrant, floor sandbox.IsolationClass) error {
	if err := sandbox.CheckMinimumIsolation(s.tier, floor); err != nil {
		return err
	}
	_, err := s.p.ready(ctx, grant, floor)
	return err
}

// prepare runs with the turn held, before a call: it starts a stopped sandbox, then
// reads the sandbox and its configuration back and ends the session on any
// difference. Nothing has run when it fails.
func (s *session) prepare(ctx context.Context) error {
	s.mu.Lock()
	stopped := s.stopped
	s.mu.Unlock()
	if stopped {
		if err := s.start(ctx); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			s.finish(sandbox.SessionBoundaryFailed, "the sandbox could not be started again: "+err.Error())
			return sandbox.RefuseEndedSession(s.Err())
		}
	}
	resp, err := s.p.client.GetSandbox(ctx, connect.NewRequest(&openshellv1.GetSandboxRequest{WorkspaceScope: ws(), Name: s.b.name}))
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if connect.CodeOf(err) == connect.CodeNotFound {
			s.finish(sandbox.SessionSandboxChanged, "the sandbox no longer exists")
			return sandbox.RefuseEndedSession(s.Err())
		}
		return fmt.Errorf("openshell get sandbox: %w", err)
	}
	sb := resp.Msg.GetSandbox()
	switch ph := sb.GetStatus().GetPhase(); ph {
	case openshellv1.SandboxPhase_SANDBOX_PHASE_READY:
	case openshellv1.SandboxPhase_SANDBOX_PHASE_ERROR, openshellv1.SandboxPhase_SANDBOX_PHASE_COMPLETED:
		s.finish(sandbox.SessionMainProcessEnded, conditionSummary(sb))
		return sandbox.RefuseEndedSession(s.Err())
	default:
		s.finish(sandbox.SessionSandboxChanged, fmt.Sprintf("the sandbox is in phase %v, not ready", ph))
		return sandbox.RefuseEndedSession(s.Err())
	}
	if err := s.p.verifySandbox(sb, s.labels, sessionCommand, nil); err != nil {
		s.finish(sandbox.SessionSandboxChanged, err.Error())
		return sandbox.RefuseEndedSession(s.Err())
	}
	if err := s.p.verifyConfig(ctx, s.b.name); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		s.finish(sandbox.SessionSandboxChanged, err.Error())
		return sandbox.RefuseEndedSession(s.Err())
	}
	return nil
}

// boundary runs after every call, with the turn still held and whatever happened to
// the caller's context: the sweep, then, when it did not prove the boundary, a stop
// and start, and when that fails the end of the session. A session over its disk
// budget ends here too. It reports nothing: the session's state says what happened.
func (s *session) boundary() {
	if s.Err() != nil {
		return
	}
	ctx, cancel := context.WithTimeout(s.ctx, sweepBudget)
	s.mu.Lock()
	args := append([]string{"node", "-e", sweepScript, strconv.FormatInt(s.disk, 10), strconv.Itoa(maxDiskEntries)}, s.baseline...)
	s.mu.Unlock()
	out, err := s.p.exec(ctx, s.b, args, nil, nil, 4096, 4096)
	cancel()
	if s.Err() != nil {
		return
	}
	switch {
	case err == nil && out.exited && out.exitCode == sweepClean:
		return
	case err == nil && out.exited && out.exitCode == sweepOverBudget:
		s.finish(sandbox.SessionDiskExceeded, fmt.Sprintf("the session's files under /tmp exceed %d bytes or %d entries", s.disk, maxDiskEntries))
		return
	case err == nil && out.exited && out.exitCode == sweepUnmeasurable:
		s.finish(sandbox.SessionDiskExceeded, "a directory under /tmp could not be read, so the session's disk use cannot be measured")
		return
	}
	sweepErr := fmt.Sprintf("the sweep exited %d (err %v)", out.exitCode, err)
	// The sandbox's main process may have ended (code in the sandbox can kill it),
	// which a restart would hide rather than repair.
	rctx, rcancel := context.WithTimeout(s.ctx, stopBudget+projectMax)
	defer rcancel()
	resp, gerr := s.p.client.GetSandbox(rctx, connect.NewRequest(&openshellv1.GetSandboxRequest{WorkspaceScope: ws(), Name: s.b.name}))
	if gerr == nil {
		switch resp.Msg.GetSandbox().GetStatus().GetPhase() {
		case openshellv1.SandboxPhase_SANDBOX_PHASE_ERROR, openshellv1.SandboxPhase_SANDBOX_PHASE_COMPLETED:
			s.finish(sandbox.SessionMainProcessEnded, conditionSummary(resp.Msg.GetSandbox()))
			return
		}
	}
	slog.Warn("openshell: session sweep did not prove the call boundary; restarting the sandbox", "sandbox", s.b.name, "detail", sweepErr)
	if err := s.stop(rctx); err != nil {
		s.finish(sandbox.SessionBoundaryFailed, sweepErr+"; the recovery stop failed: "+err.Error())
		return
	}
	if err := s.start(rctx); err != nil {
		s.finish(sandbox.SessionBoundaryFailed, sweepErr+"; the recovery start failed: "+err.Error())
	}
}

// callError is what a call returns when its exec did not deliver an exit status: a
// session that ended during the call (its lifetime passed, or it was closed) is
// reported as that end. Execution may have happened, so it is not marked
// not-dispatched.
func (s *session) callError(runCtx context.Context, err error) error {
	if end := s.Err(); end != nil {
		return end
	}
	if ctxErr := deadline.Expired(runCtx); ctxErr != nil {
		return ctxErr
	}
	return err
}

// RunJavaScript runs req.Code with `node -` in the session's sandbox.
func (s *session) RunJavaScript(ctx context.Context, req sandbox.Request) (sandbox.Result, error) {
	fail := sandbox.Result{Sandbox: Name, Isolation: s.tier}
	if err := sandbox.ValidateRequest(req); err != nil {
		return fail, err
	}
	if err := req.Software.Check(""); err != nil {
		return fail, err
	}
	timeout := clampTimeout(req.Timeout, snippetDefault, snippetMax)
	if err := s.admit(ctx, req.Grant, req.MinimumIsolation); err != nil {
		return fail, err
	}
	if err := s.acquire(ctx); err != nil {
		return fail, err
	}
	defer s.release()
	if err := s.prepare(ctx); err != nil {
		return fail, err
	}
	defer s.boundary()
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()
	code, env := req.Code, map[string]string(nil)
	var g *grantRun
	if req.Grant != nil {
		// A call's grant lives for the call: its relay is one of the call's processes,
		// and the sweep after the call ends it like any other.
		var err error
		if g, err = s.p.startGrant(runCtx, s.b, req.Grant, timeout); err != nil {
			return fail, s.callError(runCtx, err)
		}
		defer g.Close()
		code, env = sandbox.HostClientSnippet(req.Code, req.Grant), g.env()
	}
	start := time.Now()
	out, err := s.p.exec(runCtx, s.b, []string{"node", "-"}, env, []byte(code), maxOutputBytes, maxOutputBytes)
	res := sandbox.Result{
		Stdout:          string(out.stdout),
		Stderr:          string(out.stderr),
		StdoutTruncated: out.stdoutTruncated,
		StderrTruncated: out.stderrTruncated,
		ExitCode:        out.exitCode,
		Duration:        time.Since(start),
		Sandbox:         Name,
		Isolation:       s.tier,
	}
	if g != nil {
		res.CallTrace = g.broker.Trace()
	}
	if out.exited {
		return res, nil
	}
	if deadline.Expired(runCtx) == context.DeadlineExceeded && s.Err() == nil {
		// The call's own deadline: its process group is killed, and the sweep that
		// follows kills anything that detached.
		res.TimedOut, res.ExitCode = true, 124
		return res, nil
	}
	// The brokered calls happened whatever became of the exec stream.
	fail.CallTrace = res.CallTrace
	return fail, s.callError(runCtx, err)
}

// RunProject writes the files and runs the steps through /runner.mjs in the session's
// sandbox. The work directory is under /tmp, so files persist to the next call.
func (s *session) RunProject(ctx context.Context, req sandbox.ProjectRequest) (sandbox.ProjectResult, error) {
	fail := sandbox.ProjectResult{Sandbox: Name, Isolation: s.tier}
	if err := sandbox.ValidateProjectRequest(req); err != nil {
		return fail, err
	}
	if err := req.Software.Check(""); err != nil {
		return fail, err
	}
	timeout := clampTimeout(req.Timeout, projectDefault, projectMax)
	key, err := runnerwire.NewKey()
	if err != nil {
		return fail, err
	}
	plan := runnerwire.Plan{Steps: req.Steps, StepTimeout: timeout, Artifacts: req.Artifacts, HostSDK: sandbox.HostClientModule(req.Grant), ReportKey: key}
	for _, f := range req.Files {
		plan.Files = append(plan.Files, runnerwire.File(f))
	}
	planJSON, err := plan.Encode()
	if err != nil {
		return fail, err
	}
	if err := s.admit(ctx, req.Grant, req.MinimumIsolation); err != nil {
		return fail, err
	}
	if err := s.acquire(ctx); err != nil {
		return fail, err
	}
	defer s.release()
	if err := s.prepare(ctx); err != nil {
		return fail, err
	}
	defer s.boundary()
	runCtx, cancel := context.WithTimeout(ctx, timeout+runnerGrace)
	defer cancel()
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()
	var g *grantRun
	if req.Grant != nil {
		if g, err = s.p.startGrant(runCtx, s.b, req.Grant, timeout+runnerGrace); err != nil {
			return fail, s.callError(runCtx, err)
		}
		defer g.Close()
	}
	res, err := s.p.runPlan(runCtx, s.b, s.tier, planJSON, key, g)
	if g != nil {
		res.CallTrace = g.broker.Trace()
	}
	// The brokered calls happened whatever became of the run.
	fail.CallTrace = res.CallTrace
	if err != nil {
		return fail, s.callError(runCtx, err)
	}
	if res.Outcome == sandbox.ProjectOutcomeTimedOut && s.Err() != nil {
		// The session ended under the call, not the call's own budget.
		return fail, s.Err()
	}
	return res, nil
}
