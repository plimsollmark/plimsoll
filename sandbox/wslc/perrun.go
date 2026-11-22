package wslc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandbox/internal/providerkit"
)

// The per-run mode (SANDBOX_WSLC_MODE=per-run) gives every run a WSLC session of its
// own: one Hyper-V VM with its own Linux kernel, dockerd and storage disk, started for
// the run and deleted after it. Driven, as measured on a real WSLC session,
// through two Microsoft programs already on the machine, wslc.exe and powershell.exe:
//
//  1. copy the template disk to a fresh directory named like the session
//     (powershell.exe Copy-Item: Windows to Windows, 0.36 s for 1 GB where the drive
//     mount takes about 9 s);
//  2. start the holder, `wslc system session enter DIR --name NAME`, with its input a
//     pipe: the session lives while the holder does;
//  3. wait until the name is listed (listed is not booted: the VM boots during the first
//     command, here the boot ID read);
//  4. read the session VM's boot ID, refuse one seen before, and run the container with
//     `wslc --session NAME container run` and runArgv's flags;
//  5. write the fixed exit line to the holder's input and close it, wait until the holder
//     has exited and the name is gone, and delete the directory. When that does not work,
//     or the run ended abnormally, the give-up path terminates the session by name
//     (`wslc --session NAME system session terminate`) and also every listed session with
//     this provider's prefix that no live run holds.
//
// `session enter` is not in Microsoft's published documentation and can change in any WSL
// release. A killed holder leaves its session listed and its VM running until WSLC's idle
// timeout, so the smoke test sweeps such sessions and their directories at
// startup. The holder's input is a root shell in the run's VM: nothing but
// holderExitLine is ever written to it (holder.closeInput, the one writer).

// SessionPrefix starts the name of every session this provider creates, and of its
// directory under the run root. A sweep ends a listed session named with it only when its
// directory is under this provider's own run root (sweep), and a run root is locked to one
// process (lockRoot), so two per-run plimsollds on one machine need a run root each.
const SessionPrefix = "plimsoll-run-"

const (
	templateDirName = "plimsoll-template"
	storageFile     = "storage.vhdx"
	// holderExitLine is the one thing ever written to a holder's input.
	holderExitLine = "exit\n"
	// seenBootIDsCap bounds the boot IDs remembered to refuse a reused VM.
	seenBootIDsCap = 1 << 16
	// gvisorRegisterTimeout bounds one VM's settings write, reload and read-back (0.07 s
	// measured in a trial of gVisor in a WSLC session, plus the 5 s the script itself waits for the reload).
	gvisorRegisterTimeout = 60 * time.Second
)

// SharedQualification is the sentence that goes with the shared mode's tier on every
// surface that states it.
const SharedQualification = "One WSLC session VM shared by every run (a container per run in the caller's default session). Microsoft states that WSL is not a security sandbox for running untrusted code; the wall between two runs is runc's, and this mode is weaker than plimsoll's docker provider under runc."

// perRunFacts is what both of the per-run mode's sentences state about its wall.
const perRunFacts = "Hyper-V VM per run (one WSLC session per run). Microsoft states that WSL is not a security sandbox for running untrusted code; the VM wall is Hyper-V's, and the Windows components around it (network relay, shares, interop) run with the user's rights."

// PerRunQualification is the sentence that goes with the per-run mode's tier, container,
// on every surface that states it, when the operator has not set
// SANDBOX_WSLC_ACCEPT_VM_TIER=1.
const PerRunQualification = "Reported as container: " + perRunFacts + " An operator who accepts that statement sets SANDBOX_WSLC_ACCEPT_VM_TIER=1 and this mode then reports vm."

// PerRunAcceptedQualification is the sentence that goes with the per-run mode's tier, vm,
// when the operator has set SANDBOX_WSLC_ACCEPT_VM_TIER=1.
const PerRunAcceptedQualification = perRunFacts + " The operator of this daemon set SANDBOX_WSLC_ACCEPT_VM_TIER=1."

var (
	sessionNameRE = regexp.MustCompile(`^` + SessionPrefix + `[0-9a-f]{16}$`)
	// ownEntryRE is every name this provider creates under the run root besides the
	// template: a run's directory and a template build's image archive.
	ownEntryRE = regexp.MustCompile(`^` + SessionPrefix + `[0-9a-f]{16}(\.tar)?$`)
	bootIDRE   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

func newSessionName() string { return SessionPrefix + providerkit.RandHex(8) }

// runRoot is the directory that holds the template and the run disks, both ways.
type runRoot struct{ linux, win string }

// holder is one session's `wslc system session enter` process.
type holder struct {
	name   string
	dir    string // the storage directory as this distribution mounts it
	winDir string // the same directory as wslc.exe takes it
	cmd    *exec.Cmd
	// in is the holder's input: a root shell in the session VM. Only startHolder sets it
	// and only closeInput writes to it (TestHolderInputHasOneWriter).
	in        io.WriteCloser
	out       *syncBuffer // the holder's own output (a prompt), never a caller's
	exited    chan struct{}
	closeOnce sync.Once
	slot      bool // it holds a place in Provider.alive
	// forced is set when endSession ended the session by terminate (the give-up path),
	// not at its exit line: the template build refuses such a store.
	forced bool
}

// syncBuffer is a providerkit.Capture read while a process writes to it.
type syncBuffer struct {
	mu sync.Mutex
	b  providerkit.Capture
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// closeInput writes the fixed exit line and closes the holder's input, once.
func (h *holder) closeInput() {
	h.closeOnce.Do(func() {
		if h.in == nil {
			return
		}
		_, _ = io.WriteString(h.in, holderExitLine)
		_ = h.in.Close()
	})
}

// dead reports whether the holder process has exited.
func (h *holder) dead() bool {
	if h.exited == nil {
		return true
	}
	select {
	case <-h.exited:
		return true
	default:
		return false
	}
}

func (h *holder) waitExited(d time.Duration) bool {
	if h.exited == nil {
		return true
	}
	select {
	case <-h.exited:
		return true
	case <-time.After(d):
		return false
	}
}

// perRunState is the per-run mode's state, kept on the Provider.
type perRunState struct {
	mu       sync.Mutex
	root     runRoot
	template string // the template's storage.vhdx as wslc.exe takes it; "" until built
	running  int
	live     map[string]*holder
	seen     map[string]struct{}
	order    []string
	// alive bounds the sessions that exist at once, from the copy to the deleted
	// directory: a run waits (on its context) for a teardown to finish.
	alive     chan struct{}
	teardowns sync.WaitGroup
	// abandon makes teardown do nothing, as if plimsolld had died (live tests only).
	abandon bool
	// skipGVisorWrite makes the per-run gVisor check read the default runtime back without
	// writing the settings or reloading dockerd: a session whose settings were never
	// rewritten, which the check must refuse (live tests only).
	skipGVisorWrite bool
}

// seenBootID records id and reports whether it was seen before.
func (s *perRunState) seenBootID(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.seen[id]; ok {
		return true
	}
	s.seen[id] = struct{}{}
	s.order = append(s.order, id)
	if len(s.order) > seenBootIDsCap {
		delete(s.seen, s.order[0])
		s.order = s.order[1:]
	}
	return false
}

// admitRun counts a run against SANDBOX_WSLC_MAX_SESSIONS, refusing it (not dispatched,
// capacity) beyond the cap; release undoes it.
func (p *Provider) admitRun() (release func(), err error) {
	s := p.pr
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running >= p.cfg.MaxSessions {
		return nil, sandbox.NotDispatched(sandbox.RefusalCapacity,
			fmt.Errorf("wslc: %d per-run sessions are already running, the most SANDBOX_WSLC_MAX_SESSIONS allows", s.running))
	}
	s.running++
	return func() {
		s.mu.Lock()
		s.running--
		s.mu.Unlock()
	}, nil
}

// takeSlot waits, on ctx, until fewer than the cap of sessions exist.
func (p *Provider) takeSlot(ctx context.Context) error {
	select {
	case p.pr.alive <- struct{}{}:
		return nil
	case <-ctx.Done():
		return sandbox.NotDispatched(sandbox.RefusalCapacity, fmt.Errorf("wslc: waiting for a session to end: %w", ctx.Err()))
	}
}

func (p *Provider) releaseSlot() { <-p.pr.alive }

// newHolder names a session and its directory under the root, and registers it as live
// at once: the directory exists from the template copy on, before any process does, and a
// concurrent run's give-up sweep must spare it (it spares what is live).
func (p *Provider) newHolder() *holder {
	name := newSessionName()
	h := &holder{name: name, dir: path.Join(p.pr.root.linux, name), winDir: p.pr.root.win + "/" + name}
	p.pr.mu.Lock()
	p.pr.live[name] = h
	p.pr.mu.Unlock()
	return h
}

// copyTemplate copies the template disk into a new directory for h. New-Item without
// -Force fails if the directory exists, so a run never starts on an older disk.
func (p *Provider) copyTemplate(ctx context.Context, h *holder) error {
	p.pr.mu.Lock()
	tpl := p.pr.template
	p.pr.mu.Unlock()
	if tpl == "" {
		return errors.New("wslc: no template disk")
	}
	_, err := p.powershell(ctx, fmt.Sprintf("New-Item -ItemType Directory -Path %s | Out-Null; Copy-Item -LiteralPath %s -Destination %s",
		psQuote(h.winDir), psQuote(tpl), psQuote(h.winDir+"/"+storageFile)))
	return err
}

// startHolder starts h's `session enter` and registers it as live. Its context is not a
// run's: a cancelled run must not kill the holder, which would orphan the session.
func (p *Provider) startHolder(h *holder) error {
	cmd := hostCommand(context.Background(), p.cfg.Path, "system", "session", "enter", h.winDir, "--name", h.name)
	in, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	h.out = &syncBuffer{b: providerkit.Capture{Limit: errorCap}}
	cmd.Stdout, cmd.Stderr = h.out, h.out
	cmd.WaitDelay = 5 * time.Second
	if err := cmd.Start(); err != nil {
		return err
	}
	h.cmd, h.in, h.exited = cmd, in, make(chan struct{})
	p.pr.mu.Lock()
	p.pr.live[h.name] = h
	p.pr.mu.Unlock()
	go func() {
		_ = cmd.Wait()
		close(h.exited)
	}()
	return nil
}

// listSessions is every session wslc lists, by name (`wslc system info --format json`).
func (p *Provider) listSessions(ctx context.Context) ([]string, error) {
	out, err := p.output(ctx, "system", "info", "--format", "json")
	if err != nil {
		return nil, err
	}
	var info struct {
		Server struct {
			Sessions []struct{ Name string }
		}
	}
	if err := json.Unmarshal(out, &info); err != nil {
		return nil, fmt.Errorf("wslc system info: unreadable answer: %w", err)
	}
	names := make([]string, 0, len(info.Server.Sessions))
	for _, s := range info.Server.Sessions {
		names = append(names, s.Name)
	}
	return names, nil
}

// waitListed polls until h's session is listed, refusing when the holder exits first.
func (p *Provider) waitListed(ctx context.Context, h *holder) error {
	deadline := time.Now().Add(p.listTimeout)
	for {
		lctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		names, err := p.listSessions(lctx)
		cancel()
		if err == nil && slices.Contains(names, h.name) {
			return nil
		}
		if h.dead() {
			return fmt.Errorf("wslc: the holder of %s exited before the session was listed: %s", h.name, strings.TrimSpace(h.out.String()))
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("wslc: %s was not listed within %v (last list: %v)", h.name, p.listTimeout, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(p.listPoll):
		}
	}
}

// waitGone polls until name is not listed (and, with h, its holder has exited).
func (p *Provider) waitGone(name string, h *holder, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		names, err := p.listSessions(ctx)
		cancel()
		if err == nil && !slices.Contains(names, name) && (h == nil || h.dead()) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(p.listPoll)
	}
}

// terminate ends a session by name; an error is logged by the caller.
func (p *Provider) terminate(name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_, err := p.output(ctx, "--session", name, "system", "session", "terminate")
	return err
}

// removeOwn deletes a directory or file this provider created under the run root, and
// nothing else: its name must be a session's, an archive's or the template's. A disk the
// ended VM has not released yet refuses the delete for a moment, so it tries a few times.
func (p *Provider) removeOwn(linux string) error {
	if path.Dir(linux) != p.pr.root.linux || !(ownEntryRE.MatchString(path.Base(linux)) || path.Base(linux) == templateDirName) {
		return fmt.Errorf("wslc: refusing to delete %s: not a name this provider creates under %s", linux, p.pr.root.linux)
	}
	var err error
	for try := 0; try < p.removeTries*4; try++ {
		if try > 0 {
			time.Sleep(p.removePause)
		}
		if err = os.RemoveAll(linux); err == nil {
			return nil
		}
	}
	return err
}

// endSession ends h's session and deletes its directory (unless keepDir), then gives back
// its place. polite sends the exit line and waits; the give-up path (not polite, or the
// polite end did not finish) terminates the session by name, and every orphan with this
// provider's prefix too. It returns what is left, if anything.
func (p *Provider) endSession(h *holder, polite, keepDir bool) error {
	s := p.pr
	s.mu.Lock()
	abandon := s.abandon
	s.mu.Unlock()
	if abandon {
		return nil
	}
	defer func() {
		if h.slot {
			h.slot = false
			p.releaseSlot()
		}
	}()
	gone := h.cmd == nil // no holder was started: nothing to end
	if !gone && polite && !h.dead() {
		h.closeInput()
		gone = p.waitGone(h.name, h, p.teardownTimeout)
	}
	gaveUp := !gone
	if gaveUp {
		h.forced = true
		if err := p.terminate(h.name); err != nil {
			slog.Warn("wslc: session terminate failed", "session", h.name, "err", err)
		}
		gone = p.waitGone(h.name, nil, 30*time.Second)
		h.closeInput()
		if !h.waitExited(10*time.Second) && h.cmd != nil && h.cmd.Process != nil {
			_ = h.cmd.Process.Kill()
			h.waitExited(10 * time.Second)
		}
	}
	var errs []error
	if !gone {
		errs = append(errs, fmt.Errorf("wslc: session %s is still listed after its teardown", h.name))
	}
	if !keepDir {
		if err := p.removeOwn(h.dir); err != nil {
			errs = append(errs, fmt.Errorf("wslc: deleting %s: %w", h.dir, err))
		}
	}
	if gaveUp {
		// h is still live here, so the sweep spares its directory (kept for a template).
		_, sweepErr := p.sweep(false)
		errs = append(errs, sweepErr)
	}
	s.mu.Lock()
	delete(s.live, h.name)
	s.mu.Unlock()
	return errors.Join(errs...)
}

// endSessionLater ends h's session in the background, so a run's result does not wait for
// its teardown (about 1 s: measured on a real WSLC session, 0.73 s to end and 0.34 s to delete).
func (p *Provider) endSessionLater(h *holder, polite bool) {
	p.pr.teardowns.Add(1)
	go func() {
		defer p.pr.teardowns.Done()
		if err := p.endSession(h, polite, false); err != nil {
			slog.Error("wslc: a per-run session was not fully torn down; the next startup sweep removes it", "session", h.name, "err", err)
		}
	}()
}

// drain waits for every background teardown.
func (p *Provider) drain() {
	if p.pr != nil {
		p.pr.teardowns.Wait()
	}
}

// Drain waits, until ctx ends, for the teardowns the daemon's shutdown would otherwise cut
// off: a session whose VM is still up when plimsolld exits waits for the next startup's
// sweep. The shared mode has none.
func (p *Provider) Drain(ctx context.Context) error {
	if p.pr == nil {
		return nil
	}
	done := make(chan struct{})
	go func() { p.pr.teardowns.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("wslc: per-run sessions are still being torn down: %w", ctx.Err())
	}
}

// ReconcileOrphans terminates the listed sessions with this provider's prefix that no live
// run holds, and deletes their directories, as the startup sweep does for a dead
// plimsolld's; it returns how many sessions it ended. Until the smoke test has placed the
// template it does nothing: the smoke test sweeps for itself, and the template build's
// directory is no live run's between its session's end and its rename to the template's
// name, so a sweep then would delete it.
func (p *Provider) ReconcileOrphans(context.Context) (int, error) {
	if p.pr == nil {
		return 0, nil
	}
	p.pr.mu.Lock()
	ready := p.pr.root.linux != "" && p.pr.template != ""
	p.pr.mu.Unlock()
	if !ready {
		return 0, nil
	}
	return p.sweep(false)
}

// sweep terminates every listed session with this provider's prefix whose directory is under
// this provider's run root, and deletes every entry it created there. At startup (all) that
// is everything of its own; on a run's give-up path it spares what a live run holds. A
// session of another provider (the same prefix, a directory under another run root) is never
// touched, and lockRoot keeps two processes from sharing one run root.
func (p *Provider) sweep(all bool) (int, error) {
	s := p.pr
	liveNow := func(name string) bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		_, ok := s.live[name]
		return ok
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	names, err := p.listSessions(ctx)
	cancel()
	if err != nil {
		return 0, fmt.Errorf("wslc: sweep: %w", err)
	}
	var errs []error
	var ended []string
	for _, n := range names {
		if !sessionNameRE.MatchString(n) || (!all && liveNow(n)) {
			continue
		}
		// A session is this provider's only if its directory is under this provider's run
		// root: every session is started from a directory made there first and outlives it
		// never (the directory goes after the session). A name with the prefix and no
		// directory here is another provider's run on this machine (another daemon, with its
		// own run root), and ending it would refuse that run with "Session not found".
		if _, err := os.Stat(path.Join(s.root.linux, n)); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, fmt.Errorf("wslc: sweep: %w", err))
			}
			continue
		}
		if err := p.terminate(n); err != nil {
			errs = append(errs, fmt.Errorf("wslc: sweep: terminating %s: %w", n, err))
		}
		ended = append(ended, n)
	}
	for _, n := range ended {
		if !p.waitGone(n, nil, 30*time.Second) {
			errs = append(errs, fmt.Errorf("wslc: sweep: %s is still listed after terminate", n))
		}
	}
	entries, err := os.ReadDir(s.root.linux)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, fmt.Errorf("wslc: sweep: %w", err))
	}
	for _, e := range entries {
		name := e.Name()
		own := ownEntryRE.MatchString(name)
		if !own && !(all && name == templateDirName) {
			continue
		}
		if own && !all && liveNow(strings.TrimSuffix(name, ".tar")) {
			continue
		}
		if err := p.removeOwn(path.Join(s.root.linux, name)); err != nil {
			errs = append(errs, fmt.Errorf("wslc: sweep: %w", err))
		}
	}
	if len(ended) > 0 {
		slog.Warn("wslc: swept per-run sessions no live run held", "sessions", ended)
	}
	return len(ended), errors.Join(errs...)
}

// openRunSession takes a place, copies the template, starts the holder, waits until the
// session is listed, and reads the session VM's boot ID, refusing one seen before. Every
// failure ran no guest code: it is marked not dispatched, and what was started is torn
// down.
func (p *Provider) openRunSession(ctx context.Context) (*holder, string, error) {
	if err := p.takeSlot(ctx); err != nil {
		return nil, "", err
	}
	h := p.newHolder()
	h.slot = true
	fail := func(err error) (*holder, string, error) {
		if tErr := p.endSession(h, false, false); tErr != nil {
			slog.Error("wslc: a per-run session that failed to start was not fully torn down", "session", h.name, "err", tErr)
		}
		reason := sandbox.RefusalEnvironment
		if ctx.Err() != nil {
			reason = sandbox.RefusalCapacity
		}
		return nil, "", sandbox.NotDispatched(reason, err)
	}
	if err := p.copyTemplate(ctx, h); err != nil {
		return fail(fmt.Errorf("wslc: copying the template disk: %w", err))
	}
	if err := p.startHolder(h); err != nil {
		return fail(fmt.Errorf("wslc: starting the session holder: %w", err))
	}
	if err := p.waitListed(ctx, h); err != nil {
		return fail(err)
	}
	// The first command boots the VM; reading the boot ID is that command.
	bctx, cancel := context.WithTimeout(ctx, p.cfg.StartAllowance)
	boot, err := p.sessionRead(bctx, h.name, "cat", "/proc/sys/kernel/random/boot_id")
	cancel()
	switch {
	case err != nil:
		return fail(fmt.Errorf("wslc: reading the run's session VM boot ID: %w", err))
	case !bootIDRE.MatchString(boot):
		return fail(fmt.Errorf("wslc: the run's session VM answered boot ID %q", boot))
	case p.pr.seenBootID(boot):
		return fail(fmt.Errorf("wslc: the run's session VM has boot ID %s, seen before: not a fresh VM", boot))
	}
	if p.cfg.GVisor {
		// WSLC rewrites the docker settings at every boot, so this VM is under runc until
		// the settings are written and read back. No branch below starts a container unless
		// the read-back says runsc, and none starts one under another runtime.
		gctx, gcancel := context.WithTimeout(ctx, gvisorRegisterTimeout)
		err := p.registerGVisor(gctx, h.name)
		gcancel()
		if err != nil {
			// A session exists only while its holder does, so say which of the two went first.
			if h.dead() {
				err = fmt.Errorf("%w; the session's holder had exited, printing %q", err, strings.TrimSpace(h.out.String()))
			} else {
				err = fmt.Errorf("%w; the session's holder was still running", err)
			}
			return fail(err)
		}
	}
	return h, boot, nil
}
