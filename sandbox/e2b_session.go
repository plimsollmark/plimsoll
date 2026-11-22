package sandbox

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox/internal/deadline"
	"github.com/plimsollmark/plimsoll/sandbox/internal/providerkit"
	"github.com/plimsollmark/plimsoll/sandbox/internal/sessionkit"
)

// E2B sessions keep one microVM for many calls (SessionProvider). Every call is a
// process envd starts in it, and after every call the shared sweep
// (sandbox/internal/sessionkit) kills every process the call left behind. What is
// particular to E2B:
//
//   - Inside the microVM, E2B's template gives its default user passwordless sudo,
//     leaves root's and that user's passwords empty and runs an sshd that accepts root
//     and empty passwords: code there can become root, and root code could forge the
//     sweep's verdict. So the session's code runs as a uid no account has, through
//     setpriv with no-new-privs (no setuid program gives root back), and plimsoll's
//     own programs (the process lister, the sweep, the identity check) run as root,
//     where the guest cannot signal, attach to or replace them. Before any guest code,
//     the open locks every empty password and stops sshd, then proves from the guest
//     that sudo, su and an ssh login to root all fail (e2b_session.js).
//   - The template is the operator's machine image, not plimsoll's, and the work
//     folder carries no no-execute mark, so nothing stops a file the session wrote
//     from being loaded by a program that goes looking for one. So every program of
//     plimsoll's here (the open, the stager, the lister, the sweep, the identity check,
//     the relays, the artifact reader, the launcher, and the setpriv that drops to the
//     guest) starts in /, which the session cannot write (a library search folder
//     given relatively is then a folder of the root), under
//     sessionkit.ControlArgvClosed: an empty environment (envd hands every process
//     PATH, HOME, USER, LOGNAME, the sandbox's environment variables and the request's,
//     none of which passes /usr/bin/env -i), an empty OpenSSL settings file, and the
//     program by the full path the open found for it on the root before any of the
//     session's code ran (e2b_session.js pin), never by a search. The guest's own
//     processes get envd's environment as the open read it (guestEnv), handed to them
//     explicitly, and change into the work folder themselves. What plimsoll does not
//     check: a template that replaces the system files these programs load (a library,
//     the loader's settings, /etc/ld.so.preload), or sets a variable that loads code
//     into /bin/sh and /usr/bin/env before -i clears it. That is the operator's.
//   - envd writes files as root and may follow a link the guest planted, so a call's
//     files reach the guest through a root-only staging directory and a root program
//     that becomes the guest before writing them; a relay starts as root and drops to
//     the guest the same way, which leaves it non-dumpable, out of the guest's reach.
//   - A microVM runs an init and system services, so the sweep's baseline is every
//     process of the untouched machine (sessionkit.BaselineAll).
//   - A suspend is E2B's pause: memory, files and processes kept, compute billing
//     stopped, every connection into the machine cut. The relays' streams are among
//     them, so a pause forgets the interpreters and a resume sweeps them away; the
//     next cell starts a fresh one and says so.
//   - Anyone holding the API key can change a sandbox, so the control plane's record of
//     it (state, template, resources, metadata, network, lifecycle) is read back before
//     every call and compared with what it was at open.
//   - A paused sandbox never expires on E2B, so every session sandbox declares its
//     expiry in its metadata, and ReconcileOrphans of any instance deletes one past it.

//go:embed e2b_session.js
var e2bSessionJS string

const (
	// e2bSessionWork is the working directory of every call, the guest's own.
	e2bSessionWork = "/work"
	// e2bSessionStage is where a call's files wait for the stager: root's only.
	e2bSessionStage = "/var/lib/plimsoll-stage"
	// e2bSessionOwn holds the directory of the call in progress: its snippet or step
	// scripts, written as the guest.
	e2bSessionOwn = "/tmp/.plimsoll-call"
	// e2bDefaultGuestUID is the uid and gid a session's code runs as by default:
	// docker's default, a uid no account uses.
	e2bDefaultGuestUID = 61000
	// e2bSessionMargin is how long the microVM's own timeout runs past the session's
	// lifetime: the backstop if the delete at the session's end never lands.
	e2bSessionMargin = time.Minute
	// e2bPauseBudget and e2bResumeBudget bound a suspend and a resume (a pause takes
	// about 4 s per GiB of memory, a resume about 1 s, by E2B's documentation).
	e2bPauseBudget  = 60 * time.Second
	e2bResumeBudget = 60 * time.Second
	// e2bAttachBudget bounds a relay's start, until envd names its PID.
	e2bAttachBudget = 30 * time.Second
	// e2bInputChunk bounds one SendInput.
	e2bInputChunk = 1 << 20
	// e2bRootUser is who envd starts plimsoll's own programs as.
	e2bRootUser = "root"
	// e2bControlDir is the working folder envd starts every process of a session in:
	// the root, which the session cannot write. A guest process changes into the work
	// folder itself (e2bGuestStart), as the guest.
	e2bControlDir = "/"
	// e2bEnv is the first program of every command (sessionkit.ControlArgv names it);
	// the open checks it is the root's own.
	e2bEnv = "/usr/bin/env"
	// e2bGuestStart, run by the pinned sh as the guest, changes into its first argument
	// and execs the rest, so the process keeps its PID.
	e2bGuestStart = `cd "$1" || exit 125; shift; exec "$@"`
)

// A pause's budget is held under SuspendBound, which a session layer's suspend budget is
// derived from: a larger number here does not compile.
const _ = uint64(SuspendBound - e2bPauseBudget)

// e2bRequiredBins are the programs the open must find on the root: every later start
// names them by the path it found (e2b_session.js pin). python3 is pinned where the
// machine has it.
var e2bRequiredBins = []string{"node", "sh", "setpriv"}

// e2bEnvName is an environment variable's name as the guest's environment may carry it.
var e2bEnvName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// e2bEnvDropped are names in envd's environment that describe the process that read it,
// or that a guest process gets from plimsoll instead (HOME, the work folder).
var e2bEnvDropped = map[string]bool{"HOME": true, "PWD": true, "OLDPWD": true, "SHLVL": true, "_": true}

// e2bSessionDirs are the directories the guest can write, which the sweep measures
// against the session's disk budget by walking them.
var e2bSessionDirs = []string{e2bSessionWork, "/tmp", "/var/tmp", "/dev/shm"}

// errE2BDraining is an open refused because Drain has begun.
var errE2BDraining = fmt.Errorf("%w: the e2b provider is shutting down", ErrAtCapacity)

// SupportsSessions reports that E2B keeps sessions: the conformance suite passes
// against the live service (make e2b-session-live). On a template whose node is too old
// for sessionkit.NodeSignalFlag every open is refused, with words that say so
// (e2bSessionNodeRefused), and on one with no node outside /usr/local (E2B's base) too
// (e2bSessionNoNode); a daemon with sessions on fails its startup session smoke
// test there rather than state sessions it cannot open.
func (e *E2B) SupportsSessions() bool { return true }

// SessionEnvironments is the runs' environments: one template runs every payload kind.
func (e *E2B) SessionEnvironments() Environments { return e.Environments() }

func (e *E2B) guestUID() int {
	if e.GuestUID > 0 {
		return e.GuestUID
	}
	return e2bDefaultGuestUID
}

// e2bSession is one open session.
type e2bSession struct {
	e      *E2B
	uid    int // the guest's uid and gid
	tier   IsolationClass
	opened e2bRecord // the control plane's record of the sandbox at open
	life   *sessionkit.Life
	grants e2bGrantChannel
	routes *RouteBudget // route caps span the session's granted calls
	// bins is each program plimsoll starts here, by the path the open found it at;
	// guestEnv is envd's environment as the open read it, NAME=value, which every guest
	// process is handed. Both are set before any of the session's code runs.
	bins     map[string]string
	guestEnv []string
	// usrLocal is what the open's closing of /usr/local did (e2b_session.js,
	// closeUsrLocal): the entries it checked, how many it changed, and how long it took.
	usrLocal e2bUsrLocal
	// billEnd is the latest end of E2B's own lifetime for the sandbox (its timeout, set
	// at create and at each resume; Unix nanoseconds): past it the sandbox bills no
	// compute. billsUntil is billEnd once a delete has given up, else 0.
	billEnd, billsUntil atomic.Int64

	mu sync.Mutex
	vm e2bVM // its tokens are replaced if a resume answers with others
}

var _ Session = (*e2bSession)(nil)

func (s *e2bSession) machine() e2bVM {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.vm
}

// OpenSession creates the session's microVM, its lifetime declared on it, then, before
// any of the session's code: verifies its record (deny-all network, no auto-resume),
// makes it one where the guest cannot become root (e2b_session.js open), and records
// its processes, which every sweep spares.
func (e *E2B) OpenSession(ctx context.Context, opts SessionOptions) (Session, error) {
	if opts.Lifetime <= 0 {
		return nil, NotDispatched(RefusalRequest, fmt.Errorf("%w: a session needs a positive lifetime", ErrInvalidRequest))
	}
	if err := e.admit(opts.MinimumIsolation, SoftwareRule{}); err != nil {
		return nil, err
	}
	// A template the startup check found unable to hold a session is refused before a
	// sandbox is made for it (and billed): the open would fail there. The check read the
	// node a session's own programs use (the closed PATH's, e2bSessionNode), not the
	// steps' node: none there is the open's own refusal (e2bSessionNoNode), one too old
	// for the flag is e2bSessionNodeRefused. What the check could not tell, the open finds.
	switch n := e.smokeSessionNode(); {
	case !n.read:
	case n.version == "":
		return nil, e2bSessionNoNode()
	case sessionkit.CheckNodeVersion(n.version) != nil:
		return nil, e2bSessionNodeRefused("the startup check read node's version " + truncateForError(n.version) + " from the node a session's programs use")
	}
	// No pool, so a warm-only open finds nothing and makes nothing: it must never make a
	// billed sandbox.
	if opts.WarmOnly {
		return nil, RefuseNoWarmSandbox()
	}
	// E2B has no pool, so a language hint changes nothing here; it is still checked,
	// so a hint is refused alike on every provider.
	if _, err := SessionLanguages(opts.Languages, e.SessionEnvironments().Project.Languages); err != nil {
		return nil, err
	}
	leave, ok := e.sessions.Enter()
	if !ok {
		return nil, NotDispatched(RefusalCapacity, errE2BDraining)
	}
	defer leave()
	// The lifetime runs from the open's start; the declared expiry is rounded up, so a
	// reaper never finds the session past it while it lives.
	expires := time.Now().Add(opts.Lifetime)
	md := map[string]string{"session": "1", "expires": strconv.FormatInt(expires.Unix()+1, 10)}
	grants, err := e.grantChannel()
	if err != nil {
		return nil, err
	}
	vm, err := e.create(ctx, opts.Lifetime+e2bSessionMargin, e2bCreate{metadata: md, guard: grants.guard()})
	if err != nil {
		grants.close()
		return nil, err
	}
	s := &e2bSession{e: e, vm: vm, uid: e.guestUID(), tier: e.IsolationClass(), grants: grants, routes: NewRouteBudget()}
	// What the create asked E2B for, not a shorter sum of its own: the create's
	// timeout carries ten seconds more than the lifetime and the margin, and a leaked
	// sandbox bills until it (round-4 review, 2026-10-08).
	s.billEnd.Store(vm.billEnd.UnixNano())
	s.life = sessionkit.NewLife(vm.id, s.hooks())
	if err := s.setUp(ctx, md); err != nil {
		s.abandon(ctx)
		return nil, err
	}
	// Once Drain has begun the session is refused and its sandbox deleted, which Drain
	// waits for.
	if !s.life.Activate(&e.sessions, expires, opts.DiskBytes) {
		s.abandon(ctx)
		return nil, NotDispatched(RefusalCapacity, errE2BDraining)
	}
	return s, nil
}

// abandon gives up a session that failed to open: its grant channel and its sandbox.
// The delete runs before the open returns, under the open's context, so a delete that
// gives up reaches the caller's watch (WatchTeardownUntil) with the time the sandbox
// may bill until: a failed open has no session left to report it (round-3 review: the
// delete ran in the background and its failure reached no meter).
func (s *e2bSession) abandon(ctx context.Context) {
	s.life.Abandon()
	s.grants.close()
	wctx, gaveUp := WatchTeardown(ctx)
	s.e.kill(wctx, s.machine())
	if gaveUp() {
		TeardownGaveUpUntil(ctx, time.Unix(0, s.billEnd.Load()))
	}
}

// BillsUntil is when E2B's own lifetime for the sandbox ends if its delete gave up, and
// zero when it was deleted (BillsUntiler). Read it after Done.
func (s *e2bSession) BillsUntil() time.Time {
	if n := s.billsUntil.Load(); n != 0 {
		return time.Unix(0, n)
	}
	return time.Time{}
}

// setUp is the open's work between the create and handing the session over.
func (s *e2bSession) setUp(ctx context.Context, md map[string]string) error {
	vm := s.machine()
	if err := s.e.verifyResources(ctx, vm); err != nil {
		return err
	}
	rec, err := s.e.record(ctx, vm.id)
	if err != nil {
		return fmt.Errorf("e2b session: read the sandbox back: %w", err)
	}
	if err := rec.checkOpen(vm, md, s.grants.guard()); err != nil {
		return fmt.Errorf("e2b session: %w", err)
	}
	s.opened = rec
	// The one start by name: node through the control PATH (sessionkit.ControlPathClosed:
	// E2B's template build leaves /usr/local writable by every user in the machine, so
	// nothing of plimsoll's is ever looked for there), before any of the session's code,
	// so nothing the session writes can be what is found. The open then pins every
	// program later starts name by path.
	argv, err := sessionkit.ControlArgvClosedByName(nil, sessionkit.NodeArgv("-e", e2bSessionJS, "open", strconv.Itoa(s.uid), e2bSessionWork, e2bSessionStage)...)
	if err != nil {
		return err
	}
	out, err := s.root(ctx, argv, 4096, 4096)
	if err != nil {
		return fmt.Errorf("e2b session: prepare the machine: %w", err)
	}
	if !out.Exited || out.ExitCode != 0 {
		// The open is the session's first program started with sessionkit.NodeSignalFlag;
		// a node that does not know it exits 9 before running any of it. Nothing of the
		// caller's has run, and the template's own words stay out of the refusal.
		if out.Exited && out.ExitCode == 9 && sessionkit.NodeFlagRefused(out.Stderr) {
			return e2bSessionNodeRefused("the session's open exited 9: node: bad option: " + sessionkit.NodeSignalFlag)
		}
		// The control PATH holds no node (e2bNoControlNode, which the startup check
		// reads too).
		if e2bNoControlNode(out.Exited, out.ExitCode, out.Stderr) {
			return e2bSessionNoNode()
		}
		// The open could not take the write permission on /usr/local back from the
		// session's user (e2b_session.js, closeUsrLocal); its words are the open's own.
		if out.Exited && out.ExitCode == e2bOpenUsrLocalExit {
			return e2bSessionUsrLocalOpen(strings.TrimSpace(out.Stderr))
		}
		// The open refused the machine (e2b_session.js, refuse): a pinned program the
		// guest could change, no setpriv, a guest uid that is an account, a drop it could
		// not prove, and the rest. Nothing of the caller's has run.
		if out.Exited && out.ExitCode == e2bOpenRefusedExit {
			return e2bSessionOpenRefused(out.Stderr)
		}
		return fmt.Errorf("e2b session: the machine cannot hold a session (exit %d): %s", out.ExitCode, truncateForError(strings.TrimSpace(out.Stderr)))
	}
	var prepared struct {
		Envd     int               `json:"envd"`
		Bins     map[string]string `json:"bins"`
		UsrLocal e2bUsrLocal       `json:"usrLocal"`
	}
	if err := json.Unmarshal([]byte(out.Stdout), &prepared); err != nil || prepared.Envd <= 1 {
		return fmt.Errorf("e2b session: the machine's preparation reported %q", truncateForError(out.Stdout))
	}
	if err := checkE2BBins(prepared.Bins); err != nil {
		return fmt.Errorf("e2b session: %w", err)
	}
	s.bins = prepared.Bins
	s.usrLocal = prepared.UsrLocal
	if s.guestEnv, err = s.readGuestEnv(ctx); err != nil {
		return err
	}
	list, err := s.control(nil, sessionkit.ListArgv()...)
	if err != nil {
		return err
	}
	if out, err = s.root(ctx, list, 1<<20, 4096); err != nil {
		return fmt.Errorf("e2b session: list processes: %w", err)
	}
	if !out.Exited || out.ExitCode != 0 {
		return fmt.Errorf("e2b session: the process list exited %d: %q", out.ExitCode, truncateForError(out.Stderr))
	}
	keep, err := sessionkit.BaselineAll([]byte(out.Stdout), s.uid)
	if err != nil {
		return fmt.Errorf("e2b session: %w", err)
	}
	s.life.SetBaseline(keep)
	// Identities a launcher reports are confirmed by root, whom the guest cannot reach;
	// a relay is confirmed by its parent, envd, which starts every relay.
	s.life.Interps.Checker = s.check
	s.life.Interps.RelayParent = prepared.Envd
	// An interpreter is guest-facing: the launcher (plimsoll's, started clean) execs it
	// by its pinned path with the guest's environment, as a snippet's node gets it.
	s.life.Interps.Bins = map[string]string{}
	for _, name := range []string{"node", "python3"} {
		if p, ok := s.bins[name]; ok {
			s.life.Interps.Bins[name] = p
		}
	}
	s.life.Interps.Start = append(append([]string{e2bEnv, "-i"}, s.guestEnv...), "HOME="+e2bSessionWork)
	return nil
}

// e2bSessionNodeRefused is the refusal of a session on a template whose node does not
// accept sessionkit.NodeSignalFlag (finding rust-native-helper-35): every program of
// plimsoll's in a session starts with it, while a single run starts none, so the provider
// serves single runs there and refuses sessions, before any of the caller's code has run,
// as unsupported, which a caller or router reads as "use another backend" (connect's
// Unimplemented over RPC, never an internal error). E2B's base template carried node
// v20.9.0 on 2026-11-20. found says what showed the node: the startup check's reading or
// the open's exit; never the template's own words. The template's name is not said: a
// caller is never told one (DescribeResponse states no mutable name).
func e2bSessionNodeRefused(found string) error {
	return NotDispatched(RefusalUnsupported, fmt.Errorf("%w: an E2B session cannot open on this template: %w (%s). "+
		"Single runs work on it; for sessions the operator builds plimsoll's E2B template (e2b/README.md in plimsoll's repository) and sets E2B_TEMPLATE to it",
		ErrUnsupported, sessionkit.ErrNodeFlagRefused, found))
}

// ErrE2BNoControlNode is the refusal of a session on a template with no node where
// plimsoll's own programs look for one.
var ErrE2BNoControlNode = errors.New("plimsoll's own programs take node from " + strings.ReplaceAll(sessionkit.ControlPathClosed, ":", ", ") + " and found none there")

// e2bSessionNoNode is the refusal of a session on a template whose only node is under
// /usr/local (finding rust-native-helper-40): node's own images and E2B's base template
// put it there, and E2B's template build leaves that folder writable by every user in
// the machine, so plimsoll's own programs never take a node from it. Nothing of the
// caller's has run. Like e2bSessionNodeRefused it is unsupported, not an internal
// error, and says how the operator gets a template that serves sessions.
func e2bSessionNoNode() error {
	return NotDispatched(RefusalUnsupported, fmt.Errorf("%w: an E2B session cannot open on this template: %w. "+
		"E2B's template build leaves /usr/local, where node's own images put node, writable by every user in the machine, so a node there could be replaced by the session's code. "+
		"Single runs work on it; for sessions the operator builds plimsoll's E2B template (e2b/README.md in plimsoll's repository), which puts a node in /usr/bin, and sets E2B_TEMPLATE to it",
		ErrUnsupported, ErrE2BNoControlNode))
}

// e2bOpenRefusedExit is the open's exit when it refuses the machine, with its reason as
// the last line of its standard error (e2b_session.js, refuse).
const e2bOpenRefusedExit = 2

// ErrE2BOpenRefused is the refusal of a session whose open refused its machine.
var ErrE2BOpenRefused = errors.New("the session's open refused the machine before any of the session's code ran")

// e2bSessionOpenRefused is the refusal of a session whose open refused its machine
// (e2b_session.js, refuse, exit 2). The machine is the template's, so the reason is
// environment (another backend may have a template that holds a session, as for a docker
// image the provider refuses), and it wraps ErrUnsupported, as the other template
// refusals do, so a caller over RPC gets Unimplemented with these words, never an
// internal error: none of the caller's code has run. The words are the open's own, its
// refusal line, the last line of its standard error; nothing else of that stream is
// kept. Until 2026-11-20 this refusal reached a caller unmarked, as an internal error.
func e2bSessionOpenRefused(stderr string) error {
	why := strings.TrimSpace(stderr)
	if i := strings.LastIndexByte(why, '\n'); i >= 0 {
		why = strings.TrimSpace(why[i+1:])
	}
	if why == "" {
		why = "it gave no reason"
	}
	return NotDispatched(RefusalEnvironment, fmt.Errorf("%w: an E2B session cannot open on this template: %w (%s). "+
		"For sessions the operator builds plimsoll's E2B template (e2b/README.md in plimsoll's repository) and sets E2B_TEMPLATE to it",
		ErrUnsupported, ErrE2BOpenRefused, truncateForError(why)))
}

// e2bOpenUsrLocalExit is the open's exit when something under /usr/local stays the
// session's user's to write after the open took the write permission back
// (e2b_session.js, usrLocalExit).
const e2bOpenUsrLocalExit = 24

// e2bUsrLocal is the open's report of closing /usr/local: the files and folders the
// session's user was checked against (those under /usr/local and the folders above it),
// how many lost a write permission, and the time it took in milliseconds.
type e2bUsrLocal struct {
	Entries int     `json:"entries"`
	Changed int     `json:"changed"`
	MS      float64 `json:"ms"`
}

// ErrE2BUsrLocalOpen is the refusal of a session on a template where the open could not
// make /usr/local closed to the session's user.
var ErrE2BUsrLocalOpen = errors.New("the session's open could not take the write permission on /usr/local away from the session's user")

// e2bSessionUsrLocalOpen is the refusal of a session whose open found something under
// /usr/local that the session's user could still write after the open took the write
// permission back (finding hunt-quality-55). E2B's template build leaves the folder
// writable by every user, and programs that run as root (E2B's own among them) live and
// look there, so session code that could write it could make itself root in its
// machine. Nothing of the caller's has run. why is the open's own account of the first
// such path. Unsupported, as the other template refusals are, with the way out.
func e2bSessionUsrLocalOpen(why string) error {
	return NotDispatched(RefusalUnsupported, fmt.Errorf("%w: an E2B session cannot open on this template: %w (%s). "+
		"E2B's template build leaves /usr/local writable by every user in the machine, and a session's open takes that back before any of the session's code runs; on this template it could not. "+
		"Single runs work on it; for sessions the operator builds plimsoll's E2B template (e2b/README.md in plimsoll's repository) and sets E2B_TEMPLATE to it",
		ErrUnsupported, ErrE2BUsrLocalOpen, truncateForError(why)))
}

// checkE2BBins checks the open's pinned programs: every required one there, each a
// clean absolute path outside every folder the guest can write.
func checkE2BBins(bins map[string]string) error {
	for _, name := range e2bRequiredBins {
		if bins[name] == "" {
			return fmt.Errorf("the machine's preparation pinned no %s", name)
		}
	}
	for name, p := range bins {
		if !e2bEnvName.MatchString(name) || !strings.HasPrefix(p, "/") || path.Clean(p) != p || strings.ContainsAny(p, "\x00\n") {
			return fmt.Errorf("the machine's preparation pinned %q as %q", truncateForError(name), truncateForError(p))
		}
		for _, d := range append([]string{e2bSessionOwn, e2bSessionStage}, e2bSessionDirs...) {
			if p == d || strings.HasPrefix(p, d+"/") {
				return fmt.Errorf("the machine's preparation pinned %s in %s, a folder the session writes", name, d)
			}
		}
	}
	return nil
}

// readGuestEnv reads the environment envd hands a process of root's, which every guest
// process gets, as it did when envd started it directly: before any of the session's
// code, by the pinned /usr/bin/env, in /. Names that describe the reader (e2bEnvDropped)
// and names no shell could carry are left out.
func (s *e2bSession) readGuestEnv(ctx context.Context) ([]string, error) {
	out, err := s.e.envdRun(ctx, s.machine(), envdProcess{user: e2bRootUser, cmd: e2bEnv, args: []string{"-0"}, cwd: e2bControlDir}, 64<<10, 4096)
	if err != nil {
		return nil, fmt.Errorf("e2b session: read the machine's environment: %w", err)
	}
	if !out.exited || out.exitCode != 0 || out.stdoutTruncated {
		return nil, fmt.Errorf("e2b session: reading the machine's environment exited %d (truncated %v)", out.exitCode, out.stdoutTruncated)
	}
	var env []string
	for _, kv := range strings.Split(out.stdout, "\x00") {
		name, _, ok := strings.Cut(kv, "=")
		if !ok || !e2bEnvName.MatchString(name) || e2bEnvDropped[name] {
			continue
		}
		env = append(env, kv)
	}
	slices.Sort(env)
	return env, nil
}

// control is argv, one of plimsoll's own programs, as it starts here: under
// sessionkit.ControlArgvClosed with env, its program by the path the open pinned (a
// name is looked up; a path must be one the open pinned).
func (s *e2bSession) control(env map[string]string, argv ...string) ([]string, error) {
	if len(argv) == 0 {
		return nil, errors.New("e2b session: no program")
	}
	bin, err := s.pinned(argv[0])
	if err != nil {
		return nil, err
	}
	return sessionkit.ControlArgvClosed(env, append([]string{bin}, argv[1:]...)...)
}

// pinned is the path the open found name at, or name itself when it is such a path.
func (s *e2bSession) pinned(name string) (string, error) {
	if p, ok := s.bins[name]; ok {
		return p, nil
	}
	for _, p := range s.bins {
		if name == p {
			return p, nil
		}
	}
	return "", fmt.Errorf("e2b session: %q is no program the open found on the machine's root", truncateForError(name))
}

// hooks are what the session's lifecycle does to its microVM.
func (s *e2bSession) hooks() sessionkit.Hooks {
	return sessionkit.Hooks{
		Provider: "e2b", Unit: "sandbox",
		Refuse:  sessionRefusals(),
		Suspend: s.pause,
		// The paused machine's memory is E2B's to hold, not this host's.
		SuspendHoldsMemory: false,
		Resume:             s.resume,
		ReadBack:           s.readBack,
		Sweep: func(ctx context.Context, argv []string) (sessionkit.ExecResult, error) {
			argv, err := s.control(nil, argv...)
			if err != nil {
				return sessionkit.ExecResult{}, err
			}
			return s.root(ctx, argv, 4096, 4096)
		},
		Measure: sessionkit.MeasureWalk,
		Dirs:    e2bSessionDirs,
		// No restart: a cold boot would lose the files and the memory the session keeps.
		Unproven: func(ctx context.Context, sweep string) *sessionkit.EndedError {
			if _, err := s.e.record(ctx, s.machine().id); errors.Is(err, errE2BNotFound) {
				return &SessionEndedError{Reason: SessionSandboxChanged, Detail: "the sandbox no longer exists", Public: true}
			}
			return &SessionEndedError{Reason: SessionBoundaryFailed, Detail: sweep}
		},
		Teardown: func() {
			s.grants.close()
			// A delete that gives up leaves the sandbox billing until E2B's own timeout
			// for it; BillsUntil reports that to whoever charges the session's time
			// (round-3 review: the failure reached no meter, so the session's time
			// stopped being charged while its sandbox billed on).
			ctx, gaveUp := WatchTeardown(context.Background())
			s.e.kill(ctx, s.machine())
			if gaveUp() {
				s.billsUntil.Store(s.billEnd.Load())
			}
		},
	}
}

func (s *e2bSession) Isolation() IsolationClass { return s.tier }

// Environments is the provider's: a template is not an identity.
func (s *e2bSession) Environments() Environments { return s.e.Environments() }
func (s *e2bSession) ExpiresAt() time.Time       { return s.life.ExpiresAt() }
func (s *e2bSession) Done() <-chan struct{}      { return s.life.Done() }
func (s *e2bSession) Err() error                 { return s.life.Err() }

// Close ends the session and deletes its sandbox. It does not wait for a call in
// flight: the call is stopped.
func (s *e2bSession) Close(context.Context) error {
	s.life.Close()
	return nil
}

// Suspend pauses the sandbox: compute billing stops, its memory and files are kept.
func (s *e2bSession) Suspend(ctx context.Context) (bool, error) { return s.life.Suspend(ctx) }

// pause pauses the sandbox, keeping its memory. A pause cuts every connection into the
// machine, the relays' streams with them, so the interpreters are forgotten first;
// the resume sweeps them away. A 503 means the node could not take the pause and the
// sandbox runs on, so it is tried again within the budget.
func (s *e2bSession) pause(ctx context.Context) error {
	s.life.Interps.Clear()
	ctx, cancel := context.WithTimeout(ctx, e2bPauseBudget)
	defer cancel()
	id := s.machine().id
	for attempt := 0; ; attempt++ {
		code, body, err := s.e.control(ctx, http.MethodPost, "/sandboxes/"+id+"/pause", map[string]any{"memory": true})
		switch {
		case err != nil:
			return fmt.Errorf("e2b pause: %w", err)
		case code == http.StatusNoContent || code == http.StatusOK:
			return nil
		case code == http.StatusConflict:
			// Already paused, or in another state: the record says which.
			if rec, err := s.e.record(ctx, id); err == nil && rec.State == "paused" {
				return nil
			}
			return fmt.Errorf("e2b pause: HTTP 409: %s", truncateForError(body))
		case code == http.StatusServiceUnavailable && attempt < 2:
			if err := sleepCtx(ctx, time.Duration(attempt+1)*2*time.Second); err != nil {
				return fmt.Errorf("e2b pause: %w", err)
			}
		default:
			return fmt.Errorf("e2b pause: HTTP %d: %s", code, truncateForError(body))
		}
	}
}

// resume resumes a paused sandbox, its own timeout set to the session's remaining
// lifetime plus the margin, then sweeps away the interpreters and relays the pause
// left without a stream: they are no longer kept.
func (s *e2bSession) resume(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, e2bResumeBudget)
	defer cancel()
	vm := s.machine()
	timeout := max(int((time.Until(s.life.ExpiresAt()) + e2bSessionMargin).Seconds()), 60)
	// The resume sets E2B's timeout anew, so the sandbox may bill until then. The clock
	// starts no later than this request's own end, so the charge is taken from there
	// and never cuts into the time the request itself took.
	raise := func() {
		for end := time.Now().Add(time.Duration(timeout) * time.Second).UnixNano(); ; {
			if old := s.billEnd.Load(); end <= old || s.billEnd.CompareAndSwap(old, end) {
				return
			}
		}
	}
	raise()
	code, body, err := s.e.control(ctx, http.MethodPost, "/v2/sandboxes/"+vm.id+"/connect", map[string]any{"timeout": timeout})
	raise()
	if err != nil {
		return fmt.Errorf("e2b resume: %w", err)
	}
	if code != http.StatusOK && code != http.StatusCreated {
		return fmt.Errorf("e2b resume: HTTP %d: %s", code, truncateForError(body))
	}
	var got struct {
		SandboxID          string `json:"sandboxID"`
		EnvdAccessToken    string `json:"envdAccessToken"`
		TrafficAccessToken string `json:"trafficAccessToken"`
	}
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		return fmt.Errorf("e2b resume: unparseable answer: %w", err)
	}
	if got.SandboxID != vm.id {
		return fmt.Errorf("e2b resume: the answer names sandbox %q", truncateForError(got.SandboxID))
	}
	// The tokens are derived from the sandbox's ID today, so they come back the same;
	// a new one is used if E2B ever issues one.
	s.mu.Lock()
	if got.EnvdAccessToken != "" {
		s.vm.accessToken = got.EnvdAccessToken
	}
	if got.TrafficAccessToken != "" {
		s.vm.trafficAccessToken = got.TrafficAccessToken
	}
	s.mu.Unlock()
	argv, err := s.control(nil, sessionkit.SweepArgv(0, sessionkit.MeasureWalk, nil, s.life.Keep())...)
	if err != nil {
		return err
	}
	out, err := s.root(ctx, argv, 4096, 4096)
	if err != nil || !out.Exited || out.ExitCode != sessionkit.SweepClean {
		return fmt.Errorf("e2b resume: the sweep of the interpreters the pause left exited %d (err %v)", out.ExitCode, err)
	}
	return nil
}

// readBack reads the control plane's record of the sandbox before a call and says how
// the session ends on any difference from the record at open. A read the control plane
// does not answer refuses the call and keeps the session.
func (s *e2bSession) readBack(ctx context.Context) error {
	rec, err := s.e.record(ctx, s.machine().id)
	if errors.Is(err, errE2BNotFound) {
		return &SessionEndedError{Reason: SessionSandboxChanged, Detail: "the sandbox no longer exists", Public: true}
	}
	if err != nil {
		return err
	}
	if rec.State != "running" {
		return &SessionEndedError{Reason: SessionSandboxChanged, Detail: fmt.Sprintf("the sandbox is %q, not running", rec.State)}
	}
	if diff := rec.differs(s.opened); diff != "" {
		return &SessionEndedError{Reason: SessionSandboxChanged, Detail: diff}
	}
	return nil
}

// admit is the checks a call shares before it takes its turn.
func (s *e2bSession) admit(grant *HostAPIGrant, floor IsolationClass, rule SoftwareRule) error {
	if err := CheckMinimumIsolation(s.tier, floor); err != nil {
		return err
	}
	if err := rule.Check(""); err != nil {
		return err
	}
	if err := CheckSessionGrant(grant); err != nil {
		return err
	}
	return s.grants.check(grant)
}

// lend serves the call's grant through the session's grant channel until the
// release; a call without a grant gets nothing.
func (s *e2bSession) lend(ctx context.Context, grant *HostAPIGrant, timeout time.Duration) (*brokerSession, func(), error) {
	if grant == nil {
		return nil, func() {}, nil
	}
	return s.grants.lend(ctx, s, grant, timeout)
}

// e2bGuardEnv points a granted call's node at the guest OS trust store, which holds the
// CA of the E2B proxy the guard is reached through (see e2bGuestCABundle).
var e2bGuardEnv = map[string]string{"NODE_EXTRA_CA_CERTS": e2bGuestCABundle}

// root runs argv, one of plimsoll's own programs as control builds it, as root, in /.
func (s *e2bSession) root(ctx context.Context, argv []string, outCap, errCap int) (sessionkit.ExecResult, error) {
	out, err := s.e.envdRun(ctx, s.machine(), envdProcess{user: e2bRootUser, cmd: argv[0], args: argv[1:], cwd: e2bControlDir}, outCap, errCap)
	return sessionkit.ExecResult{
		Stdout: out.stdout, Stderr: out.stderr,
		StdoutTruncated: out.stdoutTruncated, StderrTruncated: out.stderrTruncated,
		ExitCode: out.exitCode, Exited: err == nil && out.exited,
	}, err
}

// check runs the interpreter driver's identity check as root.
func (s *e2bSession) check(ctx context.Context, argv []string, _ map[string]string, _ []byte, outCap, errCap int) (sessionkit.ExecResult, error) {
	argv, err := s.control(nil, argv...)
	if err != nil {
		return sessionkit.ExecResult{}, err
	}
	return s.root(ctx, argv, outCap, errCap)
}

// dropArgs is setpriv's drop to the guest: every uid and gid the guest's, no
// supplementary group, no-new-privs. setpriv execs the command, so it keeps the PID.
func (s *e2bSession) dropArgs() []string {
	g := strconv.Itoa(s.uid)
	return []string{"--reuid=" + g, "--regid=" + g, "--clear-groups", "--no-new-privs", "--"}
}

// asGuest is inner run as the guest: the pinned setpriv, a control program started as
// root in /, drops to the guest and execs inner, which keeps the PID.
func (s *e2bSession) asGuest(inner []string) ([]string, error) {
	return s.control(nil, append(append([]string{"setpriv"}, s.dropArgs()...), inner...)...)
}

// guest runs argv, a guest-facing command, as the guest, in the work directory, with
// envd's environment as the open read it plus HOME (the work directory) and env. The
// pinned sh changes into the work directory as the guest, then /usr/bin/env -i hands
// argv that environment, so no root process of the chain starts in the work directory
// or holds the machine's environment.
func (s *e2bSession) guest(ctx context.Context, argv []string, env map[string]string, outCap, errCap int) (procOutput, error) {
	sh, err := s.pinned("sh")
	if err != nil {
		return procOutput{}, err
	}
	inner := append([]string{sh, "-c", e2bGuestStart, "sh", e2bSessionWork, e2bEnv, "-i"}, s.guestEnv...)
	inner = append(inner, "HOME="+e2bSessionWork)
	for _, k := range slices.Sorted(maps.Keys(env)) {
		if !e2bEnvName.MatchString(k) {
			return procOutput{}, fmt.Errorf("e2b session: %q is not an environment variable name", k)
		}
		inner = append(inner, k+"="+env[k])
	}
	full, err := s.asGuest(append(inner, argv...))
	if err != nil {
		return procOutput{}, err
	}
	return s.e.envdRun(ctx, s.machine(), envdProcess{user: e2bRootUser, cmd: full[0], args: full[1:], cwd: e2bControlDir}, outCap, errCap)
}

// guestControl runs argv, one of plimsoll's own programs, as the guest, in /, started
// as control starts one with env: the artifact reader and the interpreter launcher.
func (s *e2bSession) guestControl(ctx context.Context, argv []string, env map[string]string, outCap, errCap int) (procOutput, error) {
	inner, err := s.control(env, argv...)
	if err != nil {
		return procOutput{}, err
	}
	full, err := s.asGuest(inner)
	if err != nil {
		return procOutput{}, err
	}
	return s.e.envdRun(ctx, s.machine(), envdProcess{user: e2bRootUser, cmd: full[0], args: full[1:], cwd: e2bControlDir}, outCap, errCap)
}

// e2bErrno is what the stager's error code may be before it reaches a result: the
// stager runs as the guest, so it is shaped like an errno or dropped.
var e2bErrno = regexp.MustCompile(`^E[A-Z0-9]{1,15}$`)

// e2bStaged is a file the stager could not write: its index among the call's work
// files and an errno-shaped code.
type e2bStaged struct {
	File  int    `json:"file"`
	Errno string `json:"errno"`
}

// stage writes a call's files as the guest: work files under the work directory,
// never following a link out of it, and own files (name → content) into a fresh
// directory of the call's own, which it returns. They travel through the root-only
// staging directory and the root stager, which becomes the guest before writing. A
// work file it could not write is *e2bStaged.
//
// Its error is the call's answer, and is marked not dispatched (unsent) only up to the
// stager's start, while the call's bytes are only where the guest cannot read them (the
// root-only staging directory). From the stager's start they are not: it writes the
// call's own files as the guest, so code alive in the session (a thread in a kept
// interpreter) can read them, kill the stager, which it may signal, and run the call's
// code itself, with the call's grant already lent. So no failure of the stager is
// marked (TestE2BSessionDockerCallWhoseStagerWasKilledIsNotMarked): no mark means the
// code may have run, which is then true. A work file the stager reports it could not
// write is the call's result (setup_failed), as before, never a mark.
func (s *e2bSession) stage(ctx context.Context, work []File, own map[string]string) (dir string, refusal *e2bStaged, err error) {
	type entry struct {
		Path string `json:"path,omitempty"`
		Name string `json:"name,omitempty"`
		B64  string `json:"b64"`
	}
	var spec struct {
		Work []entry `json:"work"`
		Own  []entry `json:"own"`
	}
	for _, f := range work {
		spec.Work = append(spec.Work, entry{Path: f.Path, B64: base64.StdEncoding.EncodeToString([]byte(f.Content))})
	}
	for _, name := range slices.Sorted(maps.Keys(own)) {
		spec.Own = append(spec.Own, entry{Name: name, B64: base64.StdEncoding.EncodeToString([]byte(own[name]))})
	}
	raw, err := json.Marshal(spec)
	if err != nil {
		return "", nil, s.unsent(ctx, err)
	}
	nonce := providerkit.RandHex(8)
	file := e2bSessionStage + "/" + nonce + ".json"
	dir = e2bSessionOwn + "/" + nonce
	if err := s.e.writeFilesAs(ctx, s.machine(), e2bRootUser, []File{{Path: file, Content: string(raw)}}); err != nil {
		return "", nil, s.unsent(ctx, fmt.Errorf("e2b session: stage the call's files: %w", err))
	}
	argv, err := s.control(nil, sessionkit.NodeArgv("-e", e2bSessionJS, "stage", file, strconv.Itoa(s.uid), e2bSessionWork, dir)...)
	if err != nil {
		return "", nil, s.unsent(ctx, err)
	}
	// From here the stager may have written the call's own files as the guest: nothing
	// below is marked (see above).
	out, err := s.root(ctx, argv, 4096, 4096)
	switch {
	case err != nil:
		return "", nil, s.life.CallError(ctx, fmt.Errorf("e2b session: write the call's files: %w", err))
	case out.Exited && out.ExitCode == 0:
		return dir, nil, nil
	case out.Exited && out.ExitCode == 3:
		var r e2bStaged
		if json.Unmarshal([]byte(out.Stdout), &r) == nil {
			return "", &r, nil
		}
	}
	return "", nil, s.life.CallError(ctx, fmt.Errorf("e2b session: the stager exited %d: %s", out.ExitCode, truncateForError(strings.TrimSpace(out.Stderr))))
}

// unsent is the error of a call none of whose bytes have left the root-only staging
// directory (stage): marked not dispatched, as the session's end, the caller's
// deadline, or the environment.
func (s *e2bSession) unsent(runCtx context.Context, err error) error {
	if end := s.Err(); end != nil {
		return RefuseEndedSession(end)
	}
	if deadline.Expired(runCtx) == context.DeadlineExceeded {
		return NotDispatched(RefusalCapacity, fmt.Errorf("%w: %v", context.DeadlineExceeded, err))
	}
	return NotDispatched(RefusalEnvironment, err)
}

// e2bLinuxSignals names the signals as Go's os.ProcessState prints them on Linux,
// which is how envd reports a process a signal ended ("signal: killed").
var e2bLinuxSignals = map[string]int{
	"hangup": 1, "interrupt": 2, "quit": 3, "illegal instruction": 4, "trace/breakpoint trap": 5,
	"aborted": 6, "bus error": 7, "floating point exception": 8, "killed": 9,
	"user defined signal 1": 10, "segmentation fault": 11, "user defined signal 2": 12,
	"broken pipe": 13, "alarm clock": 14, "terminated": 15, "CPU time limit exceeded": 24,
	"file size limit exceeded": 25,
}

// exitStatus is a guest process's exit code as a shell reports it: its own when it
// exited, 128 plus the signal's number when a signal ended it.
func exitStatus(out procOutput) int {
	if out.exited {
		return out.exitCode
	}
	if n, ok := e2bLinuxSignals[strings.TrimPrefix(out.status, "signal: ")]; ok {
		return 128 + n
	}
	return out.exitCode
}

// RunJavaScript runs req.Code with node in the session's work directory, as the guest.
func (s *e2bSession) RunJavaScript(ctx context.Context, req Request) (Result, error) {
	fail := Result{Sandbox: s.e.Name(), Isolation: s.tier}
	if err := ValidateRequest(req); err != nil {
		return fail, err
	}
	if err := s.admit(req.Grant, req.MinimumIsolation, req.Software); err != nil {
		return fail, err
	}
	timeout := clampRunTimeout(req.Timeout, s.e.DefaultTimeout, s.e.MaxTimeout)
	runCtx, done, err := s.life.Call(ctx, timeout)
	if err != nil {
		return fail, err
	}
	defer done()
	core, release, err := s.lend(runCtx, req.Grant, timeout)
	if err != nil {
		return fail, err
	}
	defer release()
	code, env := req.Code, map[string]string(nil)
	if req.Grant != nil {
		code, env = withGuardHostSDK(code, req.Grant, s.e.guardConfig().URL, ""), e2bGuardEnv
	}
	dir, refusal, err := s.stage(runCtx, nil, map[string]string{"snippet.cjs": code})
	if err == nil && refusal != nil {
		// A snippet has no work files, so the stager reports this only when the work
		// directory itself is gone (code of the session can remove it), after it wrote
		// the snippet: unmarked, as any failure of the stager.
		err = s.life.CallError(runCtx, errors.New("e2b session: the stager could not reach the work directory after it wrote the snippet"))
	}
	if err != nil {
		// The grant was live while the staging ran, and code a session keeps can use it,
		// so what it served is returned with the error (round-7 review, 2026-10-08).
		release()
		fail.CallTrace = core.traceSnapshot()
		return fail, err
	}
	start := time.Now()
	out, err := s.guest(runCtx, sessionkit.GuestNodeArgv(dir+"/snippet.cjs"), env, s.e.maxOutput(), s.e.maxOutput())
	release() // before the trace is read: the release waits for the grant's calls in flight
	trace := core.traceSnapshot()
	fail.CallTrace = trace
	res := Result{
		Stdout:          out.stdout,
		Stderr:          out.stderr,
		StdoutTruncated: out.stdoutTruncated,
		StderrTruncated: out.stderrTruncated,
		Duration:        time.Since(start),
		Sandbox:         s.e.Name(),
		Isolation:       s.tier,
		CallTrace:       trace,
	}
	if err == nil {
		res.ExitCode = exitStatus(out)
		return res, nil
	}
	if deadline.Expired(runCtx) == context.DeadlineExceeded && s.Err() == nil {
		// The call's own deadline: envd kills the process, and the sweep that follows
		// kills anything it started.
		res.TimedOut, res.ExitCode = true, 124
		return res, nil
	}
	return fail, s.life.CallError(runCtx, err)
}

// RunProject writes the files under the work directory and runs the steps there in
// order, as the guest, stopping at the first that fails; the files persist to the
// next call.
func (s *e2bSession) RunProject(ctx context.Context, req ProjectRequest) (ProjectResult, error) {
	fail := ProjectResult{Sandbox: s.e.Name(), Isolation: s.tier}
	if err := ValidateProjectRequest(req); err != nil {
		return fail, err
	}
	if err := s.admit(req.Grant, req.MinimumIsolation, req.Software); err != nil {
		return fail, err
	}
	timeout := clampRunTimeout(req.Timeout, s.e.DefaultTimeout, s.e.MaxTimeout)
	runCtx, done, err := s.life.Call(ctx, timeout)
	if err != nil {
		return fail, err
	}
	defer done()
	core, release, err := s.lend(runCtx, req.Grant, timeout)
	if err != nil {
		return fail, err
	}
	defer release()
	res, err := s.runProject(ctx, runCtx, req, release)
	release() // before the trace is read, as for a snippet
	res.CallTrace = core.traceSnapshot()
	return res, err
}

// runProject stages the files and a script per step, then runs the steps and reads the
// artifacts as the guest, under the exec-based providers' one contract (exec_steps.go):
// the artifacts are read within a short grace past runCtx's deadline, which ctx bounds.
// A granted call's steps preload the guard's host SDK, and endGrant ends the grant once
// the steps are done, before the artifact grace: a process a step left behind could
// otherwise keep calling the API past the run's deadline, as the one-shot paths already
// prevent (review, 2026-10-24).
func (s *e2bSession) runProject(ctx, runCtx context.Context, req ProjectRequest, endGrant func()) (ProjectResult, error) {
	fail := ProjectResult{Sandbox: s.e.Name(), Isolation: s.tier}
	scripts := map[string]string{}
	for i, step := range req.Steps {
		// A script per step, as in a run: a step is never one huge argument.
		scripts[fmt.Sprintf("step-%d.sh", i)] = step
	}
	if req.Grant != nil {
		scripts["host.mjs"] = hostGuardSDKModule(req.Grant, s.e.guardConfig().URL, "")
	}
	dir, refusal, err := s.stage(runCtx, req.Files, scripts)
	if err != nil {
		return fail, err
	}
	var env map[string]string
	if req.Grant != nil {
		env = map[string]string{"NODE_OPTIONS": "--import " + dir + "/host.mjs", "NODE_EXTRA_CA_CERTS": e2bGuestCABundle}
	}
	res := ProjectResult{Sandbox: s.e.Name(), Isolation: s.tier, Outcome: ProjectOutcomeCompleted}
	if refusal != nil {
		which := "a file"
		if refusal.File >= 0 && refusal.File < len(req.Files) {
			which = "file " + strconv.Quote(req.Files[refusal.File].Path)
		}
		why := "an unnamed error"
		if e2bErrno.MatchString(refusal.Errno) {
			why = refusal.Errno
		}
		res.Outcome, res.Detail = ProjectOutcomeSetupFailed, fmt.Sprintf("%s could not be written into the work directory: %s", which, why)
		return res, nil
	}
	// A session that ends cancels runCtx, which is not its deadline, so a step it cut
	// short is the session's error, never a timed-out step.
	steps, outcome, detail, err := runExecSteps(runCtx, req.Steps, func(ctx context.Context, i int, _ string) (stepOutput, error) {
		out, err := s.guest(ctx, stepArgv(fmt.Sprintf("%s/step-%d.sh", dir, i)), env, ProjectStepOutputCap, ProjectStepOutputCap)
		// With the error, what envd streamed before it (review, 2026-10-26).
		return stepOutput{stdout: out.stdout, stderr: out.stderr, stdoutTruncated: out.stdoutTruncated,
			stderrTruncated: out.stderrTruncated, exitCode: exitStatus(out)}, err
	})
	endGrant()
	if err != nil {
		return fail, s.life.CallError(runCtx, err)
	}
	res.Steps, res.Outcome, res.Detail = steps, outcome, detail
	if len(req.Artifacts) == 0 {
		return res, nil
	}
	// Artifacts are read as the guest, so a link the session's code left reads only
	// what the guest could; the reader keeps only regular files whose real path lies
	// inside the work directory, even after a failed or timed-out step.
	argv := append(sessionkit.NodeArgv("-e", e2bSessionJS, "artifacts", e2bSessionWork, strconv.Itoa(maxArtifactBytesTotal)), req.Artifacts...)
	// The grace runs from the later of the deadline and the grant's end (artifactDeadline);
	// the session's own lifetime still bounds the call.
	runDeadline, _ := runCtx.Deadline()
	actx, cancelArtifacts := context.WithDeadline(ctx, artifactDeadline(runDeadline))
	defer cancelArtifacts()
	out, err := s.guestControl(actx, argv, nil, maxArtifactBytesTotal/3*4+(64<<10), 4096)
	if err != nil && s.Err() != nil {
		return fail, s.life.CallError(runCtx, err)
	}
	var got struct {
		Artifacts []struct {
			Path string `json:"path"`
			B64  string `json:"b64"`
		} `json:"artifacts"`
		Truncated bool `json:"truncated"`
	}
	if err == nil && (!out.exited || out.exitCode != 0 || json.Unmarshal([]byte(out.stdout), &got) != nil) {
		err = fmt.Errorf("the artifact reader did not report (it exited %d)", exitStatus(out))
	}
	var arts []Artifact
	for _, a := range got.Artifacts {
		data, decodeErr := base64.StdEncoding.DecodeString(a.B64)
		if err == nil && (decodeErr != nil || !slices.Contains(req.Artifacts, a.Path)) {
			err = errors.New("the artifact reader reported an artifact it was not asked for")
		}
		arts = append(arts, Artifact{Path: a.Path, Content: data})
	}
	setArtifacts(&res, arts, got.Truncated, err)
	return res, nil
}

// RunCell runs code in the session's interpreter for req.Language, starting one when
// none is alive (sandbox/internal/sessionkit), through a relay the session keeps
// attached by one envd stream held open, so a warm cell starts no process. A pause
// cuts that stream, so the cell after a suspend starts a fresh interpreter and says so.
// A cell's budget is a project's.
func (s *e2bSession) RunCell(ctx context.Context, req CellRequest) (CellResult, error) {
	fail := CellResult{Sandbox: s.e.Name(), Isolation: s.tier}
	if err := ValidateCellRequest(req); err != nil {
		return fail, err
	}
	if err := s.admit(nil, req.MinimumIsolation, req.Software); err != nil {
		return fail, err
	}
	timeout := clampRunTimeout(req.Timeout, s.e.DefaultTimeout, s.e.MaxTimeout)
	runCtx, done, err := s.life.Call(ctx, timeout)
	if err != nil {
		return fail, err
	}
	defer done()
	start := time.Now()
	out, err := s.life.Interps.RunRelayed(runCtx, s.launch, s.attach, SessionCell(req, s.Environments().Project, e2bSessionWork, s.e.maxOutput()))
	return SessionCellResult(runCtx, fail, out, err, time.Since(start), "", "", s.Err,
		func() error { return nil }, func(err error) error { return s.life.CallError(runCtx, err) })
}

// launch runs the interpreter launcher as the guest: the launcher makes the
// interpreter's directory, which the interpreter, the guest too, writes into. The
// launcher, plimsoll's, starts clean in / by the pinned sh; the interpreter it starts
// gets the guest's environment through Interps.Start and is named by its pinned path
// (Interps.Bins), as on docker.
func (s *e2bSession) launch(ctx context.Context, argv []string, env map[string]string, stdin []byte, outCap, errCap int) (sessionkit.ExecResult, error) {
	if len(stdin) > 0 {
		return sessionkit.ExecResult{}, errors.New("e2b session: the launcher takes no stdin")
	}
	out, err := s.guestControl(ctx, argv, env, outCap, errCap)
	return sessionkit.ExecResult{
		Stdout: out.stdout, Stderr: out.stderr,
		StdoutTruncated: out.stdoutTruncated, StderrTruncated: out.stderrTruncated,
		ExitCode: out.exitCode, Exited: err == nil && out.exited,
	}, err
}

// attach starts argv, a relay, as root on an envd stream held open with stdin, without
// a deadline (envd would kill it at one). The relay becomes the guest itself
// (PLIMSOLL_RELAY_UID), which leaves it non-dumpable: the guest can neither open its
// pipes nor attach to it. It starts in / under control, with env as its only
// variables, by the node the open pinned.
func (s *e2bSession) attach(argv []string, env map[string]string) (sessionkit.Attached, error) {
	envs := map[string]string{"PLIMSOLL_RELAY_UID": strconv.Itoa(s.uid)}
	maps.Copy(envs, env)
	argv, err := s.control(envs, argv...)
	if err != nil {
		return nil, err
	}
	vm := s.machine()
	ctx, cancel := context.WithCancel(s.life.Context())
	resp, err := s.e.envdStart(ctx, vm, envdProcess{user: e2bRootUser, cmd: argv[0], args: argv[1:], cwd: e2bControlDir, stdin: true})
	if err != nil {
		cancel()
		return nil, fmt.Errorf("e2b attach: %w", err)
	}
	pr, pw := io.Pipe()
	a := &e2bAttached{e: s.e, vm: vm, ctx: ctx, cancel: cancel, out: pr}
	started := make(chan uint32, 1)
	ended := make(chan struct{})
	go func() {
		defer close(ended)
		defer resp.Body.Close()
		defer cancel()
		err := readEnvdFrames(resp.Body, 0, func(msg []byte) error {
			var ev procEvent
			if json.Unmarshal(msg, &ev) != nil {
				return nil
			}
			switch {
			case ev.Event.Start != nil:
				select {
				case started <- ev.Event.Start.PID:
				default:
				}
			case ev.Event.Data != nil && len(ev.Event.Data.Stdout) > 0:
				if _, err := pw.Write(ev.Event.Data.Stdout); err != nil {
					return err
				}
			case ev.Event.End != nil:
				return io.EOF
			}
			return nil
		})
		if err == nil {
			err = io.EOF
		}
		_ = pw.CloseWithError(err)
	}()
	timer := time.NewTimer(e2bAttachBudget)
	defer timer.Stop()
	select {
	case a.pid = <-started:
		if a.pid == 0 {
			a.Close()
			return nil, errors.New("e2b attach: envd named no PID")
		}
		return a, nil
	case <-ended:
		a.Close()
		return nil, errors.New("e2b attach: the stream ended before envd named the relay's PID")
	case <-timer.C:
		a.Close()
		return nil, errors.New("e2b attach: envd did not name the relay's PID in time")
	}
}

// e2bAttached is a relay on an envd stream held open: its stdout arrives through a
// pipe a goroutine fills from the stream's events, and what is written to its stdin
// goes out as process.Process/SendInput calls, in order.
type e2bAttached struct {
	e      *E2B
	vm     e2bVM
	pid    uint32
	ctx    context.Context
	cancel context.CancelFunc
	out    *io.PipeReader
	mu     sync.Mutex // one SendInput at a time keeps the input in order
}

func (a *e2bAttached) Stdin() io.Writer  { return a }
func (a *e2bAttached) Stdout() io.Reader { return a.out }

// Close lets go of the stream; the relay in the sandbox ends at the next sweep.
func (a *e2bAttached) Close() {
	a.cancel()
	_ = a.out.Close()
}

func (a *e2bAttached) Write(p []byte) (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for off := 0; off < len(p); off += e2bInputChunk {
		chunk := p[off:min(off+e2bInputChunk, len(p))]
		body, err := json.Marshal(map[string]any{"process": map[string]any{"pid": a.pid}, "input": map[string]any{"stdin": chunk}})
		if err != nil {
			return off, err
		}
		if err := a.send(body); err != nil {
			return off, err
		}
	}
	return len(p), nil
}

// send is one SendInput, a unary Connect call with the JSON codec.
func (a *e2bAttached) send(body []byte) error {
	ctx, cancel := context.WithTimeout(a.ctx, e2bAttachBudget)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.e.envdHost(a.vm.id)+"/process.Process/SendInput", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connect-Protocol-Version", "1")
	a.vm.authorize(req)
	req.SetBasicAuth(e2bRootUser, "")
	resp, err := a.e.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("envd send input: HTTP %d: %s", resp.StatusCode, truncateForError(strings.TrimSpace(string(raw))))
	}
	return nil
}

// Drain refuses every open from now on (waiting for those already in flight), ends
// every open session (SessionShutdown), and waits, within ctx, for their sandboxes to
// be deleted.
func (e *E2B) Drain(ctx context.Context) error {
	e.sessions.Drain()
	select {
	case <-e.sessions.Opened():
	case <-ctx.Done():
		e.sessions.EndAll(SessionShutdown)
		return fmt.Errorf("e2b: sessions still opening: %w", ctx.Err())
	}
	if err := e.sessions.EndAll(SessionShutdown)(ctx); err != nil {
		return fmt.Errorf("e2b: session sandboxes still being deleted: %w", err)
	}
	if err := e.sessions.WaitRemovals(ctx); err != nil {
		return fmt.Errorf("e2b: session sandboxes still being deleted: %w", err)
	}
	return nil
}

// ---- the control plane's record of a sandbox ----

// errE2BNotFound is a sandbox the control plane does not know (deleted, or expired).
var errE2BNotFound = errors.New("e2b: no such sandbox")

// e2bNetwork is a sandbox's network configuration as the control plane reports it.
type e2bNetwork struct {
	AllowPublicTraffic *bool                      `json:"allowPublicTraffic"`
	AllowOut           []string                   `json:"allowOut"`
	DenyOut            []string                   `json:"denyOut"`
	Rules              map[string]json.RawMessage `json:"rules"`
	EgressProxy        json.RawMessage            `json:"egressProxy"`
	MaskRequestHost    string                     `json:"maskRequestHost"`
}

// e2bRecord is GET /sandboxes/{id}, the fields a session checks.
type e2bRecord struct {
	TemplateID          string            `json:"templateID"`
	SandboxID           string            `json:"sandboxID"`
	State               string            `json:"state"`
	CPUCount            int               `json:"cpuCount"`
	MemoryMB            int               `json:"memoryMB"`
	DiskSizeMB          *int              `json:"diskSizeMB"`
	Metadata            map[string]string `json:"metadata"`
	AllowInternetAccess *bool             `json:"allowInternetAccess"`
	Network             *e2bNetwork       `json:"network"`
	Lifecycle           *struct {
		AutoResume bool   `json:"autoResume"`
		OnTimeout  string `json:"onTimeout"`
	} `json:"lifecycle"`
}

// record reads the control plane's record of sandbox id.
func (e *E2B) record(ctx context.Context, id string) (e2bRecord, error) {
	code, body, err := e.control(ctx, http.MethodGet, "/sandboxes/"+id, nil)
	if err != nil {
		return e2bRecord{}, fmt.Errorf("e2b get sandbox: %w", err)
	}
	if code == http.StatusNotFound {
		return e2bRecord{}, errE2BNotFound
	}
	if code != http.StatusOK {
		return e2bRecord{}, fmt.Errorf("e2b get sandbox: HTTP %d: %s", code, truncateForError(body))
	}
	var rec e2bRecord
	if err := json.Unmarshal([]byte(body), &rec); err != nil {
		return e2bRecord{}, fmt.Errorf("e2b get sandbox: unparseable answer: %w", err)
	}
	if rec.SandboxID != id {
		return e2bRecord{}, fmt.Errorf("e2b get sandbox: the answer names sandbox %q", truncateForError(rec.SandboxID))
	}
	return rec, nil
}

// checkOpen is what a session requires of its sandbox's record at open: running,
// carrying the metadata this open stamped, no egress but what is denied (or, with
// guard, exactly the guard's host and header rule), no public traffic, no egress proxy,
// and neither auto-resume nor a pause at its timeout (a paused session's sandbox resumed
// by traffic would bill unseen).
func (r e2bRecord) checkOpen(vm e2bVM, md map[string]string, guard *e2bGuardConfig) error {
	if r.State != "running" {
		return fmt.Errorf("the new sandbox is %q, not running", r.State)
	}
	for k, v := range md {
		if r.Metadata[k] != v {
			return fmt.Errorf("the sandbox's metadata %q reads %q, not %q", k, r.Metadata[k], v)
		}
	}
	if r.Metadata["lease"] != vm.lease {
		return errors.New("the sandbox's lease stamp is not this open's")
	}
	n := r.Network
	switch {
	case n == nil:
		return errors.New("the control plane reports no network configuration, so deny-all egress cannot be verified")
	case n.AllowPublicTraffic == nil || *n.AllowPublicTraffic:
		return errors.New("the sandbox accepts public traffic")
	case guard == nil && len(n.AllowOut) > 0:
		return fmt.Errorf("the sandbox allows egress to %v", n.AllowOut)
	case guard == nil && len(n.Rules) > 0:
		return errors.New("the sandbox has network rules")
	case guard != nil && !guard.matches(n):
		return errors.New("the sandbox's egress is not exactly the guard's host with the guard's header rule")
	case len(n.EgressProxy) > 0 && string(n.EgressProxy) != "null":
		return errors.New("the sandbox has an egress proxy")
	case !slices.Contains(n.DenyOut, "0.0.0.0/0"):
		return fmt.Errorf("the sandbox does not deny all egress (deny %v)", n.DenyOut)
	}
	if l := r.Lifecycle; l != nil && (l.AutoResume || (l.OnTimeout != "" && l.OnTimeout != "kill")) {
		return fmt.Errorf("the sandbox auto-resumes (%v) or does %q at its timeout", l.AutoResume, l.OnTimeout)
	}
	return nil
}

// differs says what of the record differs from the one at open, "" when nothing does;
// state is checked by the caller, the expiry time E2B extends is not compared, and an
// empty egress list or rule set reads as an absent one (a "call" grant's rule taken off
// may come back either way). The text shown passes truncateForError, which scrubs a
// guard credential in a rule.
func (r e2bRecord) differs(opened e2bRecord) string {
	strip := func(x e2bRecord) e2bRecord {
		x.State = ""
		if x.Network != nil {
			n := *x.Network
			if len(n.AllowOut) == 0 {
				n.AllowOut = nil
			}
			if len(n.Rules) == 0 {
				n.Rules = nil
			}
			x.Network = &n
		}
		return x
	}
	a, _ := json.Marshal(strip(r))
	b, _ := json.Marshal(strip(opened))
	if bytes.Equal(a, b) {
		return ""
	}
	return "the sandbox's record changed since the open: " + truncateForError(string(a))
}

// control sends one control-plane request with the API key and returns the status
// and at most 1 MiB of the body.
func (e *E2B) control(ctx context.Context, method, path string, body any) (int, string, error) {
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, "", err
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, e.apiBase()+path, rd)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("X-API-Key", e.APIKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := e.httpClient().Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, "", err
	}
	return resp.StatusCode, strings.TrimSpace(string(raw)), nil
}
