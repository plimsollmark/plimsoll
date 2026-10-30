package rpc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"strings"
	"sync"

	"connectrpc.com/connect"

	"github.com/plimsollmark/plimsoll/internal/withheld"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// The ship scan (docs/ship-scan.md): every call's payload is scanned against the
// operator's withheld set, as the last check before admission. What a find does is its
// entry's mode: refuse ends the call there, not dispatched, having taken no slot,
// session turn or paid time; audit lets it run and names the entry on the operator's
// audit line alone. A call the scan reads takes its rate token before the scan, since
// the scan is work the rate must bound, so a refused call has spent it (and admission
// takes no second one). The scan reads inside the archives a call carries
// (withheld/archive.go) within bounds per call; a call whose archives pass one is
// incomplete, and a set with any refuse-mode entry refuses it, since what the scan
// could not read may hold one. Every scanned call's audit line states the scan; the
// response and the record do not yet.

// The scan's statuses, on the audit line.
const (
	withheldScanned    = "scanned"
	withheldExempt     = "exempt"
	withheldNotScanned = "not_scanned"
	// withheldIncomplete: scanned, but an archive bound was reached or the call carries
	// an archive the scan cannot read, so part of what the call carries was not read.
	withheldIncomplete = "incomplete"
)

// maxUnreadNamed bounds the parts an incomplete scan's refusal names.
const maxUnreadNamed = 8

// scans bounds the scans running at once: half the daemon's cores in all, and a
// quarter of those for any one caller. A scan runs before admission, so no slot has
// applied yet, and only the rate token it takes first (shipScan); its work is bounded
// by the request and by the archive
// bounds (at most withheld.MaxValueRuns hashes per run of letters and digits in each
// of a part's views, as written, escapes decoded and base64 decoded, and the same in
// each of the streams its archives decompress to, at most withheld.MaxArchiveBytes of
// them: docs/ship-scan.md states the measured worst cases).
// The total bounds how much of the machine such requests hold at once; the per-caller
// share keeps one caller's stream of them from making every other caller's calls wait
// behind it.
//
// A call waiting for a slot holds its decoded request (up to about 4.4 MiB) and nothing
// else bounds it: the decode slot is given back before the handler runs, and admission
// comes after the scan. So the calls that may wait are bounded too (waitBound), and a
// call past the bound is refused at once, not dispatched, reason capacity.
var scans = newScanGate(max(1, runtime.GOMAXPROCS(0)/2))

// scanGate is the two-level bound on scans: all is the daemon's slots, and each caller
// holds at most perCaller of them. A caller's entry exists only while it has a scan
// waiting or running, so the map is as large as the calls in flight.
type scanGate struct {
	all       chan struct{}
	perCaller int
	mu        sync.Mutex
	users     int // calls holding or waiting for a slot, every caller's
	callers   map[string]*callerScans
}

type callerScans struct {
	slots chan struct{}
	users int // calls holding or waiting for one of slots
}

func newScanGate(slots int) *scanGate {
	return &scanGate{all: make(chan struct{}, slots), perCaller: max(1, slots/4), callers: map[string]*callerScans{}}
}

// waitBound is how many calls may wait for a scan slot beyond those the slots hold: in
// all, and of one caller's. A call is refused when its caller already has its slots'
// worth of calls and perCaller more, or the daemon its slots' worth and all more, so
// the calls the scan holds, and the requests they keep in memory, are at most the
// slots plus all.
type waitBound struct{ all, perCaller int }

// scanWaitBound is as many calls as admission takes at once: the limiter's concurrency
// in all and its per-caller concurrency for one caller (SANDBOX_MAX_CONCURRENT and
// SANDBOX_PER_KEY_CONCURRENT). A caller within what admission would run is not refused
// by the scan for having to wait, and the scan holds at most that many requests beyond
// its slots, half what the decode stage may hold (LimitHTTPConcurrency is given twice
// the concurrency). Without a limiter, plimsolld's defaults: 8 and 4.
func (s *SandboxService) scanWaitBound() waitBound {
	if s.Limiter == nil {
		return waitBound{all: 8, perCaller: 4}
	}
	all := cap(s.Limiter.sem)
	perCaller := s.Limiter.perKey
	if perCaller <= 0 || perCaller > all {
		perCaller = all
	}
	return waitBound{all: all, perCaller: perCaller}
}

// errScanWaitFull is the refusal of a call past the wait bound.
var errScanWaitFull = errors.New("too many calls are waiting for the ship scan, retry shortly")

// scanTurn is one call's place at the gate, from enter until its release or leave.
type scanTurn struct {
	g      *scanGate
	caller string
	c      *callerScans
}

// enter places a call of caller's at the gate, or refuses it at once, not dispatched,
// reason capacity, when the bound's calls already wait (waitBound).
func (g *scanGate) enter(caller string, b waitBound) (*scanTurn, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	c := g.callers[caller]
	if g.users >= cap(g.all)+b.all || c != nil && c.users >= g.perCaller+b.perCaller {
		return nil, refuse(connect.CodeResourceExhausted, sandbox.RefusalCapacity, errScanWaitFull)
	}
	if c == nil {
		c = &callerScans{slots: make(chan struct{}, g.perCaller)}
		g.callers[caller] = c
	}
	c.users++
	g.users++
	return &scanTurn{g: g, caller: caller, c: c}, nil
}

// leave gives up the turn without a slot.
func (t *scanTurn) leave() {
	g := t.g
	g.mu.Lock()
	g.users--
	if t.c.users--; t.c.users == 0 {
		delete(g.callers, t.caller)
	}
	g.mu.Unlock()
}

// wait waits for one of the caller's slots and then one of the daemon's, and returns
// the release; it leaves and gives up with ctx's error when ctx ends first. Waiting
// holds nothing else of the daemon's.
func (t *scanTurn) wait(ctx context.Context) (release func(), err error) {
	select {
	case t.c.slots <- struct{}{}:
	case <-ctx.Done():
		t.leave()
		return nil, ctx.Err()
	}
	select {
	case t.g.all <- struct{}{}:
	case <-ctx.Done():
		<-t.c.slots
		t.leave()
		return nil, ctx.Err()
	}
	return func() {
		<-t.g.all
		<-t.c.slots
		t.leave()
	}, nil
}

// shipScanResult is one call's scan; nil when the daemon has no set.
type shipScanResult struct {
	set        *withheld.Set
	status     string
	found      []withheld.Finding
	incomplete []withheld.Incomplete
	// charged: the call's rate token was taken for the scan, so admission takes none.
	charged bool
}

// rateCharged reports whether the scan took the call's rate token.
func (r *shipScanResult) rateCharged() bool { return r != nil && r.charged }

type shipScanKey struct{}

// shipScanFrom is the scan check put on the call's context; nil when there was none.
func shipScanFrom(ctx context.Context) *shipScanResult {
	r, _ := ctx.Value(shipScanKey{}).(*shipScanResult)
	return r
}

// shipScan scans what k carries into its sandbox and returns the context carrying the
// result. Any find, and an incomplete scan, writes a line naming every entry found, by
// label, and each part a bound was reached in. A find in refuse mode, or an incomplete
// scan under a set with a refuse-mode entry, is then a refusal, marked not dispatched,
// that names the refuse-mode entries and where they sit, and the parts not read whole.
func (s *SandboxService) shipScan(ctx context.Context, env envelope, k kind, t target) (context.Context, error) {
	if s.Withheld == nil {
		return ctx, nil
	}
	r := &shipScanResult{set: s.Withheld, status: withheldScanned}
	if caller, authenticated := mintingSubject(ctx); authenticated && s.Withheld.Exempt(caller) {
		r.status = withheldExempt
		return context.WithValue(ctx, shipScanKey{}, r), nil
	}
	shipped := k.shipped()
	if shipped == nil {
		r.status = withheldNotScanned
		return context.WithValue(ctx, shipScanKey{}, r), nil
	}
	caller := auditCaller(ctx)
	turn, err := scans.enter(caller, s.scanWaitBound())
	if err != nil {
		return ctx, err
	}
	// The rate token pays for the scan, taken before it: the scan costs up to a few
	// seconds of a core whatever happens next, and a token taken only at admission would
	// leave SANDBOX_RATE_PER_MIN unable to bound it, since a call the scan refuses never
	// reaches admission and one admission refuses has been scanned already. So a caller
	// whose rate is spent is refused here at constant cost, and a call the scan refuses
	// has spent its token. Taken after the place at the gate, so a call refused for the
	// wait spends none; admission then takes the slot alone (rateCharged).
	if s.Limiter != nil {
		if err := s.Limiter.Charge(caller); err != nil {
			turn.leave()
			return ctx, err
		}
		r.charged = true
	}
	release, err := turn.wait(ctx)
	if err != nil {
		return ctx, mapSandboxErr(sandbox.RefuseGaveUp(ctx))
	}
	var scanErr error
	func() {
		defer release()
		// The parts are copies of the request's text, so they are made inside the slot:
		// the memory they take is bounded by the slots, not by the calls waiting.
		var res withheld.Result
		res, scanErr = s.Withheld.Scan(ctx, shipped())
		r.found, r.incomplete = res.Found, res.Incomplete
	}()
	if scanErr != nil {
		// The call's context ended during the scan: the caller went away.
		return ctx, mapSandboxErr(sandbox.RefuseGaveUp(ctx))
	}
	if len(r.incomplete) > 0 {
		r.status = withheldIncomplete
	}
	ctx = context.WithValue(ctx, shipScanKey{}, r)
	if len(r.found) == 0 && len(r.incomplete) == 0 {
		return ctx, nil
	}
	var refused, unread []string
	for _, f := range r.found {
		if f.Mode == withheld.ModeRefuse {
			refused = append(refused, f.Label+" ("+strings.Join(f.Where, ", ")+")")
		}
	}
	if s.Withheld.Refuses() {
		// The refusal names the first parts not read whole; the audit line names every
		// one. A call of hundreds of parts, each past a bound once the first spent it,
		// would otherwise make an error of tens of kilobytes.
		for i, in := range r.incomplete {
			if i == maxUnreadNamed {
				unread = append(unread, fmt.Sprintf("and %d more", len(r.incomplete)-i))
				break
			}
			unread = append(unread, in.Where+": "+in.Bound.Text())
		}
	}
	// Every find gets a line of its own now, whatever happens to the call next: an
	// audit-mode find in a call that admission then refuses (its concurrency, no slot)
	// is still evidence that the caller had the material. The run's line, when there is
	// one, names the entries again.
	attrs := append([]slog.Attr{slog.String("op", k.op()), slog.String("caller", auditCaller(ctx))}, k.requestAttrs()...)
	attrs = append(attrs, r.attrs()...)
	attrs = append(attrs, slog.Bool("withheld_refused", len(refused) > 0 || len(unread) > 0))
	attrs = append(append(attrs, traceAttrs(env.traceID)...), t.attrs...)
	msg := "withheld material found"
	switch {
	case len(refused) > 0:
		msg = "withheld material refused"
	case len(r.incomplete) > 0:
		msg = "withheld scan incomplete"
	}
	s.logger().LogAttrs(ctx, slog.LevelWarn, msg, attrs...)
	if len(refused) == 0 && len(unread) == 0 {
		return ctx, nil
	}
	var why []string
	if len(refused) > 0 {
		why = append(why, "the request carries material this daemon's operator withholds from sandboxes: "+strings.Join(refused, "; "))
	}
	if len(unread) > 0 {
		// Whether a bound is reached depends on the request alone, and whether the set
		// refuses is the same for every call, so this tells the caller nothing of the set.
		why = append(why, "the ship scan could not read every archive in the request ("+strings.Join(unread, "; ")+
			"), and this daemon's operator refuses what the scan cannot read")
	}
	return ctx, refuse(connect.CodePermissionDenied, sandbox.RefusalPermission, errors.New(strings.Join(why, "; and ")))
}

// attrs state the scan on the audit line: its status, the set, every entry found by
// label, whatever its mode, and each part a bound was reached in, with the bound.
// Labels are the operator's and places are built from indexes; nothing of the
// request's.
func (r *shipScanResult) attrs() []slog.Attr {
	if r == nil {
		return nil
	}
	attrs := []slog.Attr{slog.String("withheld_scan", r.status), slog.String("withheld_set", r.set.Digest())}
	if len(r.found) > 0 {
		labels := make([]string, len(r.found))
		for i, f := range r.found {
			labels[i] = f.Label
		}
		attrs = append(attrs, slog.Any("withheld_found", labels))
	}
	if len(r.incomplete) > 0 {
		unread := make([]string, len(r.incomplete))
		for i, in := range r.incomplete {
			unread[i] = in.Where + ": " + string(in.Bound)
		}
		attrs = append(attrs, slog.Any("withheld_incomplete", unread))
	}
	return attrs
}

// What each kind carries into its sandbox. A part is named by its place in the
// request's own lists, so no report repeats the caller's text.

func (k *javascriptKind) shipped() func() []withheld.Part {
	return func() []withheld.Part { return []withheld.Part{{Where: "code", Data: []byte(k.req.Code), Whole: true}} }
}

func (k *projectKind) shipped() func() []withheld.Part {
	return func() []withheld.Part {
		parts := filesShipped(k.req.Files)
		for i, st := range k.req.Steps {
			parts = append(parts, withheld.Part{Where: fmt.Sprintf("steps[%d]", i), Data: []byte(st)})
		}
		for i, a := range k.req.Artifacts {
			parts = append(parts, withheld.Part{Where: fmt.Sprintf("artifacts[%d]", i), Data: []byte(a)})
		}
		return parts
	}
}

// shipped: a module run carries parameter rows into a compiled simulator, and no file;
// the scan states it as not scanned rather than clean.
func (*moduleKind) shipped() func() []withheld.Part { return nil }

func (k *cellKind) shipped() func() []withheld.Part {
	return func() []withheld.Part {
		return append([]withheld.Part{{Where: "code", Data: []byte(k.req.Code), Whole: true}}, filesShipped(k.req.Files)...)
	}
}

func filesShipped(files []sandbox.File) []withheld.Part {
	parts := make([]withheld.Part, 0, 2*len(files))
	for i, f := range files {
		parts = append(parts,
			withheld.Part{Where: fmt.Sprintf("files[%d].path", i), Data: []byte(f.Path)},
			withheld.Part{Where: fmt.Sprintf("files[%d].content", i), Data: []byte(f.Content), Whole: true})
	}
	return parts
}
