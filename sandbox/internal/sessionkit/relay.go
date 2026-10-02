package sessionkit

import (
	"bufio"
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/plimsollmark/plimsoll/sandbox/internal/deadline"
)

// A relay (relay.js) runs beside an interpreter, so a cell costs a line on a pipe
// the provider already holds instead of a new process in the sandbox. The provider starts it once per interpreter, after the interpreter,
// as a long-lived command whose stdin and stdout it keeps; the sweep keeps it with
// the interpreter, by the identity it reports when it starts. When either one goes,
// both go: a relayed cell that times out, an interpreter that ends, a relay that
// stops answering.

//go:embed interp/relay.js
var relayJS string

// maxFrame bounds one line from a relay: a piece of output (at most 48 KiB, so
// 64 KiB in base64) or the relay's identity. With frameQueue it bounds what a relay
// can make the daemon hold, whatever the session's code writes into its stdout.
const (
	maxFrame   = 128 << 10
	frameQueue = 64
)

// Attached is a long-lived command in the sandbox whose stdin and stdout the
// provider holds.
type Attached interface {
	Stdin() io.Writer
	Stdout() io.Reader
	// Close lets go of the command on the provider's side. The command in the
	// sandbox ends at the next sweep, which no longer keeps it.
	Close()
}

// AttachFunc starts argv in the session's sandbox, in its work directory, and
// returns it attached.
type AttachFunc func(argv []string, env map[string]string) (Attached, error)

// RelayArgv is the relay's command for an interpreter's language and work directory.
func RelayArgv(lang, work string) []string {
	return []string{"node", "-e", relayJS, interpRoot + lang, work}
}

type frame struct {
	N        string `json:"n"` // the request's nonce, on every frame of a cell
	Prepared bool   `json:"prepared"`
	Ready    string `json:"ready"`
	O        string `json:"o"`
	E        string `json:"e"`
	Done     *int   `json:"done"`
	OT       bool   `json:"ot"`
	ET       bool   `json:"et"`
	// On a done of cellFilesFailed: the failing file's index in the request and the
	// system's error code. On OpenShell the session's own code can forge them.
	File  *int   `json:"file"`
	Errno string `json:"errno"`
}

type relay struct {
	att    Attached
	id     string
	frames chan frame
	errc   chan error
	done   chan struct{} // closed by close: the reader stops waiting to deliver
	once   sync.Once
}

func (r *relay) close() {
	r.once.Do(func() {
		close(r.done)
		r.att.Close()
	})
}

// gone reports whether the relay already stopped, between cells (code of an
// earlier call can kill it): no request reached it, so a new one is safe to start.
func (r *relay) gone() bool {
	select {
	case err := <-r.errc:
		r.errc <- err
		return true
	default:
		return false
	}
}

func startRelay(ctx context.Context, attach AttachFunc, lang, work string) (*relay, error) {
	att, err := attach(RelayArgv(lang, work), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: the relay could not start: %v", ErrLaunch, err)
	}
	r := &relay{att: att, frames: make(chan frame, frameQueue), errc: make(chan error, 1), done: make(chan struct{})}
	go func() {
		sc := bufio.NewScanner(att.Stdout())
		sc.Buffer(make([]byte, 64<<10), maxFrame)
		for sc.Scan() {
			var f frame
			if err := json.Unmarshal(sc.Bytes(), &f); err != nil {
				r.errc <- fmt.Errorf("the relay wrote a line that is not a frame: %w", err)
				return
			}
			// Once the relay is let go, nobody reads frames again: a cell that timed
			// out under a chatty interpreter would otherwise strand this goroutine.
			select {
			case r.frames <- f:
			case <-r.done:
				return
			}
		}
		if err := sc.Err(); err != nil {
			r.errc <- err
			return
		}
		r.errc <- io.EOF
	}()
	select {
	case f := <-r.frames:
		if !identityPattern.MatchString(f.Ready) {
			r.close()
			return nil, fmt.Errorf("%w: the relay reported no identity", ErrLaunch)
		}
		r.id = f.Ready
		return r, nil
	case err := <-r.errc:
		r.close()
		return nil, fmt.Errorf("%w: the relay ended at start: %v", ErrLaunch, err)
	case <-ctx.Done():
		r.close()
		return nil, ctx.Err()
	}
}

// errRelayLost is a relay that stopped answering during a cell.
var errRelayLost = errors.New("the relay stopped answering")

// errOutOfTurn is a frame that does not belong to the cell in progress: another
// nonce, or a status the step cannot produce. Code of the session can write frames
// into the relay's stdout, so this is what a forged frame usually looks like.
var errOutOfTurn = errors.New("the relay answered out of turn")

// drain drops frames left from before this cell: the relay writes none between
// cells, so any there were written by something else.
func (r *relay) drain() {
	for {
		select {
		case <-r.frames:
		default:
			return
		}
	}
}

// send writes one request line under ctx: a relay that stops reading would
// otherwise block the write, and with it the session's turn, past the cell's
// budget. Ending the call lets go of the relay, which unblocks the write.
func (r *relay) send(req []byte) <-chan error {
	wrote := make(chan error, 1)
	go func() {
		_, err := r.att.Stdin().Write(append(req, '\n'))
		wrote <- err
	}()
	return wrote
}

// prepare asks the relay to write the cell's files and connect to the interpreter,
// and waits for its answer: a done frame (3, files; 75, no interpreter) or
// prepared. No code has been sent, whatever the answer, so every outcome here is
// one in which the cell's code did not run.
func (r *relay) prepare(ctx context.Context, nonce string, files []File) (frame, error) {
	req, err := json.Marshal(struct {
		Nonce string `json:"nonce"`
		Files []File `json:"files"`
	}{nonce, files})
	if err != nil {
		return frame{}, err
	}
	r.drain()
	wrote := r.send(req)
	for {
		select {
		case err := <-wrote:
			if err != nil {
				return frame{}, fmt.Errorf("%w: %v", errRelayLost, err)
			}
			wrote = nil
		case f := <-r.frames:
			switch {
			case f.N != nonce:
				return frame{}, errOutOfTurn
			case f.Prepared:
				return f, nil
			case f.Done != nil && (*f.Done == cellFilesFailed || *f.Done == cellNoInterpreter):
				return f, nil
			default:
				return frame{}, errOutOfTurn
			}
		case err := <-r.errc:
			return frame{}, fmt.Errorf("%w: %v", errRelayLost, err)
		case <-ctx.Done():
			r.close()
			return frame{}, ctx.Err()
		}
	}
}

// run hands the prepared cell's code to the relay and reads its frames until the
// relay says it is done, keeping at most the caps of output. Its done is the cell's
// status; a frame of another nonce is errOutOfTurn.
func (r *relay) run(ctx context.Context, nonce, code string, outCap, errCap int) (ExecResult, frame, error) {
	var res ExecResult
	req, err := json.Marshal(struct {
		Nonce  string `json:"nonce"`
		Code   string `json:"code"`
		OutCap int    `json:"outCap"`
		ErrCap int    `json:"errCap"`
	}{nonce, code, outCap, errCap})
	if err != nil {
		return res, frame{}, err
	}
	wrote := r.send(req)
	var out, errb []byte
	add := func(dst []byte, cap int, b64 string, cut *bool) []byte {
		b, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			*cut = true
			return dst
		}
		if room := cap - len(dst); len(b) > room {
			b, *cut = b[:max(room, 0)], true
		}
		return append(dst, b...)
	}
	for {
		select {
		case err := <-wrote:
			if err != nil {
				return res, frame{}, fmt.Errorf("%w: %v", errRelayLost, err)
			}
			wrote = nil
		case f := <-r.frames:
			switch {
			case f.N != nonce:
				res.Stdout, res.Stderr = string(out), string(errb)
				return res, frame{}, errOutOfTurn
			case f.Done != nil:
				res.Stdout, res.Stderr = string(out), string(errb)
				res.StdoutTruncated = res.StdoutTruncated || f.OT
				res.StderrTruncated = res.StderrTruncated || f.ET
				return res, f, nil
			case f.O != "":
				out = add(out, outCap, f.O, &res.StdoutTruncated)
			case f.E != "":
				errb = add(errb, errCap, f.E, &res.StderrTruncated)
			}
		case err := <-r.errc:
			res.Stdout, res.Stderr = string(out), string(errb)
			return res, frame{}, fmt.Errorf("%w: %v", errRelayLost, err)
		case <-ctx.Done():
			r.close()
			res.Stdout, res.Stderr = string(out), string(errb)
			return res, frame{}, ctx.Err()
		}
	}
}

// dropRelay forgets lang's relay and lets go of it.
func (in *Interpreters) dropRelay(lang string) {
	in.mu.Lock()
	r := in.relays[lang]
	delete(in.relays, lang)
	in.mu.Unlock()
	if r != nil {
		r.close()
	}
}

func (in *Interpreters) relayFor(lang string) *relay {
	in.mu.Lock()
	defer in.mu.Unlock()
	return in.relays[lang]
}

// Close lets go of every relay: the session ended.
func (in *Interpreters) Close() {
	in.mu.Lock()
	rs := in.relays
	in.relays = nil
	in.live = nil
	in.mu.Unlock()
	for _, r := range rs {
		r.close()
	}
}

// RunRelayed runs one cell through the language's relay, starting the interpreter
// and then its relay when either is missing. A cell is two steps. The prepare writes
// the cell's files and connects to the interpreter; whatever it answers, no code has
// been sent, so a refusal from it (files that could not be written, ErrFiles; an
// interpreter that cannot be started or reached, ErrLaunch) is one in which the code
// did not run, and an interpreter found gone there (code of an earlier call killed
// it) is started again once. Only then is the code sent, and from then on nothing
// the relay says can turn the call into a refusal or a second send: code of the
// session can write into the relay's stdout, so a status the run step cannot produce
// is read as an interpreter that ended, with the cell's result unknown. A deadline
// drops the interpreter and its relay, so the sweep after the call kills them. A
// relaunched interpreter gets a new relay too, since the launcher replaces the FIFOs
// the old relay reads.
func (in *Interpreters) RunRelayed(ctx context.Context, exec ExecFunc, attach AttachFunc, c Cell) (CellOutcome, error) {
	if _, ok := command[c.Language]; !ok {
		return CellOutcome{}, fmt.Errorf("unknown interpreter language %q", c.Language)
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return CellOutcome{}, err
	}
	nonce := hex.EncodeToString(raw)
	var outcome CellOutcome
	// An interpreter started for a cell whose files failed was never reported;
	// this cell reports it, or nothing would say the earlier state is gone.
	outcome.Started = in.takeUnreported(c.Language)
	lose := func() {
		in.dropRelay(c.Language)
		in.drop(c.Language)
	}
	// unsent is a deadline before the code was sent. The interpreter and relay are
	// dropped all the same (a relay stuck in a prepare holds the cell's files half
	// written), so the next cell starts both and says so.
	unsent := func() (CellOutcome, error) {
		lose()
		return CellOutcome{}, ErrUnsent
	}
	var r *relay
	for attempt := 0; ; attempt++ {
		if attempt == 2 {
			return outcome, fmt.Errorf("%w: the %s interpreter stopped answering as soon as it started", ErrLaunch, c.Language)
		}
		if !in.alive(c.Language) {
			in.dropRelay(c.Language)
			if err := in.launch(ctx, exec, c.Language, c.Work); err != nil {
				if deadline.Expired(ctx) == context.DeadlineExceeded {
					return unsent()
				}
				return CellOutcome{}, err
			}
			outcome.Started = true
		}
		r = in.relayFor(c.Language)
		if r != nil && r.gone() {
			// Killed between calls. Its interpreter may still be alive; if it is not,
			// the new relay finds no one listening and the loop starts both.
			in.dropRelay(c.Language)
			r = nil
		}
		if r == nil {
			var err error
			if r, err = startRelay(ctx, attach, c.Language, c.Work); err == nil {
				if reportedCmd(r.id) != argvHex(RelayArgv(c.Language, c.Work)) {
					err = fmt.Errorf("%w: the relay reported a process that is not the %s relay", ErrLaunch, c.Language)
				} else {
					err = in.check(ctx, "relay:"+r.id)
				}
				if err != nil {
					r.close()
				}
			}
			if err != nil {
				if deadline.Expired(ctx) == context.DeadlineExceeded {
					return unsent()
				}
				lose()
				return CellOutcome{}, err
			}
			in.mu.Lock()
			if in.relays == nil {
				in.relays = map[string]*relay{}
			}
			in.relays[c.Language] = r
			in.mu.Unlock()
		}
		f, err := r.prepare(ctx, nonce, c.Files)
		if deadline.Expired(ctx) == context.DeadlineExceeded {
			return unsent()
		}
		if err != nil {
			lose()
			return CellOutcome{}, fmt.Errorf("%w: the relay failed before the code was sent: %v", ErrLaunch, err)
		}
		if f.Prepared {
			break
		}
		if *f.Done == cellFilesFailed {
			// Nothing of the cell ran, and its interpreter is as the last cell left it,
			// or new, which the next answered cell reports.
			if outcome.Started {
				in.markUnreported(c.Language)
			}
			return CellOutcome{}, filesError(f, len(c.Files))
		}
		lose() // cellNoInterpreter: start both again, once
	}
	out, done, err := r.run(ctx, nonce, c.Code, c.OutCap, c.ErrCap)
	outcome.ExecResult = out
	if deadline.Expired(ctx) == context.DeadlineExceeded {
		lose()
		outcome.TimedOut, outcome.Raised, outcome.Ended = true, true, true
		return outcome, nil
	}
	if errors.Is(err, errRelayLost) || errors.Is(err, errOutOfTurn) {
		// The code may have run; the interpreter's state is unknown.
		lose()
		outcome.Raised, outcome.Ended = true, true
		return outcome, nil
	}
	if err != nil {
		lose()
		return outcome, err
	}
	outcome.ExitCode, outcome.Exited = *done.Done, true
	switch *done.Done {
	case cellRan:
		return outcome, nil
	case cellRaised:
		outcome.Raised = true
		return outcome, nil
	default:
		// The interpreter ended during the cell (76), or a status the run step cannot
		// produce: either way the code may have run, and the interpreter is gone.
		lose()
		outcome.Raised, outcome.Ended = true, true
		return outcome, nil
	}
}
