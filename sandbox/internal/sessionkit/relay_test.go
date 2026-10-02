package sessionkit

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// stuckRelay is a relay that reported its identity and then stopped reading: a
// write to its stdin blocks until Close, as a full pipe or a stalled stream does.
type stuckRelay struct {
	inR    *io.PipeReader
	inW    *io.PipeWriter
	outR   *io.PipeReader
	outW   *io.PipeWriter
	closed chan struct{}
	once   sync.Once
}

func newStuckRelay() *stuckRelay {
	a := &stuckRelay{closed: make(chan struct{})}
	a.inR, a.inW = io.Pipe()
	a.outR, a.outW = io.Pipe()
	return a
}

func (a *stuckRelay) Stdin() io.Writer  { return a.inW }
func (a *stuckRelay) Stdout() io.Reader { return a.outR }
func (a *stuckRelay) Close() {
	a.once.Do(func() {
		close(a.closed)
		_ = a.inR.CloseWithError(io.ErrClosedPipe)
		_ = a.outR.CloseWithError(io.ErrClosedPipe)
	})
}

func launched(context.Context, []string, map[string]string, []byte, int, int) (ExecResult, error) {
	return ExecResult{Stdout: "7:1:00", Exited: true}, nil
}

// A relay that stops reading must not hold a cell past its deadline: the request
// write blocks, and only the deadline can end the call.
func TestRelayedCellBlockedWriteTimesOut(t *testing.T) {
	att := newStuckRelay()
	attach := func([]string, map[string]string) (Attached, error) {
		go func() { _, _ = fmt.Fprintln(att.outW, `{"ready":"8:1:00"}`) }()
		return att, nil
	}
	var in Interpreters
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	out, err := in.RunRelayed(ctx, launched, attach, Cell{Language: "python", Code: "1", Work: "/work", OutCap: 1 << 10, ErrCap: 1 << 10})
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("the cell took %v against a 200ms deadline", took)
	}
	if err != nil || !out.TimedOut || !out.Ended {
		t.Fatalf("outcome %+v, err %v: want a timed-out cell that ended its interpreter", out, err)
	}
	select {
	case <-att.closed:
	default:
		t.Fatal("the relay was not let go after the deadline")
	}
	if keep := in.Keep(nil); len(keep) != 0 {
		t.Fatalf("the sweep would still keep %v", keep)
	}
}

// After a cell ends on its deadline nobody reads the relay's frames again; a relay
// that keeps writing must not strand the goroutine that reads it.
func TestRelayReaderExitsAfterClose(t *testing.T) {
	before := runtime.NumGoroutine()
	att := newStuckRelay()
	attach := func([]string, map[string]string) (Attached, error) {
		go func() {
			_, _ = fmt.Fprintln(att.outW, `{"ready":"8:1:00"}`)
			sc := bufio.NewScanner(att.inR)
			for sc.Scan() {
				var req relayRequest
				_ = json.Unmarshal(sc.Bytes(), &req)
				if req.Code == nil {
					_, _ = fmt.Fprintf(att.outW, "{\"n\":%q,\"prepared\":true}\n", req.Nonce)
					continue
				}
				// Far more output frames than the reader's buffer, and never a done frame.
				for i := 0; i < 1000; i++ {
					if _, err := fmt.Fprintf(att.outW, "{\"n\":%q,\"o\":\"eA==\"}\n", req.Nonce); err != nil {
						return
					}
				}
			}
			<-att.closed
		}()
		return att, nil
	}
	var in Interpreters
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if out, err := in.RunRelayed(ctx, launched, attach, Cell{Language: "python", Code: "1", Work: "/work", OutCap: 1 << 10, ErrCap: 1 << 10}); err != nil || !out.TimedOut {
		t.Fatalf("outcome %+v, err %v: want a timed-out cell", out, err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > before {
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<16)
			t.Fatalf("%d goroutines left behind (%d before):\n%s", runtime.NumGoroutine()-before, before, buf[:runtime.Stack(buf, true)])
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// relayRequest is a request line as the relay reads it: a prepare carries files and
// no code, a run carries code.
type relayRequest struct {
	Nonce string  `json:"nonce"`
	Code  *string `json:"code"`
}

// scriptedRelay answers the nth request line (prepares and runs both count) with the
// frames answer gives it; "%N" in a frame is replaced by the request's nonce. Every
// relay it starts counts its run requests in runs.
func scriptedRelay(runs *atomic.Int64, answer func(n int, run bool) []string) AttachFunc {
	return func([]string, map[string]string) (Attached, error) {
		a := newStuckRelay()
		go func() {
			_, _ = fmt.Fprintln(a.outW, `{"ready":"8:1:00"}`)
			sc := bufio.NewScanner(a.inR)
			sc.Buffer(make([]byte, 1<<16), 1<<20)
			for n := 0; sc.Scan(); n++ {
				var req relayRequest
				if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
					return
				}
				if req.Code != nil && runs != nil {
					runs.Add(1)
				}
				for _, f := range answer(n, req.Code != nil) {
					if _, err := fmt.Fprintln(a.outW, strings.ReplaceAll(f, "%N", req.Nonce)); err != nil {
						return
					}
				}
			}
		}()
		return a, nil
	}
}

// honest answers as a working relay does: prepared, then the cell's output and done.
func honest(_ int, run bool) []string {
	if !run {
		return []string{`{"n":"%N","prepared":true}`}
	}
	return []string{`{"n":"%N","o":"Mgo="}`, `{"n":"%N","done":0}`}
}

var plainCell = Cell{Language: "python", Code: "2", Work: "/work", OutCap: 1 << 10, ErrCap: 1 << 10}

// A cell whose files the relay could not write is an error naming the file and the
// errno, since its code never ran; the relay's own text never reaches it. A fresh
// interpreter that cell started is reported by the next cell that answers.
func TestRelayedCellFilesFailed(t *testing.T) {
	for _, c := range []struct{ frame, want string }{
		{`{"n":"%N","done":3,"file":1,"errno":"EISDIR"}`, "file 2 of 2: EISDIR"},
		{`{"n":"%N","done":3,"file":7,"errno":"EISDIR"}`, "a file: EISDIR"},
		{`{"n":"%N","done":3,"file":0,"errno":"E; the code ran"}`, "file 1 of 2: an unnamed error"},
	} {
		var in Interpreters
		var runs atomic.Int64
		attach := scriptedRelay(&runs, func(n int, run bool) []string {
			if n == 0 {
				return []string{c.frame}
			}
			return honest(n, run)
		})
		cell := Cell{Language: "python", Code: "1", Work: "/work", OutCap: 1 << 10, ErrCap: 1 << 10,
			Files: []File{{Path: "a", Content: "1"}, {Path: "d", Content: "2"}}}
		_, err := in.RunRelayed(context.Background(), launched, attach, cell)
		if !errors.Is(err, ErrFiles) || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "did not run") {
			t.Fatalf("frame %s: err %v; want ErrFiles saying %q", c.frame, err, c.want)
		}
		if runs.Load() != 0 {
			t.Fatalf("frame %s: the code was sent although the prepare refused it", c.frame)
		}
		out, err := in.RunRelayed(context.Background(), launched, attach, plainCell)
		if err != nil || !out.Started || out.Stdout != "2\n" {
			t.Fatalf("the cell after: %+v, %v; want it to report the interpreter the failed cell started", out, err)
		}
		out, err = in.RunRelayed(context.Background(), launched, attach, plainCell)
		if err != nil || out.Started {
			t.Fatalf("the cell after that: %+v, %v; want the same interpreter, not reported again", out, err)
		}
	}
}

// Code of the session can write frames into the relay's stdout. After the code was
// sent, no frame may turn the call into a refusal (an error the session maps to
// "nothing ran") or make the provider send the code again: each forgery below ends
// in an interpreter that ended, with the result unknown, and one send.
func TestRelayedCellForgedFramesAfterTheCodeWasSent(t *testing.T) {
	for _, forged := range []string{
		`{"n":"%N","done":3,"file":0,"errno":"EIO"}`, // files failed: would be "did not run"
		`{"n":"%N","done":75}`,                       // no interpreter: would send the code again
		`{"done":0}`,                                 // another cell's done, or none
		`{"n":"0123","o":"Zm9yZ2VkCg=="}`,            // output of another cell
	} {
		var in Interpreters
		var runs atomic.Int64
		attach := scriptedRelay(&runs, func(n int, run bool) []string {
			if !run {
				return []string{`{"n":"%N","prepared":true}`}
			}
			return []string{forged, `{"n":"%N","done":0}`}
		})
		out, err := in.RunRelayed(context.Background(), launched, attach, plainCell)
		if err != nil {
			t.Fatalf("forged %s: err %v; want an answered cell whose result is unknown, never a refusal", forged, err)
		}
		if !out.Ended || !out.Raised {
			t.Fatalf("forged %s: outcome %+v; want the interpreter ended, the result unknown", forged, out)
		}
		if n := runs.Load(); n != 1 {
			t.Fatalf("forged %s: the code was sent %d times", forged, n)
		}
		if keep := in.Keep(nil); len(keep) != 0 {
			t.Fatalf("forged %s: the sweep would still keep %v", forged, keep)
		}
	}
}

// A frame written into the relay's stdout between calls (a timer of an earlier cell)
// must not be read as the next cell's answer.
func TestRelayedCellIgnoresAFrameLeftBetweenCalls(t *testing.T) {
	var in Interpreters
	var runs atomic.Int64
	attach := scriptedRelay(&runs, func(n int, run bool) []string {
		if run && n == 1 {
			// The first cell's answer, then a stale done that arrives before the next cell.
			return []string{`{"n":"%N","o":"MQo="}`, `{"n":"%N","done":0}`, `{"done":1}`, `{"n":"%N","done":1}`}
		}
		return honest(n, run)
	})
	if out, err := in.RunRelayed(context.Background(), launched, attach, Cell{Language: "python", Code: "1", Work: "/work", OutCap: 1 << 10, ErrCap: 1 << 10}); err != nil || out.Stdout != "1\n" {
		t.Fatalf("first cell: %+v, %v", out, err)
	}
	time.Sleep(50 * time.Millisecond) // the stale frames reach the reader
	out, err := in.RunRelayed(context.Background(), launched, attach, plainCell)
	if err != nil || out.Stdout != "2\n" || out.Raised || out.ExitCode != 0 {
		t.Fatalf("second cell: %+v, %v; want its own answer, not a frame left before it", out, err)
	}
}

// A relay that dies in the prepare has not been sent the code: the cell is refused
// as an interpreter that could not start (the session marks that not dispatched),
// and a relay that answers no interpreter twice is the same.
func TestRelayedCellPrepareFailuresSendNoCode(t *testing.T) {
	for name, answer := range map[string]func(int, bool) []string{
		"out of turn":    func(int, bool) []string { return []string{`{"n":"other","prepared":true}`} },
		"no interpreter": func(int, bool) []string { return []string{`{"n":"%N","done":75}`} },
	} {
		var in Interpreters
		var runs atomic.Int64
		_, err := in.RunRelayed(context.Background(), launched, scriptedRelay(&runs, answer), plainCell)
		if !errors.Is(err, ErrLaunch) {
			t.Fatalf("%s: err %v; want ErrLaunch", name, err)
		}
		if runs.Load() != 0 {
			t.Fatalf("%s: the code was sent", name)
		}
	}
}

// An identity the provider's check does not confirm refuses the cell before any code
// is sent: the launcher's (interp) and the relay's alike.
func TestRelayedCellUnconfirmedIdentitySendsNoCode(t *testing.T) {
	for _, refuse := range []string{"interp:", "relay:"} {
		var runs atomic.Int64
		var checked []string
		in := Interpreters{Checker: func(_ context.Context, argv []string, _ map[string]string, _ []byte, _, _ int) (ExecResult, error) {
			id := argv[len(argv)-1]
			checked = append(checked, id)
			if strings.HasPrefix(id, refuse) {
				return ExecResult{Exited: true, ExitCode: 1}, nil
			}
			return ExecResult{Exited: true}, nil
		}}
		_, err := in.RunRelayed(context.Background(), launched, scriptedRelay(&runs, honest), plainCell)
		if !errors.Is(err, ErrLaunch) {
			t.Fatalf("%s refused: err %v; want ErrLaunch", refuse, err)
		}
		if runs.Load() != 0 {
			t.Fatalf("%s refused: the code was sent", refuse)
		}
		if keep := in.Keep(nil); len(keep) != 0 {
			t.Fatalf("%s refused: the sweep would keep %v", refuse, keep)
		}
		if want := []string{"interp:7:1:00", "relay:8:1:00"}; refuse == "relay:" && strings.Join(checked, ",") != strings.Join(want, ",") {
			t.Fatalf("checked %v, want %v", checked, want)
		}
	}
}
