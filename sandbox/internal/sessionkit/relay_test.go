package sessionkit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync"
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
			// Far more output frames than the reader's buffer, and never a done frame.
			for i := 0; i < 1000; i++ {
				if _, err := fmt.Fprintln(att.outW, `{"o":"eA=="}`); err != nil {
					return
				}
			}
			<-att.closed
		}()
		go func() { _, _ = io.Copy(io.Discard, att.inR) }() // this relay reads its requests
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

// scriptedRelay answers each request line with the frames answer gives it.
func scriptedRelay(answer func(n int) []string) AttachFunc {
	return func([]string, map[string]string) (Attached, error) {
		a := newStuckRelay()
		go func() {
			_, _ = fmt.Fprintln(a.outW, `{"ready":"8:1:00"}`)
			buf := make([]byte, 1<<16)
			for n := 0; ; n++ {
				if _, err := a.inR.Read(buf); err != nil {
					return
				}
				for _, f := range answer(n) {
					if _, err := fmt.Fprintln(a.outW, f); err != nil {
						return
					}
				}
			}
		}()
		return a, nil
	}
}

// A cell whose files the relay could not write is an error naming the file and the
// errno, since its code never ran; the relay's own text never reaches it. A fresh
// interpreter that cell started is reported by the next cell that answers.
func TestRelayedCellFilesFailed(t *testing.T) {
	for _, c := range []struct{ frame, want string }{
		{`{"done":3,"file":1,"errno":"EISDIR"}`, "file 2 of 2: EISDIR"},
		{`{"done":3,"file":7,"errno":"EISDIR"}`, "a file: EISDIR"},
		{`{"done":3,"file":0,"errno":"E; the code ran"}`, "file 1 of 2: an unnamed error"},
	} {
		var in Interpreters
		attach := scriptedRelay(func(n int) []string {
			if n == 0 {
				return []string{c.frame}
			}
			return []string{`{"o":"Mgo="}`, `{"done":0}`}
		})
		cell := Cell{Language: "python", Code: "1", Work: "/work", OutCap: 1 << 10, ErrCap: 1 << 10,
			Files: []File{{Path: "a", Content: "1"}, {Path: "d", Content: "2"}}}
		_, err := in.RunRelayed(context.Background(), launched, attach, cell)
		if !errors.Is(err, ErrFiles) || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "did not run") {
			t.Fatalf("frame %s: err %v; want ErrFiles saying %q", c.frame, err, c.want)
		}
		out, err := in.RunRelayed(context.Background(), launched, attach, Cell{Language: "python", Code: "2", Work: "/work", OutCap: 1 << 10, ErrCap: 1 << 10})
		if err != nil || !out.Started || out.Stdout != "2\n" {
			t.Fatalf("the cell after: %+v, %v; want it to report the interpreter the failed cell started", out, err)
		}
		out, err = in.RunRelayed(context.Background(), launched, attach, Cell{Language: "python", Code: "3", Work: "/work", OutCap: 1 << 10, ErrCap: 1 << 10})
		if err != nil || out.Started {
			t.Fatalf("the cell after that: %+v, %v; want the same interpreter, not reported again", out, err)
		}
	}
}
