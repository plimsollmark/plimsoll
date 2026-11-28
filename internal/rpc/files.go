package rpc

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/internal/fileswire"
	"github.com/plimsollmark/plimsoll/internal/withheld"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// filesKind is one operation on a session's files (FilesRun), carried out inside the session's
// sandbox by plimsoll's native helper (sandbox.FileRunner). It is a session call like any
// other: the same envelope, head, floor, rule and request ID, one at a time, in the chain,
// with a record, and the record of a call that may have run when it ends without an answer.
// Run refuses it (a file call is a session call), and a session whose provider carries none
// refuses it as unsupported, both before anything is dispatched.
//
// What a file call carries into the sandbox (every path, a write's content, a listing's glob
// and cursor) passes the ship scan, as a project's files do. A file call carries no grant, so
// it makes no CallTrace and the advisor has nothing to read. Its audit line is metadata only:
// the operation, the scope, the bytes carried in and returned, the entry count, the error, the
// outcome, the duration, never a path, a name from a listing, a glob or content.
type filesKind struct {
	grantHolder
	p   *plimsollv1.FilesRun
	req sandbox.FilesRequest
	res sandbox.FilesResult
}

func (*filesKind) op() string  { return "files" }
func (*filesKind) msg() string { return "file call" }

// sessionFiles is sess's file runner, nil when its provider carries no file calls (SessionRun
// refuses a file call to it before anything is dispatched).
func sessionFiles(sess sandbox.Session) func(context.Context, sandbox.FilesRequest) (sandbox.FilesResult, error) {
	if fr, ok := sess.(sandbox.FileRunner); ok {
		return fr.RunFiles
	}
	return nil
}

func (k *filesKind) check(env envelope) error {
	k.req = sandbox.FilesRequest{FilesCall: fileswire.Call(k.p), Timeout: env.timeout, MinimumIsolation: env.minimum, Software: env.software}
	return sandbox.ValidateFilesRequest(k.req)
}
func (*filesKind) profile() string { return "" }

// environment is the session's project environment: a file call runs in the session's one
// sandbox, as a cell does.
func (*filesKind) environment(t target) sandbox.PayloadEnvironment { return t.software.Project }

// opWord is the operation as the audit line and the metrics name it: one of a closed set,
// never the caller's text (an empty operation is refused before any line is written).
func (k *filesKind) opWord() string {
	if slices.Contains(sandbox.FilesOps, k.req.Op) {
		return string(k.req.Op)
	}
	return "none"
}

func (k *filesKind) requestAttrs() []slog.Attr {
	scope := "work"
	if k.req.Scope == sandbox.FilesScopeSandbox {
		scope = "sandbox"
	}
	paths := len(k.req.Paths)
	if k.req.Op != sandbox.FilesReadMany {
		paths = 1
		if k.req.Op == sandbox.FilesRename {
			paths = 2
		}
	}
	return []slog.Attr{slog.String("files_op", k.opWord()), slog.String("files_scope", scope),
		slog.Int("paths", paths), slog.Int("bytes_in", len(k.req.Content))}
}
func (k *filesKind) dispatch(ctx context.Context, t target) (err error) {
	k.res, err = t.files(ctx, k.req)
	if err == nil {
		k.res = filesAgreeing(k.req.Op, k.res)
	}
	return err
}

// filesAgreeing is res as the daemon states it: in the one shape a verifier accepts
// (docs/run-records.md, "A file call's answer"), whatever the provider returned. An outcome
// other than completed carries no error and no answer; completed with an error carries no
// answer. A completed result that breaks the rule otherwise (an errno name with no error, an
// answer of another operation than op, a read_many item with both bytes and an error, or an
// outcome that is not a file call's) is protocol_error with nothing: the daemon could not read
// a usable answer from the provider, which is what that outcome says.
func filesAgreeing(op sandbox.FilesOp, res sandbox.FilesResult) sandbox.FilesResult {
	broken := res
	broken.Outcome, broken.FilesAnswer = sandbox.ProjectOutcomeProtocolError, sandbox.FilesAnswer{}
	switch res.Outcome {
	case sandbox.ProjectOutcomeTimedOut, sandbox.ProjectOutcomeProtocolError, sandbox.ProjectOutcomeRunnerFailed:
		res.FilesAnswer = sandbox.FilesAnswer{}
		return res
	case sandbox.ProjectOutcomeCompleted:
	default:
		return broken
	}
	if res.Error != sandbox.FilesErrorNone {
		res.FilesAnswer = sandbox.FilesAnswer{Error: res.Error, Errno: res.Errno}
		return res
	}
	if res.Errno != "" || res.Op != op {
		return broken
	}
	for _, it := range res.Items {
		if (it.Error != sandbox.FilesErrorNone && (len(it.Content) != 0 || it.SizeAtOpen != 0)) || (it.Error == sandbox.FilesErrorNone && it.Errno != "") {
			return broken
		}
	}
	return res
}
func (*filesKind) trace() *sandbox.CallTrace { return nil }
func (k *filesKind) ran() evidence {
	return evidence{k.res.Sandbox, k.res.Isolation, k.res.SoftwareIdentity, k.res.EnvironmentIdentity, k.res.Instance, k.res.Policy}
}
func (k *filesKind) took(time.Time) time.Duration { return k.res.Duration }

// bytesOut is the bytes of file content the answer returns.
func (k *filesKind) bytesOut() int {
	n := len(k.res.Content)
	for _, it := range k.res.Items {
		n += len(it.Content)
	}
	return n
}

func (k *filesKind) resultAttrs() []slog.Attr {
	entries := len(k.res.Entries) + len(k.res.Items)
	return []slog.Attr{
		slog.String("outcome", k.res.Outcome.String()),
		slog.String("files_error", k.res.Error.String()),
		slog.Int("bytes_out", k.bytesOut()),
		slog.Int("entries", entries),
		slog.Bool("more", k.res.More),
		slog.Bool("timed_out", k.res.Outcome == sandbox.ProjectOutcomeTimedOut),
	}
}

func (k *filesKind) answer(resp *plimsollv1.RunResponse, _ []*plimsollv1.AdviceFinding) {
	resp.Result = &plimsollv1.RunResponse_Files{Files: fileswire.Result(k.res)}
}

// shipped is every path the call names, a write's content, and a listing's glob and cursor:
// what the call carries into the sandbox, scanned as a project's files are (a path is a
// part of its own, so a withheld digest of one is found, as a project file's path is).
func (k *filesKind) shipped() func() []withheld.Part {
	return func() []withheld.Part {
		c := k.req.FilesCall
		var parts []withheld.Part
		add := func(where string, data []byte, whole bool) {
			if len(data) > 0 {
				parts = append(parts, withheld.Part{Where: where, Data: data, Whole: whole})
			}
		}
		switch c.Op {
		case sandbox.FilesRename:
			add("from_path", c.Path, false)
			add("to_path", c.To, false)
		case sandbox.FilesReadMany:
			for i, p := range c.Paths {
				add(fmt.Sprintf("paths[%d]", i), p, false)
			}
		default:
			add("path", c.Path, false)
		}
		add("content", c.Content, true)
		add("match", c.Match, false)
		add("after", c.After, false)
		return parts
	}
}

// fileCallStats counts file calls for /metrics by operation, outcome and error: each label
// from a closed set (the operations, the outcome words with "unanswered" and "refused", the
// error words), so nothing a caller sends becomes a label.
type fileCallStats struct {
	mu     sync.Mutex
	counts map[FileCallSeries]int64
}

// FileCallSeries is one label set of plimsoll_file_calls_total.
type FileCallSeries struct {
	Op, Outcome, Error string
}

// observe counts one file call: answered (err nil, its outcome and error), refused before
// dispatch (marked), or unanswered.
func (st *fileCallStats) observe(k *filesKind, err error) {
	s := FileCallSeries{Op: k.opWord(), Outcome: k.res.Outcome.String(), Error: k.res.Error.String()}
	if err != nil {
		s.Error = sandbox.FilesErrorNone.String()
		s.Outcome = "unanswered"
		if _, marked := notDispatchedOf(err); marked {
			s.Outcome = "refused"
		}
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.counts == nil {
		st.counts = map[FileCallSeries]int64{}
	}
	st.counts[s]++
}

// FileCallCounts is the file calls counted so far, by series, in a stable order.
func (s *SandboxService) FileCallCounts() ([]FileCallSeries, []int64) {
	s.fileCalls.mu.Lock()
	defer s.fileCalls.mu.Unlock()
	keys := make([]FileCallSeries, 0, len(s.fileCalls.counts))
	for k := range s.fileCalls.counts {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b FileCallSeries) int {
		return strings.Compare(a.Op+"\x00"+a.Outcome+"\x00"+a.Error, b.Op+"\x00"+b.Outcome+"\x00"+b.Error)
	})
	counts := make([]int64, len(keys))
	for i, k := range keys {
		counts[i] = s.fileCalls.counts[k]
	}
	return keys, counts
}
