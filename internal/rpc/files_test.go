package rpc

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/internal/auditline"
	"github.com/plimsollmark/plimsoll/internal/withheld"
	"github.com/plimsollmark/plimsoll/protocol"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandboxtest"
)

// fileSessions is the fake session provider whose sessions carry file calls: an in-memory
// work folder of files, or run when it is set.
type fileSessions struct {
	*sandboxtest.Sessions
	run func(context.Context, sandbox.FilesRequest) (sandbox.FilesResult, error)
	// scopes are what the sessions state; nil is both.
	scopes []sandbox.FilesScope

	mu    sync.Mutex
	calls []sandbox.FilesRequest
	files map[string][]byte
}

func (p *fileSessions) SessionEnvironments() sandbox.Environments {
	e := p.Sessions.SessionEnvironments()
	scopes := p.scopes
	if scopes == nil {
		scopes = sandbox.FilesScopesBoth()
	}
	e.JavaScript.FileScopes, e.Project.FileScopes = slices.Clone(scopes), slices.Clone(scopes)
	return e
}

func (p *fileSessions) OpenSession(ctx context.Context, opts sandbox.SessionOptions) (sandbox.Session, error) {
	s, err := p.Sessions.OpenSession(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &fileSession{FakeSession: s.(*sandboxtest.FakeSession), p: p}, nil
}

type fileSession struct {
	*sandboxtest.FakeSession
	p *fileSessions
}

func (*fileSession) WorkDir() string { return "/work" }

var _ sandbox.FileRunner = (*fileSession)(nil)

func (s *fileSession) FileScopes() []sandbox.FilesScope {
	if s.p.scopes == nil {
		return sandbox.FilesScopesBoth()
	}
	return slices.Clone(s.p.scopes)
}

func (s *fileSession) RunFiles(ctx context.Context, req sandbox.FilesRequest) (sandbox.FilesResult, error) {
	if err := sandbox.ValidateFilesRequest(req); err != nil {
		return sandbox.FilesResult{}, err
	}
	p := s.p
	p.mu.Lock()
	p.calls = append(p.calls, req)
	p.mu.Unlock()
	if p.run != nil {
		return p.run(ctx, req)
	}
	res := sandbox.FilesResult{Outcome: sandbox.ProjectOutcomeCompleted, Sandbox: "fake-sessions", Isolation: sandbox.IsolationContainer}
	p.mu.Lock()
	defer p.mu.Unlock()
	switch req.Op {
	case sandbox.FilesWrite:
		if p.files == nil {
			p.files = map[string][]byte{}
		}
		p.files[string(req.Path)] = bytes.Clone(req.Content)
		res.Op, res.Written = sandbox.FilesWrite, uint64(len(req.Content))
	case sandbox.FilesRead:
		b, ok := p.files[string(req.Path)]
		if !ok {
			res.Error, res.Errno = sandbox.FilesErrorNotFound, "ENOENT"
			return res, nil
		}
		res.Op, res.Content, res.SizeAtOpen = sandbox.FilesRead, b, uint64(len(b))
	case sandbox.FilesList:
		res.Op = sandbox.FilesList
		for name, b := range p.files {
			res.Entries = append(res.Entries, sandbox.FilesEntry{Path: []byte(name), Type: sandbox.FilesTypeFile, Size: uint64(len(b))})
		}
	default:
		res.Op = req.Op
	}
	return res, nil
}

func (p *fileSessions) reached() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.calls)
}

func fileService() (*SandboxService, *fileSessions, *bytes.Buffer) {
	p := &fileSessions{Sessions: &sandboxtest.Sessions{}}
	svc := NewSandboxService(p)
	svc.Sessions = SessionConfig{MaxSessions: 4, Lifetime: 60e9, IdleTimeout: 60e9, DiskBytes: 1 << 20}
	var logs bytes.Buffer
	svc.Logger = slog.New(slog.NewJSONHandler(&logs, nil))
	return svc, p, &logs
}

func filesReq(id string, f *plimsollv1.FilesRun) *connect.Request[plimsollv1.SessionRunRequest] {
	return connect.NewRequest(&plimsollv1.SessionRunRequest{Protocol: protocol.Number, SessionId: id,
		Payload: &plimsollv1.SessionRunRequest_Files{Files: f}})
}

func writeOf(path, content string) *plimsollv1.FilesRun {
	return &plimsollv1.FilesRun{Scope: plimsollv1.FilesScope_FILES_SCOPE_WORK, Op: &plimsollv1.FilesRun_Write{Write: &plimsollv1.FilesWrite{
		Path: []byte(path), Content: []byte(content), Mode: plimsollv1.FilesWriteMode_FILES_WRITE_MODE_REPLACE, MakeParents: true}}}
}

func readOf(path string) *plimsollv1.FilesRun {
	return &plimsollv1.FilesRun{Scope: plimsollv1.FilesScope_FILES_SCOPE_WORK, Op: &plimsollv1.FilesRun_Read{Read: &plimsollv1.FilesRead{
		Path: []byte(path), MaxBytes: 1 << 20}}}
}

func openFiles(t *testing.T, svc *SandboxService, ctx context.Context) *plimsollv1.OpenSessionResponse {
	t.Helper()
	o, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	return o.Msg
}

// A file call is a session call: counted in the chain, its record checked by the same
// recomputation as any call's, the answer of a read what the write put there, and a file
// that is not there an answered NOT_FOUND, never a transport error. The open states that
// the session takes file calls and where its work folder is.
func TestFileCallsRunInTheSessionsChain(t *testing.T) {
	svc, _, _ := fileService()
	ctx := authenticatedContext("alice")
	o := openFiles(t, svc, ctx)
	if !slices.Equal(o.GetFileScopes(), []plimsollv1.FilesScope{plimsollv1.FilesScope_FILES_SCOPE_WORK, plimsollv1.FilesScope_FILES_SCOPE_SANDBOX}) || o.GetWorkDir() != "/work" {
		t.Fatalf("the open states file scopes %v, work_dir %q", o.GetFileScopes(), o.GetWorkDir())
	}
	id, fp := o.GetSessionId(), o.GetSession()
	var prev string
	for i, f := range []*plimsollv1.FilesRun{writeOf("notes/a\xff.txt", "body"), readOf("notes/a\xff.txt"), readOf("missing")} {
		req := filesReq(id, f)
		resp, err := headRun(svc, ctx, req)
		if err != nil {
			t.Fatalf("call %d: %v", i+1, err)
		}
		r, err := record.CheckSessionCall(req.Msg, resp.Msg.GetRun(), fp, uint64(i), prev)
		if err != nil {
			t.Fatalf("call %d's record: %v", i+1, err)
		}
		if r.Version != record.Version {
			t.Fatalf("call %d's record is version %d", i+1, r.Version)
		}
		prev = resp.Msg.GetRun().GetRecord().GetRecordSha256()
		got := resp.Msg.GetRun().GetFiles()
		switch i {
		case 0:
			if got.GetWrite().GetWritten() != 4 || got.GetOutcome() != plimsollv1.ProjectOutcome_PROJECT_OUTCOME_COMPLETED {
				t.Fatalf("write: %v", got)
			}
		case 1:
			if string(got.GetRead().GetContent()) != "body" || got.GetRead().GetSizeAtOpen() != 4 {
				t.Fatalf("read: %v", got)
			}
		case 2:
			if got.GetError() != plimsollv1.FilesError_FILES_ERROR_NOT_FOUND || got.GetErrno() != "ENOENT" || got.GetAnswer() != nil {
				t.Fatalf("a missing file: %v", got)
			}
		}
	}
	// A call of another kind follows in the same chain.
	req := callReq(id, "1")
	resp, err := headRun(svc, ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := record.CheckSessionCall(req.Msg, resp.Msg.GetRun(), fp, 3, prev); err != nil {
		t.Fatalf("the snippet after three file calls: %v", err)
	}
	series, counts := svc.FileCallCounts()
	want := map[FileCallSeries]int64{
		{"write", "completed", "none"}: 1, {"read", "completed", "none"}: 1, {"read", "completed", "not_found"}: 1,
	}
	if len(series) != len(want) {
		t.Fatalf("file call metrics %v %v", series, counts)
	}
	for i, s := range series {
		if want[s] != counts[i] {
			t.Errorf("%v counted %d, want %d", s, counts[i], want[s])
		}
	}
}

// A malformed file call, one to a session that carries none, and one sent to Run are refused
// before anything is dispatched, with their reasons: no provider sees them and the chain does
// not count them.
func TestFileCallRefusalsBeforeDispatch(t *testing.T) {
	svc, p, _ := fileService()
	ctx := authenticatedContext("alice")
	o := openFiles(t, svc, ctx)
	id := o.GetSessionId()
	for name, f := range map[string]*plimsollv1.FilesRun{
		"a path that leaves the work folder": readOf("../etc/passwd"),
		"an absolute WORK path":              readOf("/etc/passwd"),
		"no operation":                       {Scope: plimsollv1.FilesScope_FILES_SCOPE_WORK},
		"no scope":                           {Op: &plimsollv1.FilesRun_Stat{Stat: &plimsollv1.FilesStat{Path: []byte("a")}}},
		"a read of nothing":                  {Scope: plimsollv1.FilesScope_FILES_SCOPE_WORK, Op: &plimsollv1.FilesRun_Read{Read: &plimsollv1.FilesRead{Path: []byte("a")}}},
		"a budget below the least": {Scope: plimsollv1.FilesScope_FILES_SCOPE_WORK, Op: &plimsollv1.FilesRun_List{List: &plimsollv1.FilesList{
			Path: []byte("."), BudgetBytes: 10}}},
		"a malformed glob": {Scope: plimsollv1.FilesScope_FILES_SCOPE_WORK, Op: &plimsollv1.FilesRun_List{List: &plimsollv1.FilesList{
			Path: []byte("."), BudgetBytes: 8192, Match: []byte("a**")}}},
	} {
		_, err := headRun(svc, ctx, filesReq(id, f))
		if connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: %v; want InvalidArgument", name, err)
		}
		wantNotDispatched(t, name, err, plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_REQUEST)
		if err != nil && strings.Contains(err.Error(), "passwd") {
			t.Errorf("%s: the refusal repeats the path: %v", name, err)
		}
	}
	if n := p.reached(); n != 0 {
		t.Fatalf("%d refused calls reached the provider", n)
	}
	req := callReq(id, "1")
	resp, err := headRun(svc, ctx, req)
	if err != nil || resp.Msg.GetRun().GetRecord().GetSequence() != 1 {
		t.Fatalf("the call after the refusals: %v, %v; want the session's first", resp, err)
	}
	run := connect.NewRequest(&plimsollv1.RunRequest{Protocol: protocol.Number, Payload: &plimsollv1.RunRequest_Files{Files: readOf("a")}})
	_, err = svc.Run(ctx, run)
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("Run with a files payload: %v", err)
	}
	wantNotDispatched(t, "Run with a files payload", err, plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_REQUEST)
}

// A session that states the sandbox scope alone (OpenShell's: its work folder is not a mount of
// its own) says so in Describe and at open, refuses a WORK call before anything is dispatched
// (unimplemented, reason unsupported), uncounted by the chain, and carries a SANDBOX call,
// whose record names that scope.
func TestFileCallInAScopeNotStatedIsRefusedBeforeDispatch(t *testing.T) {
	svc, p, _ := fileService()
	p.scopes = sandbox.FilesScopesSandboxOnly()
	ctx := authenticatedContext("alice")
	sandboxOnly := []plimsollv1.FilesScope{plimsollv1.FilesScope_FILES_SCOPE_SANDBOX}
	d, err := svc.Describe(ctx, connect.NewRequest(&plimsollv1.DescribeRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if got := d.Msg.GetSessionEnvironment().GetFileScopes(); !slices.Equal(got, sandboxOnly) {
		t.Fatalf("Describe states the session file scopes %v", got)
	}
	if got := d.Msg.GetProjectEnvironment().GetFileScopes(); len(got) != 0 {
		t.Fatalf("Describe states file scopes %v on the runs' project environment", got)
	}
	o := openFiles(t, svc, ctx)
	if !slices.Equal(o.GetFileScopes(), sandboxOnly) {
		t.Fatalf("the open states the file scopes %v", o.GetFileScopes())
	}
	id, fp := o.GetSessionId(), o.GetSession()
	for name, f := range map[string]*plimsollv1.FilesRun{"a WORK read": readOf("a"), "a WORK write": writeOf("a", "x")} {
		_, err := headRun(svc, ctx, filesReq(id, f))
		if connect.CodeOf(err) != connect.CodeUnimplemented {
			t.Errorf("%s: %v; want Unimplemented", name, err)
		}
		wantNotDispatched(t, name, err, plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_UNSUPPORTED)
	}
	if n := p.reached(); n != 0 {
		t.Fatalf("%d refused calls reached the provider", n)
	}
	sb := &plimsollv1.FilesRun{Scope: plimsollv1.FilesScope_FILES_SCOPE_SANDBOX, Op: &plimsollv1.FilesRun_Write{Write: &plimsollv1.FilesWrite{
		Path: []byte("/work/a"), Content: []byte("x"), Mode: plimsollv1.FilesWriteMode_FILES_WRITE_MODE_REPLACE}}}
	req := filesReq(id, sb)
	resp, err := headRun(svc, ctx, req)
	if err != nil {
		t.Fatalf("a SANDBOX write: %v", err)
	}
	rec, err := record.CheckSessionCall(req.Msg, resp.Msg.GetRun(), fp, 0, "")
	if err != nil {
		t.Fatalf("the SANDBOX write's record: %v", err)
	}
	if rec.Sequence != 1 || p.reached() != 1 {
		t.Fatalf("the SANDBOX write is call %d, %d calls reached the provider; want the first, 1", rec.Sequence, p.reached())
	}
	// The record binds the scope: the same call under the WORK scope digests otherwise.
	work := filesReq(id, &plimsollv1.FilesRun{Scope: plimsollv1.FilesScope_FILES_SCOPE_WORK, Op: sb.GetOp()})
	if record.SessionRunRequestDigest(work.Msg) == record.SessionRunRequestDigest(req.Msg) {
		t.Fatal("the request digest does not cover the scope")
	}
}

// A file call cut after its helper started (an error with no mark) may have run: the daemon
// chains it as unanswered, the caller gets that record, and the next call follows it.
func TestACutFileCallIsChainedUnanswered(t *testing.T) {
	svc, p, _ := fileService()
	p.run = func(context.Context, sandbox.FilesRequest) (sandbox.FilesResult, error) {
		return sandbox.FilesResult{}, errors.New("the docker exec's stream broke")
	}
	ctx := authenticatedContext("alice")
	o := openFiles(t, svc, ctx)
	id, fp := o.GetSessionId(), o.GetSession()
	cut := filesReq(id, writeOf("a", "half"))
	_, err := headRun(svc, ctx, cut)
	if _, marked := notDispatchedOf(err); err == nil || marked {
		t.Fatalf("a cut call: %v (marked %v); want an unmarked error", err, marked)
	}
	var unanswered *plimsollv1.RunRecord
	var ce *connect.Error
	if errors.As(err, &ce) {
		for _, d := range ce.Details() {
			if v, _ := d.Value(); v != nil {
				if u, ok := v.(*plimsollv1.UnansweredCall); ok {
					unanswered = u.GetRecord()
				}
			}
		}
	}
	if unanswered == nil {
		t.Fatalf("no unanswered record: %v", err)
	}
	if _, err := record.CheckUnanswered(cut.Msg, unanswered, fp, 0, ""); err != nil {
		t.Fatalf("the unanswered record: %v", err)
	}
	p.run = nil
	next := filesReq(id, readOf("a"))
	resp, err := headRun(svc, ctx, next)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := record.CheckSessionCall(next.Msg, resp.Msg.GetRun(), fp, 1, unanswered.GetRecordSha256()); err != nil {
		t.Fatalf("the call after the cut does not follow its record: %v", err)
	}
	series, counts := svc.FileCallCounts()
	if len(series) != 2 || series[1] != (FileCallSeries{"write", "unanswered", "none"}) || counts[1] != 1 {
		t.Fatalf("metrics %v %v", series, counts)
	}
}

// Every path a file call names and a write's content pass the ship scan: a withheld file
// written through a file call is refused before dispatch, as it is as a project's file, and
// so is a withheld value in a path, a rename's target or a listing's glob.
func TestFileCallsPassTheShipScan(t *testing.T) {
	svc, p, _ := fileService()
	svc.Withheld = withheldSetOf(t, withheld.ModeRefuse, nil,
		withheldFile(harnessSource, "harness.py", ""), withheldValue(heldOutSeed, "seeds.txt:3", ""))
	ctx := authenticatedContext("alice")
	o := openFiles(t, svc, ctx)
	id := o.GetSessionId()
	work := plimsollv1.FilesScope_FILES_SCOPE_WORK
	for name, f := range map[string]*plimsollv1.FilesRun{
		"a withheld file's content":  writeOf("helpers/model.py", harnessSource),
		"a withheld value in a path": readOf("runs/" + heldOutSeed + "/out"),
		"a rename's target": {Scope: work, Op: &plimsollv1.FilesRun_Rename{Rename: &plimsollv1.FilesRename{
			FromPath: []byte("a"), ToPath: []byte("seed-" + heldOutSeed)}}},
		"a listing's glob": {Scope: work, Op: &plimsollv1.FilesRun_List{List: &plimsollv1.FilesList{
			Path: []byte("."), BudgetBytes: 8192, Match: []byte("*" + heldOutSeed + "*")}}},
		"a read_many path": {Scope: work, Op: &plimsollv1.FilesRun_ReadMany{ReadMany: &plimsollv1.FilesReadMany{
			Paths: [][]byte{[]byte("ok"), []byte(heldOutSeed)}, MaxBytesEach: 10, BudgetBytes: 8192}}},
	} {
		_, err := headRun(svc, ctx, filesReq(id, f))
		if _, marked := notDispatchedOf(err); connect.CodeOf(err) != connect.CodePermissionDenied || !marked {
			t.Errorf("%s: %v; want PermissionDenied, not dispatched", name, err)
		}
	}
	if n := p.reached(); n != 0 {
		t.Fatalf("%d withheld calls reached the provider", n)
	}
	// What the scan passes runs.
	if _, err := headRun(svc, ctx, filesReq(id, writeOf("agent.py", "print('hi')"))); err != nil {
		t.Fatal(err)
	}
}

// A file call's audit line is metadata only: its operation, scope, counts and sizes, its
// outcome and error, never a path, a listed name, a glob or content.
func TestFileCallAuditLineHoldsNoPathOrContent(t *testing.T) {
	svc, _, logs := fileService()
	ctx := authenticatedContext("alice")
	o := openFiles(t, svc, ctx)
	id := o.GetSessionId()
	const name, body, glob = "secret-name-7f3a", "body-content-91c2", "glob-pattern-55e1*"
	for _, f := range []*plimsollv1.FilesRun{
		writeOf(name, body),
		readOf(name),
		{Scope: plimsollv1.FilesScope_FILES_SCOPE_WORK, Op: &plimsollv1.FilesRun_List{List: &plimsollv1.FilesList{
			Path: []byte("."), Recursive: true, BudgetBytes: 8192, Match: []byte(glob)}}},
	} {
		if _, err := headRun(svc, ctx, filesReq(id, f)); err != nil {
			t.Fatal(err)
		}
	}
	for _, secret := range []string{name, body, strings.TrimSuffix(glob, "*")} {
		if strings.Contains(logs.String(), secret) {
			t.Errorf("the log holds %q:\n%s", secret, logs.String())
		}
	}
	runs, err := auditline.Parse(bytes.NewReader(logs.Bytes()))
	if err != nil || len(runs) != 3 {
		t.Fatalf("%d run lines, %v:\n%s", len(runs), err, logs.String())
	}
	w, r, l := runs[0], runs[1], runs[2]
	switch {
	case w.Msg != auditline.Files || w.Op != "files" || w.FilesOp != "write" || w.FilesScope != "work" || w.BytesIn != len(body) || w.Paths != 1 || w.FilesError != "none" || w.Outcome != "completed":
		t.Errorf("write's line: %+v", w)
	case r.FilesOp != "read" || r.BytesOut != len(body) || r.BytesIn != 0:
		t.Errorf("read's line: %+v", r)
	case l.FilesOp != "list" || l.Entries != 1 || l.Sandbox != "fake-sessions" || l.Isolation != "container":
		t.Errorf("list's line: %+v", l)
	}
}

// Whatever shape a provider returns, the daemon states a file call's result in the one shape
// every verifier accepts (docs/run-records.md, "A file call's answer"): an outcome other than
// completed loses any error and answer, an answered error loses its answer, and a completed
// result that breaks the rule otherwise is protocol_error with nothing. Each answer's record
// is checked with the request's operation, as every client checks it.
func TestFileCallResultsAgreeWithTheRecordRule(t *testing.T) {
	ok := sandbox.FilesResult{Sandbox: "fake-sessions", Isolation: sandbox.IsolationContainer}
	with := func(o sandbox.ProjectOutcome, a sandbox.FilesAnswer) sandbox.FilesResult {
		r := ok
		r.Outcome, r.FilesAnswer = o, a
		return r
	}
	read := sandbox.FilesAnswer{Op: sandbox.FilesRead, Content: []byte("x"), SizeAtOpen: 1}
	cases := []struct {
		name    string
		res     sandbox.FilesResult
		outcome plimsollv1.ProjectOutcome
		err     plimsollv1.FilesError
		answer  bool
	}{
		{"an answer", with(sandbox.ProjectOutcomeCompleted, read), plimsollv1.ProjectOutcome_PROJECT_OUTCOME_COMPLETED, 0, true},
		{"an error beside an answer", with(sandbox.ProjectOutcomeCompleted, sandbox.FilesAnswer{Op: sandbox.FilesRead, Error: sandbox.FilesErrorNotFound, Errno: "ENOENT", Content: []byte("x")}),
			plimsollv1.ProjectOutcome_PROJECT_OUTCOME_COMPLETED, plimsollv1.FilesError_FILES_ERROR_NOT_FOUND, false},
		{"a timeout with an error", with(sandbox.ProjectOutcomeTimedOut, sandbox.FilesAnswer{Error: sandbox.FilesErrorOther, Errno: "EIO"}),
			plimsollv1.ProjectOutcome_PROJECT_OUTCOME_TIMED_OUT, 0, false},
		{"a protocol error with an answer", with(sandbox.ProjectOutcomeProtocolError, read), plimsollv1.ProjectOutcome_PROJECT_OUTCOME_PROTOCOL_ERROR, 0, false},
		{"an answer of another operation", with(sandbox.ProjectOutcomeCompleted, sandbox.FilesAnswer{Op: sandbox.FilesStat, Size: 1}),
			plimsollv1.ProjectOutcome_PROJECT_OUTCOME_PROTOCOL_ERROR, 0, false},
		{"no answer and no error", with(sandbox.ProjectOutcomeCompleted, sandbox.FilesAnswer{}), plimsollv1.ProjectOutcome_PROJECT_OUTCOME_PROTOCOL_ERROR, 0, false},
		{"an errno with no error", with(sandbox.ProjectOutcomeCompleted, sandbox.FilesAnswer{Op: sandbox.FilesRead, Errno: "ENOENT"}),
			plimsollv1.ProjectOutcome_PROJECT_OUTCOME_PROTOCOL_ERROR, 0, false},
		{"setup_failed", with(sandbox.ProjectOutcomeSetupFailed, read), plimsollv1.ProjectOutcome_PROJECT_OUTCOME_PROTOCOL_ERROR, 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			svc, p, _ := fileService()
			p.run = func(context.Context, sandbox.FilesRequest) (sandbox.FilesResult, error) { return c.res, nil }
			ctx := authenticatedContext("alice")
			o := openFiles(t, svc, ctx)
			req := filesReq(o.GetSessionId(), readOf("a"))
			resp, err := headRun(svc, ctx, req)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := record.CheckSessionCall(req.Msg, resp.Msg.GetRun(), o.GetSession(), 0, ""); err != nil {
				t.Fatalf("the record: %v", err)
			}
			f := resp.Msg.GetRun().GetFiles()
			if f.GetOutcome() != c.outcome || f.GetError() != c.err || (f.GetAnswer() != nil) != c.answer {
				t.Fatalf("stated %v; want outcome %v, error %v, an answer %v", f, c.outcome, c.err, c.answer)
			}
		})
	}
	// A read_many item holding bytes beside its error is not stated.
	svc, p, _ := fileService()
	p.run = func(context.Context, sandbox.FilesRequest) (sandbox.FilesResult, error) {
		return with(sandbox.ProjectOutcomeCompleted, sandbox.FilesAnswer{Op: sandbox.FilesReadMany,
			Items: []sandbox.FilesItem{{Error: sandbox.FilesErrorNotFound, SizeAtOpen: 3}}}), nil
	}
	ctx := authenticatedContext("alice")
	o := openFiles(t, svc, ctx)
	req := filesReq(o.GetSessionId(), &plimsollv1.FilesRun{Scope: plimsollv1.FilesScope_FILES_SCOPE_WORK,
		Op: &plimsollv1.FilesRun_ReadMany{ReadMany: &plimsollv1.FilesReadMany{Paths: [][]byte{[]byte("a")}, MaxBytesEach: 64, BudgetBytes: 8192}}})
	resp, err := headRun(svc, ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := record.CheckSessionCall(req.Msg, resp.Msg.GetRun(), o.GetSession(), 0, ""); err != nil {
		t.Fatalf("the record: %v", err)
	}
	if f := resp.Msg.GetRun().GetFiles(); f.GetOutcome() != plimsollv1.ProjectOutcome_PROJECT_OUTCOME_PROTOCOL_ERROR || f.GetAnswer() != nil {
		t.Fatalf("a read_many item with bytes and an error: %v", f)
	}
}
