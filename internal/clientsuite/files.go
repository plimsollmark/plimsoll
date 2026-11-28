package clientsuite

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"sort"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/internal/rpc"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandboxtest"
)

// The files daemon serves the shared file-call cases (internal/clientcases/testdata/
// files-calls.json): the real RPC handler over sessions whose file calls an in-memory work
// folder answers, so every client's checked file call runs against the daemon's own
// chain, records, head check and request ID echo. A path is a key of bytes: nothing here
// decodes or cleans one, so a client that changed a name on its way out or back is seen in
// the answers. A call whose only path is "cut" fails after it reached the provider, unmarked,
// so the daemon sends that call's unanswered record. A SessionRun whose trace ID is
// FilesForgeTrace(name) gets the honest answer with one thing forged (FilesForgeries).
func serveFiles(t *testing.T) []string {
	svc := sessionService(filesProvider{&sandboxtest.Sessions{}}, rpc.SessionConfig{MaxSessions: 64, Lifetime: time.Minute, IdleTimeout: time.Minute})
	return []string{Serve(t, forgingFiles{svc}, nil, nil)}
}

// ServeFiles serves the files daemon and returns its URL, for the Go client's runner.
func ServeFiles(t *testing.T) string { return serveFiles(t)[0] }

// FilesForgeries are the forged answers the files daemon gives, by name: each answer's
// record still recomputes on its own (it is sealed again) unless the name says otherwise.
//
//   - answer-op: the answer of another operation than the one asked (a stat answer for any
//     call but a stat, which gets a read answer).
//   - error-beside-answer: the answer with an error stated beside it.
//   - result: an answer's bytes or numbers changed after its record was sealed.
//   - chain: the record placed after another call than the client's last.
//   - kind: a project's result for the file call.
//   - lost: the call runs and its answer never arrives (an unmarked error with no record).
var FilesForgeries = []string{"answer-op", "error-beside-answer", "result", "chain", "kind", "lost"}

// FilesForgeTrace is the trace ID that asks the files daemon for the forgery named.
func FilesForgeTrace(name string) string { return "forge-files-" + name }

// FilesCut is the path whose file call fails unmarked after it reached the provider.
const FilesCut = "cut"

// filesProvider is the in-memory session provider whose sessions take file calls.
type filesProvider struct{ *sandboxtest.Sessions }

func (p filesProvider) SessionEnvironments() sandbox.Environments {
	e := p.Sessions.SessionEnvironments()
	e.Project.FileScopes = filesScopes()
	return e
}

func (p filesProvider) OpenSession(ctx context.Context, opts sandbox.SessionOptions) (sandbox.Session, error) {
	s, err := p.Sessions.OpenSession(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &filesSession{FakeSession: s.(*sandboxtest.FakeSession), files: map[string][]byte{}, dirs: map[string]bool{".": true}}, nil
}

// filesSession is a fake session with a work folder in memory: files by path, and the
// folders that exist ("." is the work folder).
type filesSession struct {
	*sandboxtest.FakeSession
	mu    sync.Mutex
	files map[string][]byte
	dirs  map[string]bool
}

func (*filesSession) WorkDir() string { return "/work" }

// filesScopes is the work scope alone: the files daemon's sessions carry no other.
func filesScopes() []sandbox.FilesScope { return []sandbox.FilesScope{sandbox.FilesScopeWork} }

var _ sandbox.FileRunner = (*filesSession)(nil)

func (*filesSession) FileScopes() []sandbox.FilesScope { return filesScopes() }

// parent is the folder p sits in, "." for one in the work folder.
func parent(p string) string {
	if i := bytes.LastIndexByte([]byte(p), '/'); i >= 0 {
		return p[:i]
	}
	return "."
}

func (s *filesSession) RunFiles(_ context.Context, req sandbox.FilesRequest) (sandbox.FilesResult, error) {
	res := sandbox.FilesResult{Outcome: sandbox.ProjectOutcomeCompleted, Sandbox: "fake-sessions", Isolation: sandbox.IsolationContainer}
	if err := sandbox.ValidateFilesRequest(req); err != nil {
		return res, err
	}
	if err := sandbox.CheckFilesScope(req.Scope, s.FileScopes(), "fake-sessions"); err != nil {
		return res, err
	}
	if string(req.Path) == FilesCut {
		return res, errors.New("the call's stream broke after it reached the sandbox")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	fail := func(e sandbox.FilesError, errno string) (sandbox.FilesResult, error) {
		res.Error, res.Errno = e, errno
		return res, nil
	}
	p := string(req.Path)
	switch req.Op {
	case sandbox.FilesStat:
		switch b, isFile := s.files[p]; {
		case isFile:
			res.Op, res.Type, res.Size, res.Mode = sandbox.FilesStat, sandbox.FilesTypeFile, uint64(len(b)), 0o644
		case s.dirs[p]:
			res.Op, res.Type, res.Mode = sandbox.FilesStat, sandbox.FilesTypeDir, 0o755
		default:
			return fail(sandbox.FilesErrorNotFound, "ENOENT")
		}
	case sandbox.FilesRead:
		b, ok := s.files[p]
		if !ok {
			if s.dirs[p] {
				return fail(sandbox.FilesErrorIsDir, "EISDIR")
			}
			return fail(sandbox.FilesErrorNotFound, "ENOENT")
		}
		lo := min(req.Offset, uint64(len(b)))
		hi := min(lo+uint64(req.MaxBytes), uint64(len(b)))
		res.Op, res.Content, res.SizeAtOpen = sandbox.FilesRead, bytes.Clone(b[lo:hi]), uint64(len(b))
	case sandbox.FilesWrite:
		if s.dirs[p] {
			return fail(sandbox.FilesErrorIsDir, "EISDIR")
		}
		if !s.dirs[parent(p)] {
			if !req.Parents {
				return fail(sandbox.FilesErrorNotFound, "ENOENT")
			}
			for d := parent(p); d != "."; d = parent(d) {
				s.dirs[d] = true
			}
		}
		old, there := s.files[p]
		switch req.Mode {
		case sandbox.FilesWriteCreateOnly:
			if there {
				return fail(sandbox.FilesErrorExists, "EEXIST")
			}
			s.files[p] = bytes.Clone(req.Content)
		case sandbox.FilesWriteAppend:
			s.files[p] = append(bytes.Clone(old), req.Content...)
		default:
			s.files[p] = bytes.Clone(req.Content)
		}
		res.Op, res.Written = sandbox.FilesWrite, uint64(len(req.Content))
	case sandbox.FilesList:
		if !s.dirs[p] {
			if _, ok := s.files[p]; ok {
				return fail(sandbox.FilesErrorNotDir, "ENOTDIR")
			}
			return fail(sandbox.FilesErrorNotFound, "ENOENT")
		}
		if len(req.Match) > 0 || req.Recursive {
			return res, sandbox.NotDispatched(sandbox.RefusalUnsupported, errors.New("the files daemon lists one folder, with no glob"))
		}
		res.Op = sandbox.FilesList
		prefix := p + "/"
		if p == "." {
			prefix = ""
		}
		var names []string
		for _, set := range []map[string]bool{s.dirs, keys(s.files)} {
			for n := range set {
				if n != "." && parent(n) == p {
					names = append(names, n[len(prefix):])
				}
			}
		}
		sort.Strings(names) // Go compares strings by their bytes
		for _, n := range names {
			if len(req.After) > 0 && n <= string(req.After) {
				continue
			}
			e := sandbox.FilesEntry{Path: []byte(n), Type: sandbox.FilesTypeDir}
			if b, ok := s.files[prefix+n]; ok {
				e.Type, e.Size = sandbox.FilesTypeFile, uint64(len(b))
			}
			res.Entries = append(res.Entries, e)
		}
	case sandbox.FilesReadMany:
		res.Op = sandbox.FilesReadMany
		for _, q := range req.Paths {
			b, ok := s.files[string(q)]
			switch {
			case ok && len(b) > int(req.MaxBytes):
				res.Items = append(res.Items, sandbox.FilesItem{Error: sandbox.FilesErrorTooLarge, Errno: "EFBIG"})
			case ok:
				res.Items = append(res.Items, sandbox.FilesItem{Content: bytes.Clone(b), SizeAtOpen: uint64(len(b))})
			case s.dirs[string(q)]:
				res.Items = append(res.Items, sandbox.FilesItem{Error: sandbox.FilesErrorIsDir, Errno: "EISDIR"})
			default:
				res.Items = append(res.Items, sandbox.FilesItem{Error: sandbox.FilesErrorNotFound, Errno: "ENOENT"})
			}
		}
	case sandbox.FilesMakeDir:
		if _, ok := s.files[p]; ok {
			return fail(sandbox.FilesErrorExists, "EEXIST")
		}
		if s.dirs[p] && !req.Parents {
			return fail(sandbox.FilesErrorExists, "EEXIST")
		}
		if !s.dirs[parent(p)] && !req.Parents {
			return fail(sandbox.FilesErrorNotFound, "ENOENT")
		}
		for d := p; d != "."; d = parent(d) {
			s.dirs[d] = true
		}
		res.Op = sandbox.FilesMakeDir
	case sandbox.FilesRemove:
		_, isFile := s.files[p]
		switch {
		case req.Dir && s.dirs[p]:
			for n := range s.files {
				if parent(n) == p {
					return fail(sandbox.FilesErrorNotEmpty, "ENOTEMPTY")
				}
			}
			for n := range s.dirs {
				if n != p && parent(n) == p {
					return fail(sandbox.FilesErrorNotEmpty, "ENOTEMPTY")
				}
			}
			delete(s.dirs, p)
		case req.Dir && isFile:
			return fail(sandbox.FilesErrorNotDir, "ENOTDIR")
		case !req.Dir && s.dirs[p]:
			return fail(sandbox.FilesErrorIsDir, "EISDIR")
		case isFile:
			delete(s.files, p)
		default:
			return fail(sandbox.FilesErrorNotFound, "ENOENT")
		}
		res.Op = sandbox.FilesRemove
	case sandbox.FilesRename:
		b, ok := s.files[p]
		to := string(req.To)
		switch {
		case !ok:
			return fail(sandbox.FilesErrorNotFound, "ENOENT")
		case !s.dirs[parent(to)]:
			return fail(sandbox.FilesErrorNotFound, "ENOENT")
		case s.dirs[to]:
			return fail(sandbox.FilesErrorIsDir, "EISDIR")
		}
		if _, there := s.files[to]; there && !req.Replace {
			return fail(sandbox.FilesErrorExists, "EEXIST")
		}
		delete(s.files, p)
		s.files[to] = b
		res.Op = sandbox.FilesRename
	}
	return res, nil
}

func keys(m map[string][]byte) map[string]bool {
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}

// forgingFiles is the files daemon's handler: the real one, whose SessionRun answers with
// one thing forged when the trace ID asks for it.
type forgingFiles struct{ *rpc.SandboxService }

func (f forgingFiles) SessionRun(ctx context.Context, req *connect.Request[plimsollv1.SessionRunRequest]) (*connect.Response[plimsollv1.SessionRunResponse], error) {
	resp, err := f.SandboxService.SessionRun(ctx, req)
	forge, ok := "", false
	for _, n := range FilesForgeries {
		if req.Msg.GetTraceId() == FilesForgeTrace(n) {
			forge, ok = n, true
		}
	}
	if err != nil || !ok {
		return resp, err
	}
	run := resp.Msg.GetRun()
	files := run.GetFiles()
	reseal := func() {
		r := record.FromWire(run.GetRecord())
		run.Record = record.Stamp(r, run)
	}
	switch forge {
	case "answer-op":
		if _, isStat := files.GetAnswer().(*plimsollv1.FilesResult_Stat); isStat {
			files.Answer = &plimsollv1.FilesResult_Read{Read: &plimsollv1.FilesReadAnswer{Content: []byte("x"), SizeAtOpen: 1}}
		} else {
			files.Answer = &plimsollv1.FilesResult_Stat{Stat: &plimsollv1.FilesStatAnswer{Type: plimsollv1.FilesEntryType_FILES_ENTRY_TYPE_FILE, Size: 1}}
		}
		reseal()
	case "error-beside-answer":
		files.Error, files.Errno = plimsollv1.FilesError_FILES_ERROR_NOT_FOUND, "ENOENT"
		reseal()
	case "result":
		switch a := files.GetAnswer().(type) {
		case *plimsollv1.FilesResult_Read:
			a.Read.Content = append(slices.Clone(a.Read.GetContent()), 'x')
		case *plimsollv1.FilesResult_Write:
			a.Write.Written++
		case *plimsollv1.FilesResult_Stat:
			a.Stat.Size++
		case *plimsollv1.FilesResult_List:
			a.List.More = !a.List.GetMore()
		case *plimsollv1.FilesResult_ReadMany:
			a.ReadMany.More = !a.ReadMany.GetMore()
		default:
			files.Errno = "ENOENT"
		}
	case "chain":
		r := record.FromWire(run.GetRecord())
		r.PreviousSHA256 = "0000000000000000000000000000000000000000000000000000000000000001"
		run.Record = record.Stamp(r, run)
	case "kind":
		run.Result = &plimsollv1.RunResponse_Project{Project: &plimsollv1.ProjectResult{Outcome: plimsollv1.ProjectOutcome_PROJECT_OUTCOME_COMPLETED}}
		reseal()
	case "lost":
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("the answer was lost on its way back"))
	}
	return resp, nil
}
