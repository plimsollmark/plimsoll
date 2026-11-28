package client

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/internal/clientcases"
	"github.com/plimsollmark/plimsoll/internal/clientsuite"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// filesCaseCall is one call of a shared file-call case (internal/clientcases/testdata/
// files-calls.json): the operation and its fields, bytes in hex.
type filesCaseCall struct {
	Call  map[string]json.RawMessage `json:"call"`
	Forge string                     `json:"forge"`
	Rule  bool                       `json:"rule"`
}

// filesCall is the case's call as this client takes it.
func filesCall(t *testing.T, c map[string]json.RawMessage) sandbox.FilesCall {
	t.Helper()
	str := func(k string) string {
		var s string
		if raw, ok := c[k]; ok {
			if err := json.Unmarshal(raw, &s); err != nil {
				t.Fatalf("%s: %v", k, err)
			}
		}
		return s
	}
	hx := func(k string) []byte {
		b, err := hex.DecodeString(str(k))
		if err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		return b
	}
	num := func(k string) uint64 {
		var n uint64
		if raw, ok := c[k]; ok {
			if err := json.Unmarshal(raw, &n); err != nil {
				t.Fatalf("%s: %v", k, err)
			}
		}
		return n
	}
	flag := func(k string) bool {
		var b bool
		if raw, ok := c[k]; ok {
			if err := json.Unmarshal(raw, &b); err != nil {
				t.Fatalf("%s: %v", k, err)
			}
		}
		return b
	}
	f := sandbox.FilesCall{Scope: sandbox.FilesScopeWork, Op: sandbox.FilesOp(str("op"))}
	switch f.Op {
	case sandbox.FilesStat:
		f.Path = hx("path")
	case sandbox.FilesRead:
		f.Path, f.Offset, f.MaxBytes = hx("path"), num("offset"), uint32(num("max_bytes"))
	case sandbox.FilesWrite:
		modes := map[string]sandbox.FilesWriteMode{"replace": sandbox.FilesWriteReplace, "create_only": sandbox.FilesWriteCreateOnly, "append": sandbox.FilesWriteAppend}
		f.Path, f.Content, f.Mode, f.Parents = hx("path"), hx("content"), modes[str("mode")], flag("make_parents")
	case sandbox.FilesList:
		f.Path, f.Recursive, f.Match, f.After, f.Budget = hx("path"), flag("recursive"), hx("match"), hx("after"), uint32(num("budget_bytes"))
	case sandbox.FilesReadMany:
		var ps []string
		if err := json.Unmarshal(c["paths"], &ps); err != nil {
			t.Fatal(err)
		}
		for _, p := range ps {
			b, err := hex.DecodeString(p)
			if err != nil {
				t.Fatal(err)
			}
			f.Paths = append(f.Paths, b)
		}
		f.MaxBytes, f.Budget = uint32(num("max_bytes_each")), uint32(num("budget_bytes"))
	case sandbox.FilesMakeDir:
		f.Path, f.Parents = hx("path"), flag("parents")
	case sandbox.FilesRemove:
		f.Path, f.Dir = hx("path"), flag("dir")
	case sandbox.FilesRename:
		f.Path, f.To, f.Replace = hx("from"), hx("to"), flag("replace")
	default:
		t.Fatalf("a case names the operation %q", f.Op)
	}
	return f
}

func entryWord(t sandbox.FilesEntryType) string {
	return strings.ToLower(strings.TrimPrefix(plimsollv1.FilesEntryType(t).String(), "FILES_ENTRY_TYPE_"))
}

// filesAnswerSays is a file call's result as the shared cases state it: the outcome, error
// and errno by their words, op the answer's operation ("" for none), its fields with bytes
// in hex.
func filesAnswerSays(r sandbox.FilesResult) map[string]any {
	a := map[string]any{"outcome": r.Outcome.String(), "error": r.Error.String(), "errno": r.Errno, "op": string(r.Op)}
	switch r.Op {
	case sandbox.FilesStat:
		a["type"], a["size"], a["mode"] = entryWord(r.Type), r.Size, r.Mode
	case sandbox.FilesRead:
		a["content"], a["size_at_open"] = hex.EncodeToString(r.Content), r.SizeAtOpen
	case sandbox.FilesWrite:
		a["written"] = r.Written
	case sandbox.FilesList:
		es := []any{}
		for _, e := range r.Entries {
			es = append(es, map[string]any{"path": hex.EncodeToString(e.Path), "type": entryWord(e.Type), "size": e.Size})
		}
		a["entries"], a["more"] = es, r.More
	case sandbox.FilesReadMany:
		its := []any{}
		for _, it := range r.Items {
			its = append(its, map[string]any{"error": it.Error.String(), "errno": it.Errno, "content": hex.EncodeToString(it.Content), "size_at_open": it.SizeAtOpen})
		}
		a["items"], a["more"] = its, r.More
	}
	return map[string]any{"answer": a}
}

// filesCallVerdicts runs every shared file-call case through Session.RunFiles against the
// files daemon, each case in a session of its own, and returns the verdicts.
func filesCallVerdicts(t *testing.T) []clientcases.Verdict {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", clientcases.FilesCallsFile))
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Cases []struct {
			ID    string `json:"id"`
			Input struct {
				Calls []filesCaseCall `json:"calls"`
			} `json:"input"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(b, &file); err != nil {
		t.Fatal(err)
	}
	url := clientsuite.ServeFiles(t)
	ctx := context.Background()
	var vs []clientcases.Verdict
	for _, c := range file.Cases {
		s, err := newRemote(t, url).OpenSession(ctx, SessionOptions{})
		if err != nil {
			t.Fatalf("%s: %v", c.ID, err)
		}
		if !slices.Equal(s.FileScopes(), []sandbox.FilesScope{sandbox.FilesScopeWork}) || s.WorkDir() != "/work" {
			t.Fatalf("%s: the session states the file scopes %v, work dir %q", c.ID, s.FileScopes(), s.WorkDir())
		}
		var calls []any
		for _, call := range c.Input.Calls {
			cctx := ctx
			if call.Forge != "" {
				cctx = NewTraceContext(ctx, clientsuite.FilesForgeTrace(call.Forge))
			}
			res, err := s.RunFiles(cctx, sandbox.FilesRequest{FilesCall: filesCall(t, call.Call)})
			if err != nil {
				outcome, check, _ := strings.Cut(clientcases.SaysOf(err), "/")
				v := map[string]any{"refused": outcome}
				if call.Rule {
					v["check"] = check
				}
				calls = append(calls, v)
				continue
			}
			if res.Record == nil {
				t.Fatalf("%s: an answered file call carries no checked record", c.ID)
			}
			calls = append(calls, filesAnswerSays(res))
		}
		vs = append(vs, clientcases.Say(c.ID, clientcases.PathFilesCall, map[string]any{"calls": calls}))
		_, _ = s.Close(ctx)
	}
	return vs
}

// A malformed file call is refused before anything is sent: the chain does not move.
func TestRunFilesRefusesAMalformedCallBeforeSending(t *testing.T) {
	url := clientsuite.ServeFiles(t)
	s, err := newRemote(t, url).OpenSession(context.Background(), SessionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]sandbox.FilesCall{
		"no operation": {Scope: sandbox.FilesScopeWork, Path: []byte("a")},
		"no scope":     {Op: sandbox.FilesStat, Path: []byte("a")},
		"a dot-dot":    {Scope: sandbox.FilesScopeWork, Op: sandbox.FilesStat, Path: []byte("a/../b")},
		"a NUL":        {Scope: sandbox.FilesScopeWork, Op: sandbox.FilesStat, Path: []byte("a\x00b")},
	} {
		_, err := s.RunFiles(context.Background(), sandbox.FilesRequest{FilesCall: c})
		if reason, ok := sandbox.NotDispatchedReason(err); !ok || reason != sandbox.RefusalRequest {
			t.Errorf("%s: %v; want not dispatched, request", name, err)
		}
	}
	// None of them was sent: the chain has not moved, and the next call is the first.
	res, err := s.RunFiles(context.Background(), sandbox.FilesRequest{FilesCall: sandbox.FilesCall{Scope: sandbox.FilesScopeWork, Op: sandbox.FilesStat, Path: []byte("a")}})
	if err != nil || res.Record == nil || res.Record.Sequence != 1 || res.Error != sandbox.FilesErrorNotFound {
		t.Fatalf("the first call sent: %+v, %v", res, err)
	}
}
