package fileswire

import (
	"reflect"
	"testing"

	"google.golang.org/protobuf/proto"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// A name that is not UTF-8 and holds a newline, as a sandbox may hold one.
var odd = []byte("a\xff\nb")

// Every operation, with every field it carries set, goes to the wire and back unchanged,
// paths byte for byte; an operation the package does not know has no wire form.
func TestEveryCallRoundTrips(t *testing.T) {
	work := sandbox.FilesScopeWork
	calls := []sandbox.FilesCall{
		{Scope: work, Op: sandbox.FilesStat, Path: odd},
		{Scope: sandbox.FilesScopeSandbox, Op: sandbox.FilesRead, Path: []byte("/etc/\xfe"), Offset: 7, MaxBytes: 9},
		{Scope: work, Op: sandbox.FilesWrite, Path: odd, Content: []byte{0, 1, 0xff}, Mode: sandbox.FilesWriteAppend, Parents: true},
		{Scope: work, Op: sandbox.FilesList, Path: []byte("."), Recursive: true, Match: []byte("**/*\xff"), After: odd, Budget: 4096},
		{Scope: work, Op: sandbox.FilesReadMany, Paths: [][]byte{odd, []byte("x")}, MaxBytes: 64, Budget: 4096},
		{Scope: work, Op: sandbox.FilesMakeDir, Path: odd, Parents: true},
		{Scope: work, Op: sandbox.FilesRemove, Path: odd, Dir: true},
		{Scope: work, Op: sandbox.FilesRename, Path: odd, To: []byte("b\xff"), Replace: true},
	}
	if len(calls) != len(sandbox.FilesOps) {
		t.Fatalf("%d calls for %d operations", len(calls), len(sandbox.FilesOps))
	}
	for _, c := range calls {
		p := Run(c)
		if p == nil {
			t.Fatalf("%s has no wire form", c.Op)
		}
		if got := Call(p); !reflect.DeepEqual(got, c) {
			t.Errorf("%s: %+v came back as %+v", c.Op, c, got)
		}
		if q := Run(Call(p)); !proto.Equal(p, q) {
			t.Errorf("%s: the wire form %v came back as %v", c.Op, p, q)
		}
	}
	if Run(sandbox.FilesCall{Scope: work, Op: "copy"}) != nil {
		t.Fatal("an operation the package does not know has a wire form")
	}
}

// Every answer goes to the wire and back unchanged; an answered error carries no answer.
func TestEveryAnswerRoundTrips(t *testing.T) {
	answers := []sandbox.FilesAnswer{
		{Op: sandbox.FilesStat, Type: sandbox.FilesTypeLink, Size: 3, Mode: 0o644},
		{Op: sandbox.FilesRead, Content: []byte{0xff, '\n'}, SizeAtOpen: 2},
		{Op: sandbox.FilesWrite, Written: 4},
		{Op: sandbox.FilesList, Entries: []sandbox.FilesEntry{{Path: odd, Type: sandbox.FilesTypeFile, Size: 1}}, More: true},
		{Op: sandbox.FilesReadMany, Items: []sandbox.FilesItem{{Content: []byte("x"), SizeAtOpen: 1}, {Error: sandbox.FilesErrorNotFound, Errno: "ENOENT"}}, More: true},
		{Op: sandbox.FilesMakeDir},
		{Op: sandbox.FilesRemove},
		{Op: sandbox.FilesRename},
	}
	for _, a := range answers {
		res := sandbox.FilesResult{Outcome: sandbox.ProjectOutcomeCompleted, FilesAnswer: a}
		outcome, got := Answer(Result(res))
		if outcome != sandbox.ProjectOutcomeCompleted || !reflect.DeepEqual(got, a) {
			t.Errorf("%s: %+v came back as %v %+v", a.Op, a, outcome, got)
		}
	}
	w := Result(sandbox.FilesResult{Outcome: sandbox.ProjectOutcomeCompleted,
		FilesAnswer: sandbox.FilesAnswer{Op: sandbox.FilesRead, Error: sandbox.FilesErrorNotFound, Errno: "ENOENT", Content: []byte("x")}})
	if w.GetAnswer() != nil || w.GetError() != plimsollv1.FilesError_FILES_ERROR_NOT_FOUND || w.GetErrno() != "ENOENT" {
		t.Fatalf("an answered error: %v", w)
	}
}
