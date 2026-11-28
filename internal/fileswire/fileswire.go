// Package fileswire converts a session file call between package sandbox's types and the
// wire's (FilesRun, FilesResult), in both directions: the daemon reads a call and writes its
// result, the Go client writes a call and reads its result. One package for both, so the two
// sides cannot map a field differently. Every path stays bytes: nothing here decodes,
// normalizes or cleans one.
package fileswire

import (
	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/internal/wireenum"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// Call is the operation a FilesRun asks, as the provider takes it. An empty operation has
// no Op, which sandbox.ValidateFilesRequest refuses.
func Call(p *plimsollv1.FilesRun) sandbox.FilesCall {
	c := sandbox.FilesCall{Scope: sandbox.FilesScope(p.GetScope())}
	switch op := p.GetOp().(type) {
	case *plimsollv1.FilesRun_Stat:
		c.Op, c.Path = sandbox.FilesStat, op.Stat.GetPath()
	case *plimsollv1.FilesRun_Read:
		c.Op, c.Path, c.Offset, c.MaxBytes = sandbox.FilesRead, op.Read.GetPath(), op.Read.GetOffset(), op.Read.GetMaxBytes()
	case *plimsollv1.FilesRun_Write:
		w := op.Write
		c.Op, c.Path, c.Content, c.Mode, c.Parents = sandbox.FilesWrite, w.GetPath(), w.GetContent(), sandbox.FilesWriteMode(w.GetMode()), w.GetMakeParents()
	case *plimsollv1.FilesRun_List:
		l := op.List
		c.Op, c.Path, c.Recursive, c.Match, c.After, c.Budget = sandbox.FilesList, l.GetPath(), l.GetRecursive(), l.GetMatch(), l.GetAfter(), l.GetBudgetBytes()
	case *plimsollv1.FilesRun_ReadMany:
		r := op.ReadMany
		c.Op, c.Paths, c.MaxBytes, c.Budget = sandbox.FilesReadMany, r.GetPaths(), r.GetMaxBytesEach(), r.GetBudgetBytes()
	case *plimsollv1.FilesRun_MakeDir:
		c.Op, c.Path, c.Parents = sandbox.FilesMakeDir, op.MakeDir.GetPath(), op.MakeDir.GetParents()
	case *plimsollv1.FilesRun_Remove:
		c.Op, c.Path, c.Dir = sandbox.FilesRemove, op.Remove.GetPath(), op.Remove.GetDir()
	case *plimsollv1.FilesRun_Rename:
		r := op.Rename
		c.Op, c.Path, c.To, c.Replace = sandbox.FilesRename, r.GetFromPath(), r.GetToPath(), r.GetReplace()
	}
	return c
}

// Run is c on the wire; nil for an operation it does not know (which
// sandbox.ValidateFilesRequest refuses before anything is sent). Only the fields of c's
// operation are carried: the request digest covers exactly those.
func Run(c sandbox.FilesCall) *plimsollv1.FilesRun {
	p := &plimsollv1.FilesRun{Scope: plimsollv1.FilesScope(c.Scope)}
	switch c.Op {
	case sandbox.FilesStat:
		p.Op = &plimsollv1.FilesRun_Stat{Stat: &plimsollv1.FilesStat{Path: c.Path}}
	case sandbox.FilesRead:
		p.Op = &plimsollv1.FilesRun_Read{Read: &plimsollv1.FilesRead{Path: c.Path, Offset: c.Offset, MaxBytes: c.MaxBytes}}
	case sandbox.FilesWrite:
		p.Op = &plimsollv1.FilesRun_Write{Write: &plimsollv1.FilesWrite{Path: c.Path, Content: c.Content,
			Mode: plimsollv1.FilesWriteMode(c.Mode), MakeParents: c.Parents}}
	case sandbox.FilesList:
		p.Op = &plimsollv1.FilesRun_List{List: &plimsollv1.FilesList{Path: c.Path, Recursive: c.Recursive, Match: c.Match,
			After: c.After, BudgetBytes: c.Budget}}
	case sandbox.FilesReadMany:
		p.Op = &plimsollv1.FilesRun_ReadMany{ReadMany: &plimsollv1.FilesReadMany{Paths: c.Paths, MaxBytesEach: c.MaxBytes, BudgetBytes: c.Budget}}
	case sandbox.FilesMakeDir:
		p.Op = &plimsollv1.FilesRun_MakeDir{MakeDir: &plimsollv1.FilesMakeDir{Path: c.Path, Parents: c.Parents}}
	case sandbox.FilesRemove:
		p.Op = &plimsollv1.FilesRun_Remove{Remove: &plimsollv1.FilesRemove{Path: c.Path, Dir: c.Dir}}
	case sandbox.FilesRename:
		p.Op = &plimsollv1.FilesRun_Rename{Rename: &plimsollv1.FilesRename{FromPath: c.Path, ToPath: c.To, Replace: c.Replace}}
	default:
		return nil
	}
	return p
}

// Result is a file call's result on the wire. The answer names its operation, and is there
// only when the helper answered the operation (completed, no error).
func Result(res sandbox.FilesResult) *plimsollv1.FilesResult {
	out := &plimsollv1.FilesResult{
		Outcome: wireenum.OutcomeToWire(res.Outcome),
		Error:   plimsollv1.FilesError(res.Error),
		Errno:   res.Errno,
	}
	if res.Outcome != sandbox.ProjectOutcomeCompleted || res.Error != sandbox.FilesErrorNone {
		return out
	}
	switch res.Op {
	case sandbox.FilesStat:
		out.Answer = &plimsollv1.FilesResult_Stat{Stat: &plimsollv1.FilesStatAnswer{
			Type: plimsollv1.FilesEntryType(res.Type), Size: res.Size, Mode: res.Mode}}
	case sandbox.FilesRead:
		out.Answer = &plimsollv1.FilesResult_Read{Read: &plimsollv1.FilesReadAnswer{Content: res.Content, SizeAtOpen: res.SizeAtOpen}}
	case sandbox.FilesWrite:
		out.Answer = &plimsollv1.FilesResult_Write{Write: &plimsollv1.FilesWriteAnswer{Written: res.Written}}
	case sandbox.FilesList:
		l := &plimsollv1.FilesListAnswer{More: res.More}
		for _, e := range res.Entries {
			l.Entries = append(l.Entries, &plimsollv1.FilesEntry{Path: e.Path, Type: plimsollv1.FilesEntryType(e.Type), Size: e.Size})
		}
		out.Answer = &plimsollv1.FilesResult_List{List: l}
	case sandbox.FilesReadMany:
		r := &plimsollv1.FilesReadManyAnswer{More: res.More}
		for _, it := range res.Items {
			r.Items = append(r.Items, &plimsollv1.FilesReadManyItem{Error: plimsollv1.FilesError(it.Error), Errno: it.Errno,
				Content: it.Content, SizeAtOpen: it.SizeAtOpen})
		}
		out.Answer = &plimsollv1.FilesResult_ReadMany{ReadMany: r}
	case sandbox.FilesMakeDir:
		out.Answer = &plimsollv1.FilesResult_MakeDir{MakeDir: &plimsollv1.FilesDone{}}
	case sandbox.FilesRemove:
		out.Answer = &plimsollv1.FilesResult_Remove{Remove: &plimsollv1.FilesDone{}}
	case sandbox.FilesRename:
		out.Answer = &plimsollv1.FilesResult_Rename{Rename: &plimsollv1.FilesDone{}}
	}
	return out
}

// Answer is a wire result's outcome and answer as package sandbox states them: Op is the
// operation the answer names, empty when it carries none.
func Answer(f *plimsollv1.FilesResult) (sandbox.ProjectOutcome, sandbox.FilesAnswer) {
	a := sandbox.FilesAnswer{Error: sandbox.FilesError(f.GetError()), Errno: f.GetErrno()}
	switch ans := f.GetAnswer().(type) {
	case *plimsollv1.FilesResult_Stat:
		a.Op, a.Type, a.Size, a.Mode = sandbox.FilesStat, sandbox.FilesEntryType(ans.Stat.GetType()), ans.Stat.GetSize(), ans.Stat.GetMode()
	case *plimsollv1.FilesResult_Read:
		a.Op, a.Content, a.SizeAtOpen = sandbox.FilesRead, ans.Read.GetContent(), ans.Read.GetSizeAtOpen()
	case *plimsollv1.FilesResult_Write:
		a.Op, a.Written = sandbox.FilesWrite, ans.Write.GetWritten()
	case *plimsollv1.FilesResult_List:
		a.Op, a.More = sandbox.FilesList, ans.List.GetMore()
		for _, e := range ans.List.GetEntries() {
			a.Entries = append(a.Entries, sandbox.FilesEntry{Path: e.GetPath(), Type: sandbox.FilesEntryType(e.GetType()), Size: e.GetSize()})
		}
	case *plimsollv1.FilesResult_ReadMany:
		a.Op, a.More = sandbox.FilesReadMany, ans.ReadMany.GetMore()
		for _, it := range ans.ReadMany.GetItems() {
			a.Items = append(a.Items, sandbox.FilesItem{Error: sandbox.FilesError(it.GetError()), Errno: it.GetErrno(),
				Content: it.GetContent(), SizeAtOpen: it.GetSizeAtOpen()})
		}
	case *plimsollv1.FilesResult_MakeDir:
		a.Op = sandbox.FilesMakeDir
	case *plimsollv1.FilesResult_Remove:
		a.Op = sandbox.FilesRemove
	case *plimsollv1.FilesResult_Rename:
		a.Op = sandbox.FilesRename
	}
	return wireenum.OutcomeFromWire(f.GetOutcome()), a
}

// Scopes are the scopes a session takes file calls in, on the wire (PayloadEnvironment and
// OpenSessionResponse.file_scopes), in the order given.
func Scopes(scopes []sandbox.FilesScope) []plimsollv1.FilesScope {
	var out []plimsollv1.FilesScope
	for _, s := range scopes {
		out = append(out, plimsollv1.FilesScope(s))
	}
	return out
}

// ScopesFrom reads a statement of scopes from the wire: the work and sandbox scopes it
// names, each once, in the enum's order; a value this build does not know (a later
// daemon's) is left out, so nothing stated is taken for a scope it is not.
func ScopesFrom(scopes []plimsollv1.FilesScope) []sandbox.FilesScope {
	var out []sandbox.FilesScope
	for _, want := range []sandbox.FilesScope{sandbox.FilesScopeWork, sandbox.FilesScopeSandbox} {
		for _, s := range scopes {
			if sandbox.FilesScope(s) == want {
				out = append(out, want)
				break
			}
		}
	}
	return out
}
