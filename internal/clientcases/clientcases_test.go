package clientcases

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func load(t *testing.T) *Account {
	t.Helper()
	a, err := Load("../..")
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// expected is the verdicts a client gives when it says what every file states on every
// path it has, leaving out what a difference says it does not check: what the judge must
// pass.
func expected(a *Account, client string) []Verdict {
	cl := Clients[client]
	var vs []Verdict
	for _, c := range a.Cases {
		for _, p := range c.Paths {
			if _, ok := cl.Paths[p]; !ok {
				continue
			}
			if d := a.difference(client, c.ID); d != nil {
				if canonical(d.Says) != canonical(json.RawMessage(NotChecked)) {
					vs = append(vs, Verdict{ID: c.ID, Path: p, Says: d.Says})
				}
				continue
			}
			vs = append(vs, Verdict{ID: c.ID, Path: p, Says: c.Expect[p]})
		}
	}
	return vs
}

func TestTheJudgePassesEveryCaseAnsweredAsStated(t *testing.T) {
	a := load(t)
	for client := range Clients {
		if p := a.Problems(client, expected(a, client)); len(p) != 0 {
			t.Errorf("%s: %q", client, p)
		}
	}
}

// Each way a client's run can go wrong is one problem, naming the case.
func TestTheJudgeFailsWhatARunGotWrong(t *testing.T) {
	a := load(t)
	base := expected(a, "python")
	at := slices.IndexFunc(base, func(v Verdict) bool { return v.ID == "unanswered/result-and-code" && v.Path == PathAttachLost })
	if at < 0 {
		t.Fatal("no release-76 verdict to change")
	}
	for name, tc := range map[string]struct {
		change func([]Verdict) []Verdict
		want   string
	}{
		"a case skipped":                {func(vs []Verdict) []Verdict { return slices.Delete(vs, at, at+1) }, "unanswered/result-and-code on attach-lost: no verdict (clients/python/tests/test_shared_cases.py"},
		"another verdict":               {func(vs []Verdict) []Verdict { vs[at] = Say(vs[at].ID, vs[at].Path, "accept"); return vs }, `unanswered/result-and-code on attach-lost: says "accept", the file (internal/clientcases/testdata/records.json) states "may_have_run/chain"`},
		"another kind of rule":          {func(vs []Verdict) []Verdict { vs[at] = Say(vs[at].ID, vs[at].Path, "may_have_run/mismatch"); return vs }, `says "may_have_run/mismatch"`},
		"answered twice":                {func(vs []Verdict) []Verdict { return append(vs, vs[at]) }, "unanswered/result-and-code on attach-lost: answered 2 times"},
		"an id no file holds":           {func(vs []Verdict) []Verdict { return append(vs, Say("unanswered/nothing", PathAttachLost, "accept")) }, "unanswered/nothing: a verdict for an id no file holds"},
		"a path the case does not name": {func(vs []Verdict) []Verdict { return append(vs, Say("unanswered/accepted", PathDigest, "accept")) }, "a verdict on the path digest"},
	} {
		vs := tc.change(slices.Clone(base))
		p := a.Problems("python", vs)
		if len(p) != 1 || !strings.Contains(p[0], tc.want) {
			t.Errorf("%s: %q, want one problem holding %q", name, p, tc.want)
		}
	}
	// A client whose errors name no kind of rule is compared on the outcome alone.
	ts := expected(a, "typescript")
	for i, v := range ts {
		if v.ID == "unanswered/unknown-code" {
			ts[i] = Say(v.ID, v.Path, "may_have_run")
		}
	}
	if p := a.Problems("typescript", ts); len(p) != 0 {
		t.Errorf("an outcome alone: %q", p)
	}
}

// A difference that no longer holds fails, as does a verdict for a retired id.
func TestTheJudgeFailsAStaleDifferenceAndARetiredID(t *testing.T) {
	a := load(t)
	id := "golden/requests/module request"
	if d := a.difference("typescript", id); d == nil || canonical(d.Says) != canonical(json.RawMessage(NotChecked)) {
		t.Fatalf("no not_checked difference for %s", id)
	}
	vs := append(expected(a, "typescript"), Verdict{ID: id, Path: PathDigest, Says: a.Case(id).Expect[PathDigest]})
	p := a.Problems("typescript", vs)
	if len(p) != 1 || !strings.Contains(p[0], "remove the difference") {
		t.Errorf("a stale not_checked difference: %q", p)
	}
	a.Retired["unanswered/an-old-case"] = true
	p = a.Problems("go", append(expected(a, "go"), Say("unanswered/an-old-case", PathStored, "accept")))
	if len(p) != 1 || !strings.Contains(p[0], "retired") {
		t.Errorf("a retired id: %q", p)
	}
}

// Narrowed to one runner's files, the judge asks only for that runner's paths, and fails a
// verdict on a path of the other.
func TestTheJudgeNarrowsToARunnersFiles(t *testing.T) {
	a := load(t)
	all := expected(a, "go")
	var rec []Verdict
	for _, v := range all {
		if Clients["go"].Paths[v.Path] == "record/shared_cases_test.go" {
			rec = append(rec, v)
		}
	}
	if p := a.Problems("go", rec, "record/shared_cases_test.go"); len(p) != 0 {
		t.Errorf("the record runner's own verdicts: %q", p)
	}
	if p := a.Problems("go", all, "record/shared_cases_test.go"); len(p) == 0 {
		t.Error("a verdict on another runner's path passed")
	}
}

// Every path a case names is one some client has, every runner file a client names exists,
// every record case has an accepted twin in its family, and the account's size is logged.
func TestTheAccount(t *testing.T) {
	a := load(t)
	has := map[string]bool{}
	for _, cl := range Clients {
		for p, f := range cl.Paths {
			has[p] = true
			if _, err := os.Stat(filepath.Join("../..", f)); err != nil {
				t.Errorf("%s: path %s names %s: %v", cl.Name, p, f, err)
			}
		}
	}
	families := map[string]int{}
	accepted := map[string]bool{}
	for _, c := range a.Cases {
		families[c.Family]++
		for _, p := range c.Paths {
			if !has[p] {
				t.Errorf("%s names the path %s, which no client has", c.ID, p)
			}
		}
		if c.File == RecordsFile {
			all := true
			for _, p := range c.Paths {
				all = all && canonical(c.Expect[p]) == `"accept"`
			}
			accepted[c.Family] = accepted[c.Family] || all
		}
	}
	for f := range accepted {
		if !accepted[f] {
			t.Errorf("the record family %s has no accepted twin", f)
		}
	}
	t.Logf("%d cases in %d families; verdicts per client: go %d, python %d, typescript %d",
		len(a.Cases), len(families), len(expected(a, "go")), len(expected(a, "python")), len(expected(a, "typescript")))
	// The floors the per-file tests kept, now one account: fewer means a case left a file.
	for family, min := range map[string]int{"golden/refused": 22, "golden/malformed": 4, "golden/qualifications": 31, "golden/meets": 49, "checkpoint/invalid": 45, "answers": 21, "unanswered": 3} {
		if families[family] < min {
			t.Errorf("%s holds %d cases, fewer than the %d it had", family, families[family], min)
		}
	}
}

func TestReadVerdicts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v.jsonl")
	if err := os.WriteFile(path, []byte(`{"id":"a","path":"digest","says":"x"}`+"\n\n"+`{"id":"b","path":"meets","says":{"k":1}}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	vs, err := ReadVerdicts(path)
	if err != nil || len(vs) != 2 || vs[1].ID != "b" {
		t.Fatalf("%v %v", vs, err)
	}
	for _, bad := range []string{`{"id":"a","path":"digest"}`, `{"id":"a","path":"digest","says":"x","extra":1}`, `not json`} {
		if err := os.WriteFile(path, []byte(bad+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadVerdicts(path); err == nil {
			t.Errorf("%s was read", bad)
		}
	}
}
