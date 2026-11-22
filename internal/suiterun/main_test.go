package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// The reader's test, stream and check are tested where they are used, through the
// Makefile's SUITE_BEGIN and SUITE_END with real go tests (internal/maketest's
// TestTheRunner). Here: how a suite's go test is read from make's dry run, and the short
// pass's check against this repository's own Makefile.

func TestParseSelections(t *testing.T) {
	dry := `mkdir -p tmp; { env -u KEY /r/tmp/docker-go-suite.reader test -race ./sandbox ./sandbox/openshell -run 'Docker|RunProject' -skip 'Live$' -count=1 -parallel 4 -timeout 30m; echo $? > tmp/x.status; } 2>&1 | tee tmp/x.log
{ (cd examples/sbom && go vet ./... && /r/tmp/sbom-suite.reader test -race -count=1 ./...); echo $? > s; }
{ if true; then a; fi | /r/tmp/agentsandbox-suite.reader stream ./sandbox/agentsandbox -run Live + ./cmd/plimsolld -run 'AgentSandbox.*Live'; echo $? > s; }
{ /r/tmp/a.reader test ./x -run A -count=1 && B=1 /r/tmp/a.reader test ./y -run 'C$'; }`
	got := parseSelections("suite", dry)
	type want struct {
		dir, pkgs, run, skip string
	}
	wants := []want{
		{".", "./sandbox ./sandbox/openshell", "Docker|RunProject", "Live$"},
		{"examples/sbom", "./...", "", ""},
		{".", "./sandbox/agentsandbox", "Live", ""},
		{".", "./cmd/plimsolld", "AgentSandbox.*Live", ""},
		{".", "./x", "A", ""},
		{".", "./y", "C$", ""},
	}
	if len(got) != len(wants) {
		t.Fatalf("%d selections read, want %d: %+v", len(got), len(wants), got)
	}
	for i, w := range wants {
		s := got[i]
		run, skip := "", ""
		if s.run != nil {
			run = s.run.String()
		}
		if s.skip != nil {
			skip = s.skip.String()
		}
		if s.dir != w.dir || strings.Join(s.packages, " ") != w.pkgs || run != w.run || skip != w.skip {
			t.Errorf("selection %d: dir %q packages %v run %q skip %q, want %+v", i, s.dir, s.packages, run, skip, w)
		}
	}
}

func TestSelects(t *testing.T) {
	sels := parseSelections("s", `/r/a.reader test ./sandbox ./docker -run 'Docker|Smoke' -skip 'Live$' -count=1
(cd examples/sbom && /r/b.reader test -race ./...)
/r/c.reader test ./clients/python/ -run '^(TestA|TestB)$'`)
	modules := map[string]string{".": "example.com/m", "examples/sbom": "example.com/m/examples/sbom"}
	for _, c := range []struct {
		pkg, name string
		want      bool
	}{
		{"example.com/m/sandbox", "TestDockerRuns", true},
		{"example.com/m/sandbox", "TestSmokeOnly", true},
		{"example.com/m/sandbox", "TestDockerCloudLive", false},   // the suite's -skip
		{"example.com/m/sandbox", "TestExampleClientE2E", false},  // none of the words
		{"example.com/m/sandbox/agent", "TestDockerGuest", false}, // a package the line does not name
		{"example.com/m/docker", "TestDockerInstaller", true},
		{"example.com/m/examples/sbom", "TestAnything", true},
		{"example.com/m/examples/sbom/inner", "TestAnything", true},
		{"example.com/m/examples/sbomb", "TestAnything", false},
		{"example.com/m/clients/python", "TestA", true},
		{"example.com/m/clients/python", "TestAB", false},
	} {
		got := false
		for _, s := range sels {
			got = got || s.selects(modules, c.pkg, c.name)
		}
		if got != c.want {
			t.Errorf("%s %s: selected %v, want %v", c.pkg, c.name, got, c.want)
		}
	}
}

// TestUnselectedAgainstThisMakefile: a docker test the docker suite selects may skip in the
// short pass; one whose name holds none of the suite's words, and one in a package no suite
// names, fail the pass and are named. The results are written by hand; the selections are
// this repository's, read from make.
func TestUnselectedAgainstThisMakefile(t *testing.T) {
	if _, err := exec.LookPath("make"); err != nil {
		t.Skip("no make")
	}
	root := filepath.Join("..", "..")
	const module = "github.com/plimsollmark/plimsoll"
	write := func(results ...Result) string {
		path := filepath.Join(t.TempDir(), "short.results")
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		enc := json.NewEncoder(f)
		for _, r := range results {
			if err := enc.Encode(r); err != nil {
				t.Fatal(err)
			}
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		return path
	}
	skip := func(pkg, test string) Result {
		return Result{Package: module + pkg, Test: test, Action: "skip", Reason: "skipping docker sandbox test in -short mode"}
	}
	var out bytes.Buffer
	selected := write(
		skip("/sandbox", "TestDockerSessionConformance"),
		skip("/sandbox", "TestDockerGuardWindowSweep/shipped_profile"), // a subtest's skip counts for its test
		skip("/sandbox", "TestE2BLiveSessions"),                        // a paid suite's: selected, though no gate runs it
		skip("/clients/python", "TestDeepAgentsDocker"),
		Result{Package: module + "/sandbox", Test: "TestBrokerRefuses", Action: "pass"},
	)
	if err := unselected(selected, root, nil, &out); err != nil {
		t.Fatalf("tests the suites select: %v", err)
	}
	if !strings.Contains(out.String(), "4 tests skipped in this pass: 4 are selected by a suite") {
		t.Fatalf("the pass's line: %q", out.String())
	}
	for _, r := range []Result{
		skip("/sandbox", "TestANameWithNoneOfTheSuitesWords"),
		skip("/internal/rpc", "TestDockerNamedButInAPackageNoSuiteNames"),
		skip("/sandbox", "TestDockerSomethingLive"), // the docker suite skips Live$, and no live suite's pattern names it
	} {
		err := unselected(write(skip("/sandbox", "TestDockerSessionConformance"), r), root, nil, &out)
		if err == nil || !strings.Contains(err.Error(), r.Test) || !strings.Contains(err.Error(), "run nowhere") || strings.Contains(err.Error(), "TestDockerSessionConformance") {
			t.Errorf("%s %s skipped and no suite selects it: %v", r.Package, r.Test, err)
		}
	}
	// A test run by hand on purpose is accepted when a list names it with its reason, and a
	// list's line whose test did not skip fails the pass.
	list := filepath.Join(t.TempDir(), "by-hand.txt")
	text := "# run by hand\n" + module + "/sandbox TestANameWithNoneOfTheSuitesWords: it needs a machine no suite has\n"
	if err := os.WriteFile(list, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := unselected(write(skip("/sandbox", "TestANameWithNoneOfTheSuitesWords"), skip("/sandbox", "TestDockerSessionConformance")), root, []string{list}, &out); err != nil || !strings.Contains(out.String(), "1 are run by hand") {
		t.Errorf("a listed test: %v %q", err, out.String())
	}
	if err := unselected(write(skip("/sandbox", "TestDockerSessionConformance")), root, []string{list}, &out); err == nil || !strings.Contains(err.Error(), "listed as run by hand and did not skip") {
		t.Errorf("a list's line whose test did not skip: %v", err)
	}
	if err := os.WriteFile(list, []byte("no colon here\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := unselected(selected, root, []string{list}, &out); err == nil || !strings.Contains(err.Error(), "want `import/path TestName: why") {
		t.Errorf("a malformed list: %v", err)
	}
}

// fakeHost is a docker host for leftovers: its containers, and which leftovers removed.
type fakeHost struct {
	all     []container
	removed []string
	// gone is how many lists a container in it lasts before it leaves on its own, as a
	// removal already under way does.
	gone map[string]int
}

func (h *fakeHost) list() ([]container, error) {
	var now []container
	for _, c := range h.all {
		if n, ok := h.gone[c.ID]; ok {
			if n == 0 {
				continue
			}
			h.gone[c.ID] = n - 1
		}
		if !slices.Contains(h.removed, c.ID) {
			now = append(now, c)
		}
	}
	return now, nil
}

func (h *fakeHost) remove(id string) error { h.removed = append(h.removed, id); return nil }

// TestLeftovers: a container with a mount from under the run's directory fails the check,
// is named with its labels and is removed; a container of another run (a mount from a
// directory that only starts with the same characters), one with no mounts, and one already
// being removed that leaves within the wait do not; nor does a host with no containers.
func TestLeftovers(t *testing.T) {
	dir := t.TempDir()
	c := func(id, source string, labels map[string]string) container {
		var k container
		k.ID, k.Name, k.State.Status, k.Config.Labels = id, "/plsm-session-"+id, "paused", labels
		if source != "" {
			k.Mounts = []mount{{Source: "/etc/hosts"}, {Source: source}}
		}
		return k
	}
	ours := c("aaaaaaaaaaaaaaaa", filepath.Join(dir, "plimsoll-docker-config-1", "resolv.conf"), map[string]string{"io.plimsoll.instance": "478509e3598b9682", "io.plimsoll.session": "1"})
	other := c("bbbbbbbbbbbbbbbb", dir+"-another-run/plimsoll-docker-config-2/resolv.conf", nil)
	bare := c("cccccccccccccccc", "", nil)
	leaving := c("dddddddddddddddd", filepath.Join(dir, "plimsoll-docker-config-1", "guest-guard", "g"), nil)

	host := &fakeHost{all: []container{other, bare, leaving}, gone: map[string]int{leaving.ID: 1}}
	var out bytes.Buffer
	if err := leftovers(dir, host, 5*time.Second, &out); err != nil || len(host.removed) != 0 {
		t.Fatalf("no container of the run is left once the one being removed is gone: %v, removed %v\n%s", err, host.removed, out.String())
	}
	if err := leftovers(dir, &fakeHost{}, 0, &out); err != nil {
		t.Fatalf("an empty host: %v", err)
	}

	host = &fakeHost{all: []container{other, ours, bare}}
	out.Reset()
	err := leftovers(dir, host, 0, &out)
	if err == nil || !strings.Contains(err.Error(), "1 container(s)") {
		t.Fatalf("a container of the run is left: %v", err)
	}
	if !slices.Equal(host.removed, []string{ours.ID}) {
		t.Fatalf("removed %v; want only the run's own %s", host.removed, ours.ID)
	}
	if s := out.String(); !strings.Contains(s, "plsm-session-aaaaaaaaaaaaaaaa, paused") || !strings.Contains(s, `instance "478509e3598b9682"`) {
		t.Fatalf("the report does not name the container, its state and its instance:\n%s", s)
	}
	if err := leftovers("relative/dir", host, 0, &out); err == nil {
		t.Fatal("a relative directory was accepted: every container's mount would be compared against it")
	}
}
