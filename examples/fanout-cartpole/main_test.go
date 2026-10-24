package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/examples/internal/fanjob"
	"github.com/plimsollmark/plimsoll/examples/internal/fanjob/fanjobtest"
	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandboxtest"
)

// setup writes a batch of 2 by 2 candidates, one starting angle, two rooms and a third with
// no daemon, and returns the directory and the daemons for the first two.
func setup(t *testing.T, second sandbox.Sandbox) (string, map[string]fanjob.Daemon) {
	t.Helper()
	dir := t.TempDir()
	batch := `{"kp": [5, 40], "kd": [0, 5], "theta0": [0.1], "rooms": [
  {"id": "engine", "label": "WebAssembly engine", "where": "in the test", "provider": "wasm", "tier": "process", "engine": "QuickJS"},
  {"id": "twin", "label": "Its twin", "where": "in the test", "provider": "wasm-twin", "tier": "process", "engine": "QuickJS", "cloud": true, "usd_per_second": 0.5},
  {"id": "absent", "label": "A microVM", "where": "nowhere", "provider": "e2b", "tier": "vm", "engine": "node", "cloud": true}]}`
	if err := os.WriteFile(filepath.Join(dir, "rooms.json"), []byte(batch), 0o644); err != nil {
		t.Fatal(err)
	}
	tok := filepath.Join(dir, "token")
	if err := os.WriteFile(tok, []byte("unused\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, map[string]fanjob.Daemon{
		"engine": {URL: fanjobtest.Serve(t, sandboxtest.Wasm()), TokenFile: tok, Concurrency: 2},
		"twin":   {URL: fanjobtest.Serve(t, second), TokenFile: tok, Concurrency: 2},
	}
}

func runAndLoad(t *testing.T, dir string, ds map[string]fanjob.Daemon) *model {
	t.Helper()
	var bf batchFile
	if err := fanjob.ReadJSON(filepath.Join(dir, "rooms.json"), &bf); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := fanjob.Run(ctx, dir, bf.Rooms, ds, bf); err != nil {
		t.Fatal(err)
	}
	m, err := load(dir, bf)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// Two rooms, every trial twice: the four trials agree, the weak and undamped candidates fail
// and the accepted controller's gains balance, -verify accepts what the run wrote, and an
// edited bundle is refused.
func TestBatchAgreesScoresAndVerifies(t *testing.T) {
	dir, ds := setup(t, fanjobtest.Renamed{WasmSandbox: sandboxtest.Wasm(), Provider: "wasm-twin"})
	m := runAndLoad(t, dir, ds)
	if m.Runs != 8 || m.Agreed != 4 || m.Trials != 4 || len(m.Issues) != 0 {
		t.Fatalf("runs %d, agreed %d of %d, issues %v", m.Runs, m.Agreed, m.Trials, m.Issues)
	}
	score := map[string]int{}
	for _, c := range m.Cands {
		score[c.KP+"/"+c.KD] = c.Upright
	}
	if score["5/0"] != 0 || score["5/5"] != 0 || score["40/0"] != 0 || score["40/5"] != 1 {
		t.Errorf("scores %v; want only kp 40, kd 5 balanced", score)
	}
	if m.Perfect != 1 {
		t.Errorf("%d candidates balanced from every angle, want 1", m.Perfect)
	}
	if err := realMain(dir, "", false); err != nil {
		t.Fatal(err)
	}
	if err := realMain(dir, "", true); err != nil {
		t.Fatalf("verify after render: %v", err)
	}
	page, err := os.ReadFile(filepath.Join(dir, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"4 of 4", "not run: no daemon was given for it on this run", "go run ./examples/fanout-cartpole -verify", "1/1"} {
		if !bytes.Contains(page, []byte(s)) {
			t.Errorf("the page does not say %q", s)
		}
	}
	bundle := filepath.Join(dir, "bundle.jsonl")
	b, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundle, bytes.Replace(b, []byte(`"`), []byte(`"x`), 1), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := realMain(dir, "", true); err == nil {
		t.Error("-verify accepted an edited bundle")
	}
}

// A sandbox that changes one trial's answer after the engine ran it: that trial's two answers
// differ, the page lists it and outlines its candidate, and the rest still agree.
func TestAChangedAnswerIsCaught(t *testing.T) {
	alter := func(out string) string {
		if strings.Contains(out, `"trial":[3,0]`) {
			return strings.Replace(out, `"hash":"`, `"hash":"0`, 1)
		}
		return out
	}
	dir, ds := setup(t, fanjobtest.Renamed{WasmSandbox: sandboxtest.Wasm(), Provider: "wasm-twin", Alter: alter})
	m := runAndLoad(t, dir, ds)
	if m.Agreed != 3 || len(m.Issues) != 1 || m.Issues[0].C != 3 || m.Issues[0].Reason != "the two answers differ" {
		t.Fatalf("agreed %d, issues %+v", m.Agreed, m.Issues)
	}
	if m.Cands[3].Agreed != 0 || m.Cands[3].Upright != 0 {
		t.Errorf("the changed trial still counts: %+v", m.Cands[3])
	}
	page, err := render(m)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(page, []byte("Trials without agreement")) || !bytes.Contains(page, []byte(`stroke="#e34948"`)) {
		t.Error("the page does not show the disagreeing trial")
	}
}

// The published page is what the committed bundle and stated files render, and the published
// run is the one the page and the post describe: nine rooms, 512 runs, every trial agreeing
// (57 across two engines, 107 with a cloud run), 16 of 64 candidates balanced from every angle.
func TestPublishedFilesVerify(t *testing.T) {
	const published = "../../docs/examples/fanout-cartpole"
	if err := realMain(published, "", true); err != nil {
		t.Fatalf("%v; run go run ./examples/fanout-cartpole", err)
	}
	var bf batchFile
	if err := fanjob.ReadJSON(filepath.Join(published, "rooms.json"), &bf); err != nil {
		t.Fatal(err)
	}
	m, err := load(published, bf)
	if err != nil {
		t.Fatal(err)
	}
	if m.Runs != 512 || m.Agreed != 256 || m.Trials != 256 || m.RoomsRun != 9 || m.Tiers != 4 || m.TwoEngines != 57 || m.WithCloud != 107 || m.Perfect != 16 {
		t.Errorf("runs %d, agreed %d of %d, rooms %d, tiers %d, two engines %d, with cloud %d, perfect %d",
			m.Runs, m.Agreed, m.Trials, m.RoomsRun, m.Tiers, m.TwoEngines, m.WithCloud, m.Perfect)
	}
}
