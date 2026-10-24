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

// lie changes the first hex digit of one tile's counts after the engine ran it, as a sandbox
// that returned something other than what the program printed would.
func lie(tile string) func(string) string {
	return func(out string) string {
		if !strings.Contains(out, tile) {
			return out
		}
		i := strings.Index(out, `"counts":"`) + len(`"counts":"`)
		flip := byte('0')
		if out[i] == '0' {
			flip = '1'
		}
		return out[:i] + string(flip) + out[i+1:]
	}
}

// setup writes a rooms file for a 2 by 2 grid of 8-pixel tiles with three rooms, the third
// given no daemon, and returns the directory and the daemons for the first two.
func setup(t *testing.T, second sandbox.Sandbox) (string, map[string]fanjob.Daemon) {
	t.Helper()
	dir := t.TempDir()
	rooms := `{"grid": 2, "size": 8, "rooms": [
  {"id": "engine", "label": "WebAssembly engine", "where": "in the test", "provider": "wasm", "tier": "process", "engine": "QuickJS"},
  {"id": "twin", "label": "Its twin", "where": "in the test", "provider": "wasm-twin", "tier": "process", "engine": "QuickJS", "cloud": true, "usd_per_second": 0.5},
  {"id": "absent", "label": "A microVM", "where": "nowhere", "provider": "e2b", "tier": "vm", "engine": "node", "cloud": true}]}`
	if err := os.WriteFile(filepath.Join(dir, "rooms.json"), []byte(rooms), 0o644); err != nil {
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
	var rf roomsFile
	if err := fanjob.ReadJSON(filepath.Join(dir, "rooms.json"), &rf); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := fanjob.Run(ctx, dir, rf.Rooms, ds, rf.job()); err != nil {
		t.Fatal(err)
	}
	m, err := load(dir, rf)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// Two rooms, every tile twice, one in each: all four tiles agree, the page says so, the
// room with no daemon is listed as not run, and -verify accepts what the run wrote.
func TestFanOutAgreesAndVerifies(t *testing.T) {
	dir, ds := setup(t, fanjobtest.Renamed{WasmSandbox: sandboxtest.Wasm(), Provider: "wasm-twin"})
	m := runAndLoad(t, dir, ds)
	if m.Runs != 8 || m.Agreed != 4 || m.Tiers != 1 {
		t.Fatalf("runs %d, agreed %d, tiers %d; want 8, 4, 1", m.Runs, m.Agreed, m.Tiers)
	}
	for _, tile := range m.Tiles {
		if len(tile.Rooms) != 2 || tile.Rooms[0] == tile.Rooms[1] {
			t.Fatalf("tile %d,%d ran in %v", tile.X, tile.Y, tile.Rooms)
		}
	}
	if m.NotRun["absent"] == "" || m.Rooms[1].Runs != 4 || m.Rooms[1].Cost <= 0 {
		t.Fatalf("not run %v, twin %+v", m.NotRun, m.Rooms[1])
	}
	if err := realMain(dir, "", false); err != nil {
		t.Fatal(err)
	}
	if err := realMain(dir, "", true); err != nil {
		t.Fatalf("-verify refused what the run wrote: %v", err)
	}
	page, err := os.ReadFile(filepath.Join(dir, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"4 of 4", "not run: no daemon was given for it on this run", "never runtime attestation", `data-room="twin"`} {
		if !bytes.Contains(page, []byte(s)) {
			t.Errorf("the page does not say %q", s)
		}
	}

	// One byte of one stored answer changed: the bundle no longer verifies.
	raw, err := os.ReadFile(filepath.Join(dir, "bundle.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.SplitN(raw, []byte("\n"), 2)
	i := bytes.Index(lines[0], []byte(`"response":"`)) + len(`"response":"`) + 40
	edited := bytes.Clone(raw)
	edited[i] ^= 1
	if edited[i] == '"' || edited[i] == '\\' {
		edited[i] ^= 3
	}
	if err := os.WriteFile(filepath.Join(dir, "bundle.jsonl"), edited, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := realMain(dir, "", true); err == nil {
		t.Fatal("-verify accepted an edited bundle")
	}
}

// A room that returns a changed answer for one tile: that tile does not agree, it is named
// on the page and painted red, and the other tiles still agree.
func TestFanOutCatchesAWrongAnswer(t *testing.T) {
	dir, ds := setup(t, fanjobtest.Renamed{WasmSandbox: sandboxtest.Wasm(), Provider: "wasm-twin", Alter: lie(`"tile":[1,0]`)})
	m := runAndLoad(t, dir, ds)
	if m.Agreed != 3 {
		t.Fatalf("agreed %d, want 3", m.Agreed)
	}
	if bad := m.Tiles[1]; bad.Agree || bad.Reason != "the two answers differ" {
		t.Fatalf("tile 1,0: %+v", bad)
	}
	page, _, err := render(m)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(page, []byte("tile 1,0: the two answers differ")) || !bytes.Contains(page, []byte("painted flat red")) {
		t.Error("the page does not name the tile without agreement")
	}
}

func TestAssignSpreadsBothCopies(t *testing.T) {
	rooms := []string{"a", "b", "c", "d", "e", "f", "g", "h", "i"}
	count := map[string]int{}
	for _, p := range fanjob.Assign(256, rooms) {
		if p[0] == p[1] {
			t.Fatalf("one tile twice in %s", p[0])
		}
		count[p[0]]++
		count[p[1]]++
	}
	for _, r := range rooms {
		if count[r] < 56 || count[r] > 58 {
			t.Errorf("room %s has %d runs; want 56 to 58 of 512", r, count[r])
		}
	}
}

// The published page and picture are what the committed bundle and stated files render,
// and the published run is the one the page and the post describe: nine rooms, each with 56
// to 58 of the 512 runs, every tile agreeing, 57 pairs across two engines and 107 with a
// cloud run, in two clouds.
func TestPublishedFilesVerify(t *testing.T) {
	const published = "../../docs/examples/fanout"
	if err := realMain(published, "", true); err != nil {
		t.Fatalf("%v; run go run ./examples/fanout", err)
	}
	var rf roomsFile
	if err := fanjob.ReadJSON(filepath.Join(published, "rooms.json"), &rf); err != nil {
		t.Fatal(err)
	}
	m, err := load(published, rf)
	if err != nil {
		t.Fatal(err)
	}
	if m.Runs != 512 || m.Agreed != 256 || m.Tiers != 4 || m.TwoEngines != 57 || m.WithCloud != 107 || m.Clouds != 2 {
		t.Errorf("runs %d, agreed %d, tiers %d, two engines %d, with cloud %d, clouds %d", m.Runs, m.Agreed, m.Tiers, m.TwoEngines, m.WithCloud, m.Clouds)
	}
	if len(m.Rooms) != 9 {
		t.Errorf("%d rooms, want 9", len(m.Rooms))
	}
	for _, r := range m.Rooms {
		if r.Runs < 56 || r.Runs > 58 {
			t.Errorf("room %s: %d runs, want 56 to 58", r.ID, r.Runs)
		}
	}
	page, err := os.ReadFile(filepath.Join(published, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"512</div>", "256 of 256", "4 of 4", "never runtime attestation", "go run ./examples/fanout -verify"} {
		if !bytes.Contains(page, []byte(s)) {
			t.Errorf("the published page does not say %q", s)
		}
	}
}
