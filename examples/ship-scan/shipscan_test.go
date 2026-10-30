package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
)

// published is the page's directory, from this package's.
var published = filepath.Join("..", "..", "docs", "examples", "ship-scan")

// The committed page and its evidence verify: every claim, the set's digest, the clean
// call's record recomputed, and the page is what the evidence renders.
func TestPublishedFilesVerify(t *testing.T) {
	if err := verifyPublished(published); err != nil {
		t.Fatal(err)
	}
}

// Each observation the page rests on is checked: changing one makes the published
// evidence fail.
func TestAlteredEvidenceFailsToVerify(t *testing.T) {
	call := func(ev *Evidence, name string) *Call {
		for i := range ev.Calls {
			if ev.Calls[i].Name == name {
				return &ev.Calls[i]
			}
		}
		t.Fatalf("no call %s", name)
		return nil
	}
	for _, tc := range []struct {
		name  string
		alter func(*Evidence, *exchange)
	}{
		{"the clean call refused", func(ev *Evidence, _ *exchange) {
			c := call(ev, "clean")
			c.Answer = Answer{Code: "permission_denied", Mark: "permission"}
		}},
		{"a refusal naming another entry", func(ev *Evidence, _ *exchange) {
			c := call(ev, "harness-file")
			c.Answer.Message = strings.ReplaceAll(c.Answer.Message, labelHarness, "harness/other.py")
		}},
		{"a refusal not marked not dispatched", func(ev *Evidence, _ *exchange) { call(ev, "harness-edited").Answer.Mark = "" }},
		{"a refused call with a record", func(ev *Evidence, _ *exchange) {
			call(ev, "harness-archive").Record = call(ev, "clean").Record
		}},
		{"the archive's member named to the caller", func(ev *Evidence, _ *exchange) {
			call(ev, "harness-archive").Answer.Message += " vendor/plant.py"
		}},
		{"the audited call telling the caller", func(ev *Evidence, _ *exchange) {
			call(ev, "seed-in-code").Answer.Message = labelSeed
		}},
		{"the audited call's find dropped from the log", func(ev *Evidence, _ *exchange) {
			c := call(ev, "seed-in-code")
			c.Log = c.Log[len(c.Log)-1:]
		}},
		{"a log line of another set", func(ev *Evidence, _ *exchange) {
			call(ev, "clean").Log[0].WithheldSet = strings.Repeat("0", 64)
		}},
		{"the set file changed", func(_ *Evidence, ex *exchange) { ex.set = append(ex.set, ' ') }},
		{"the clean call's record digest changed", func(ev *Evidence, _ *exchange) {
			call(ev, "clean").Record.ResultSHA256 = strings.Repeat("0", 64)
		}},
		{"the clean call's output changed", func(_ *Evidence, ex *exchange) {
			var resp plimsollv1.RunResponse
			if err := protojson.Unmarshal(ex.response, &resp); err != nil {
				t.Fatal(err)
			}
			resp.GetJavascript().Stdout = []byte("final altitude 10.000 (target 10)\n")
			raw, err := protojson.Marshal(&resp)
			if err != nil {
				t.Fatal(err)
			}
			ex.response = raw
		}},
		{"an entry's mode changed", func(ev *Evidence, _ *exchange) { ev.Entries[len(ev.Entries)-1].Mode = "refuse" }},
		// What the page shows must be what was checked.
		{"the clean call's shown output changed, its response not", func(ev *Evidence, _ *exchange) {
			call(ev, "clean").Answer.Stdout = "final altitude 10.000 (target 10)\n"
		}},
		{"the seed call's shown output changed, its response not", func(ev *Evidence, _ *exchange) {
			call(ev, "seed-in-code").Answer.Stdout = "gain 0.99\n"
		}},
		{"the seed call's response changed", func(_ *Evidence, ex *exchange) {
			var resp plimsollv1.RunResponse
			if err := protojson.Unmarshal(ex.seedResponse, &resp); err != nil {
				t.Fatal(err)
			}
			resp.GetJavascript().Stdout = []byte("gain 0.99\n")
			raw, err := protojson.Marshal(&resp)
			if err != nil {
				t.Fatal(err)
			}
			ex.seedResponse = raw
		}},
		{"the tier stated as vm", func(ev *Evidence, _ *exchange) { ev.Isolation = "vm" }},
		{"an entry dropped", func(ev *Evidence, _ *exchange) { ev.Entries = ev.Entries[1:] }},
		{"a refusal with more text", func(ev *Evidence, _ *exchange) {
			call(ev, "harness-edited").Answer.Message += ", seeds.txt:1 (code)"
		}},
		{"a refused call's log naming one more entry", func(ev *Evidence, _ *exchange) {
			l := &call(ev, "harness-file").Log[0]
			l.WithheldFound = append(l.WithheldFound, "seeds.txt:1")
		}},
		{"the audited call's run line naming one more entry", func(ev *Evidence, _ *exchange) {
			c := call(ev, "seed-in-code")
			l := &c.Log[len(c.Log)-1]
			l.WithheldFound = append(l.WithheldFound, "seeds.txt:3")
		}},
		{"a log line with no set", func(ev *Evidence, _ *exchange) { call(ev, "harness-archive").Log[0].WithheldSet = "" }},
		{"a log line with an incomplete scan", func(ev *Evidence, _ *exchange) {
			call(ev, "clean").Log[0].WithheldIncomplete = []string{"code: archive_bytes"}
		}},
		{"the offline scan of the outbox clean", func(ev *Evidence, _ *exchange) { ev.Offline[0].Exit = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ev, ex, err := readPublished(published)
			if err != nil {
				t.Fatal(err)
			}
			tc.alter(ev, ex)
			if err := checkEvidence(ev, ex); err == nil {
				t.Fatal("the altered evidence still checks")
			}
		})
	}
}

// The two lines the page quotes are still in the squeeze example's transcript of the
// hackathon scan.
func TestQuotedHackathonLinesAreInTheTranscript(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "squeeze", "argon-scan.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{argonFind, argonClean} {
		if !strings.Contains(string(raw), line+"\n") {
			t.Errorf("argon-scan.txt no longer holds %q", line)
		}
	}
}

// The whole example, on WASM: the tools built from source, the daemon started with the
// set, the five calls, the offline scans. Every claim checks, and no seed or line of the
// simulator reaches the daemon's log (checked inside run), the evidence or the page.
// The seeds are random, so this is a canary run as well.
func TestExampleRunsEndToEnd(t *testing.T) {
	t.Chdir(filepath.Join("..", ".."))
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	ev, secrets, ex, err := run(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := checkEvidence(ev, ex); err != nil {
		t.Fatal(err)
	}
	evidence, err := marshalEvidence(ev)
	if err != nil {
		t.Fatal(err)
	}
	page, err := renderPage(ev)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"the evidence": evidence, "the page": page, "the clean request": ex.request, "the clean response": ex.response} {
		if err := noSecrets(name, data, secrets); err != nil {
			t.Error(err)
		}
	}
}
