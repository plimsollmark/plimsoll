package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/internal/auditline"
	"github.com/plimsollmark/plimsoll/record"
)

var recordCheck = record.Check

// The labels the build gives: a file is labeled by its path from the named directory's
// parent, a value by its file's name and line. The agent's snippet carries the second
// seed.
const (
	labelHarness = "harness/sim.py"
	labelSeed    = "seeds.txt:2"
)

const (
	msgRefused = "withheld material refused"
	msgFound   = "withheld material found"
	// wantRefusal is the refusal each harness call must get, word for word: the label
	// and the place, nothing more.
	wantRefusal = "the request carries material this daemon's operator withholds from sandboxes: " + labelHarness + " (files[0].content)"
)

// callOrder is the five calls, in the order the page tells them.
var callOrder = []string{"clean", "harness-file", "harness-edited", "harness-archive", "seed-in-code"}

// checkEvidence checks every claim the page makes against the evidence and, for the
// clean call, the exchange: the run checks it before publishing, and -verify checks the
// published files again.
func checkEvidence(ev *Evidence, ex *exchange) error {
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	sum := sha256.Sum256(ex.set)
	if got := hex.EncodeToString(sum[:]); got != ev.SetSHA256 {
		fail("the set file's SHA-256 is %s, the evidence says %s", got, ev.SetSHA256)
	}
	if ev.Provider != "wasm" || ev.Isolation != "process" {
		fail("provider %q at tier %q, want wasm at process", ev.Provider, ev.Isolation)
	}
	if entries, err := setEntries(ex.set); err != nil || !slices.Equal(entries, ev.Entries) {
		fail("the evidence's entries are not the set file's (%v)", err)
	}
	modes := map[string]string{}
	for _, e := range ev.Entries {
		modes[e.Kind+" "+e.Label] = e.Mode
	}
	for key, want := range map[string]string{"file " + labelHarness: "refuse", "source " + labelHarness: "refuse",
		"value seeds.txt:1": "audit", "value " + labelSeed: "audit", "value seeds.txt:3": "audit"} {
		if modes[key] != want {
			fail("the set's %s entry is %q, want %q", key, modes[key], want)
		}
	}
	var names []string
	for _, c := range ev.Calls {
		names = append(names, c.Name)
	}
	if !slices.Equal(names, callOrder) {
		fail("the calls are %v, want %v", names, callOrder)
	}
	for _, c := range ev.Calls {
		if c.TraceID != "ship-scan-"+c.Name {
			fail("%s: trace id %q", c.Name, c.TraceID)
		}
		for _, l := range c.Log {
			if l.TraceID != c.TraceID {
				fail("%s: a log line of trace %q", c.Name, l.TraceID)
			}
			if l.WithheldScan != "scanned" || l.WithheldSet != ev.SetSHA256 || len(l.WithheldIncomplete) != 0 {
				fail("%s: a log line states scan %q of set %q (incomplete %v), want a complete scan of the published set", c.Name, l.WithheldScan, l.WithheldSet, l.WithheldIncomplete)
			}
		}
		runLine, scanLine := lineOf(c.Log, auditline.IsRun), lineOf(c.Log, func(m string) bool { return m == msgFound || m == msgRefused })
		switch c.Expect {
		case expectRuns:
			if !c.Answer.Ran || c.Answer.ExitCode != 0 || c.Answer.Code != "" {
				fail("%s: want a run that exited 0, got %+v", c.Name, c.Answer)
			}
			if runLine == nil || len(runLine.WithheldFound) != 0 {
				fail("%s: want a run line stating a scan that found nothing, got %+v", c.Name, runLine)
			}
			if scanLine != nil {
				fail("%s: a clean call has a %q line", c.Name, scanLine.Msg)
			}
		case expectRefused:
			if c.Answer.Ran || c.Answer.Code != "permission_denied" || c.Answer.Mark != "permission" || c.Answer.Message != wantRefusal ||
				c.Answer.Stdout != "" || c.Answer.ExitCode != 0 {
				fail("%s: want permission_denied, the permission mark and %q, got %+v", c.Name, wantRefusal, c.Answer)
			}
			if c.Record != nil {
				fail("%s: a refused call has a run record", c.Name)
			}
			if runLine != nil {
				fail("%s: a refused call has a run line", c.Name)
			}
			if len(c.Log) != 1 || scanLine == nil || scanLine.Msg != msgRefused || scanLine.WithheldRefused == nil || !*scanLine.WithheldRefused ||
				!slices.Equal(scanLine.WithheldFound, []string{labelHarness}) {
				fail("%s: want a %q line naming %s, got %+v", c.Name, msgRefused, labelHarness, scanLine)
			}
		case expectRunsLogged:
			if !c.Answer.Ran || c.Answer.ExitCode != 0 || c.Answer.Code != "" || c.Answer.Message != "" ||
				strings.Contains(c.Answer.Stdout, "seeds.txt") {
				fail("%s: want a run that exited 0 and told the caller nothing, got %+v", c.Name, c.Answer)
			}
			if len(c.Log) != 2 || scanLine == nil || scanLine.Msg != msgFound || scanLine.WithheldRefused == nil || *scanLine.WithheldRefused ||
				!slices.Equal(scanLine.WithheldFound, []string{labelSeed}) {
				fail("%s: want a %q line naming %s, got %+v", c.Name, msgFound, labelSeed, scanLine)
			}
			if runLine == nil || !slices.Equal(runLine.WithheldFound, []string{labelSeed}) {
				fail("%s: want the run line to name %s again, got %+v", c.Name, labelSeed, runLine)
			}
		default:
			fail("%s: unknown expectation %q", c.Name, c.Expect)
		}
		if c.Answer.Ran && (c.Record == nil || len(c.Record.RequestSHA256) != 64 || len(c.Record.ResultSHA256) != 64) {
			fail("%s: a run without its record's digests", c.Name)
		}
		if c.Name == "harness-archive" && strings.Contains(c.Answer.Message, "vendor/plant.py") {
			fail("%s: the refusal names the archive member", c.Name)
		}
	}
	if err := checkCleanRecord(ev, ex); err != nil {
		errs = append(errs, err)
	}
	if err := checkSeedResponse(ev, ex); err != nil {
		errs = append(errs, err)
	}
	if len(ev.Offline) != 2 {
		fail("%d offline scans, want 2", len(ev.Offline))
	} else {
		out, clean := ev.Offline[0], ev.Offline[1]
		joined := strings.Join(out.Output, "\n")
		if out.Exit != 1 || !strings.Contains(joined, labelHarness) || !strings.Contains(joined, labelSeed) {
			fail("the outbox scan: want exit 1 naming %s and %s, got exit %d: %q", labelHarness, labelSeed, out.Exit, joined)
		}
		if clean.Exit != 0 || len(clean.Output) == 0 || !strings.HasPrefix(clean.Output[0], "clean:") {
			fail("the clean scan: want exit 0 and clean, got exit %d: %q", clean.Exit, clean.Output)
		}
	}
	return errors.Join(errs...)
}

// checkCleanRecord recomputes the clean call's run record from its exchange.
func checkCleanRecord(ev *Evidence, ex *exchange) error {
	var clean *Call
	for i := range ev.Calls {
		if ev.Calls[i].Name == "clean" {
			clean = &ev.Calls[i]
		}
	}
	if clean == nil || clean.Record == nil || !clean.Record.Published {
		return errors.New("the clean call's record is not published")
	}
	var req plimsollv1.RunRequest
	var resp plimsollv1.RunResponse
	if err := protojson.Unmarshal(ex.request, &req); err != nil {
		return fmt.Errorf("%s: %w", fileCleanRequest, err)
	}
	if err := protojson.Unmarshal(ex.response, &resp); err != nil {
		return fmt.Errorf("%s: %w", fileCleanResponse, err)
	}
	rec, err := recordCheck(&req, &resp)
	if err != nil {
		return fmt.Errorf("the clean call's record does not check: %w", err)
	}
	if rec.Version != clean.Record.Version || rec.RequestSHA256 != clean.Record.RequestSHA256 || rec.ResultSHA256 != clean.Record.ResultSHA256 {
		return fmt.Errorf("the clean call's exchange gives record v%d %s %s, the evidence says v%d %s %s",
			rec.Version, rec.RequestSHA256, rec.ResultSHA256, clean.Record.Version, clean.Record.RequestSHA256, clean.Record.ResultSHA256)
	}
	if req.GetTraceId() != clean.TraceID {
		return fmt.Errorf("the clean call's request carries trace %q", req.GetTraceId())
	}
	return answerIsResponse(ev, clean, &resp)
}

// checkSeedResponse recomputes the audit-mode call's result digest from its published
// response, and checks the record digests the evidence states are the response's.
func checkSeedResponse(ev *Evidence, ex *exchange) error {
	var seed *Call
	for i := range ev.Calls {
		if ev.Calls[i].Name == "seed-in-code" {
			seed = &ev.Calls[i]
		}
	}
	if seed == nil || seed.Record == nil || seed.Record.Published {
		return errors.New("the seed call's record is missing, or says its request is published")
	}
	var resp plimsollv1.RunResponse
	if err := protojson.Unmarshal(ex.seedResponse, &resp); err != nil {
		return fmt.Errorf("%s: %w", fileSeedResponse, err)
	}
	r := resp.GetRecord()
	if got := record.ResultDigest(&resp); got != seed.Record.ResultSHA256 || r.GetResultSha256() != got ||
		r.GetRequestSha256() != seed.Record.RequestSHA256 || int(r.GetVersion()) != seed.Record.Version {
		return fmt.Errorf("the seed call's response gives result %s (record v%d, %s, %s), the evidence says v%d %s %s",
			got, r.GetVersion(), r.GetRequestSha256(), r.GetResultSha256(), seed.Record.Version, seed.Record.RequestSHA256, seed.Record.ResultSHA256)
	}
	return answerIsResponse(ev, seed, &resp)
}

// answerIsResponse checks that the answer the page shows for c is the response's, and
// that the response names the provider and tier the page states.
func answerIsResponse(ev *Evidence, c *Call, resp *plimsollv1.RunResponse) error {
	js := resp.GetJavascript()
	if js == nil || !c.Answer.Ran || c.Answer.Stdout != string(js.GetStdout()) || c.Answer.ExitCode != int(js.GetExitCode()) {
		return fmt.Errorf("%s: the answer shown (%+v) is not the response's", c.Name, c.Answer)
	}
	if resp.GetSandbox() != ev.Provider || resp.GetIsolation() != ev.Isolation {
		return fmt.Errorf("%s: the response names %s at %s, the page %s at %s", c.Name, resp.GetSandbox(), resp.GetIsolation(), ev.Provider, ev.Isolation)
	}
	return nil
}

func lineOf(lines []LogLine, is func(string) bool) *LogLine {
	for i := range lines {
		if is(lines[i].Msg) {
			return &lines[i]
		}
	}
	return nil
}

// noSecrets fails when data holds any of secrets.
func noSecrets(what string, data []byte, secrets []string) error {
	for _, s := range secrets {
		if bytes.Contains(data, []byte(s)) {
			return fmt.Errorf("%s holds a withheld value or a line of the harness (%d bytes long)", what, len(s))
		}
	}
	return nil
}

// publish writes the evidence, the set, the clean exchange and the page, after checking
// that none of them holds a secret, and then verifies what it wrote.
func publish(dir string, ev *Evidence, ex *exchange, secrets []string) error {
	evidence, err := marshalEvidence(ev)
	if err != nil {
		return err
	}
	page, err := renderPage(ev)
	if err != nil {
		return err
	}
	files := map[string][]byte{fileEvidence: evidence, fileSet: ex.set, fileCleanRequest: ex.request, fileCleanResponse: ex.response,
		fileSeedResponse: ex.seedResponse, filePage: page}
	for name, data := range files {
		if err := noSecrets(name, data, secrets); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			return err
		}
	}
	if err := verifyPublished(dir); err != nil {
		return fmt.Errorf("what was written does not verify: %w", err)
	}
	fmt.Printf("published | %s\n", dir)
	return nil
}

func readPublished(dir string) (*Evidence, *exchange, error) {
	ev, err := readEvidence(dir)
	if err != nil {
		return nil, nil, err
	}
	ex := &exchange{}
	for name, dst := range map[string]*[]byte{fileSet: &ex.set, fileCleanRequest: &ex.request, fileCleanResponse: &ex.response, fileSeedResponse: &ex.seedResponse} {
		if *dst, err = os.ReadFile(filepath.Join(dir, name)); err != nil {
			return nil, nil, err
		}
	}
	return ev, ex, nil
}

// verifyPublished checks the published files offline: every claim against the evidence,
// the set's digest, the clean call's record recomputed, and the page is what the
// evidence renders.
func verifyPublished(dir string) error {
	ev, ex, err := readPublished(dir)
	if err != nil {
		return err
	}
	if err := checkEvidence(ev, ex); err != nil {
		return err
	}
	want, err := renderPage(ev)
	if err != nil {
		return err
	}
	got, err := os.ReadFile(filepath.Join(dir, filePage))
	if err != nil {
		return err
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("%s is not what %s renders: go run ./examples/ship-scan -render", filePage, fileEvidence)
	}
	return nil
}

// renderPublished rewrites the page from the published evidence, which must check.
func renderPublished(dir string) error {
	ev, ex, err := readPublished(dir)
	if err != nil {
		return err
	}
	if err := checkEvidence(ev, ex); err != nil {
		return err
	}
	page, err := renderPage(ev)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, filePage), page, 0o644)
}
