package trainers

// The two pages for newcomers, "What a sandbox is" (docs/examples/what-a-sandbox-is) and
// "Proof of what ran" (docs/examples/proof-of-what-ran), show five real runs on the wasm
// provider and let the reader check their run records in the browser. Every value they
// show comes from one evidence block, generated here from the signed bundle published
// beside the second page, so a page cannot drift from the recording it describes:
//
//	go test ./docs/trainers -run TestSandboxBasics -update
//
// rewrites the block in both pages after a new recording. Without -update the test
// fails when a page's block differs. It also holds the other published files to what
// the pages say about them: the bundle verifies with the published key and holds the
// five requests in requests/ in order, the refused request is not in it, the tampered
// copy fails both the whole-file check and the line-alone check, and the shortened copy
// verifies on its own but fails against the caller's list in requests-sent.txt.

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/plimsollmark/plimsoll/attest"
	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/record"
)

const (
	basicsEvidenceDir = "../examples/proof-of-what-ran"
	basicsBlockOpen   = `<script type="application/json" id="evidence">`
	basicsBlockClose  = `</script>`
)

// The runs in the order they were recorded; floor is the request refused before dispatch.
var (
	basicsRuns  = []string{"polite", "network", "files", "memory", "forever"}
	basicsPages = []string{"../examples/what-a-sandbox-is/index.html", "../examples/proof-of-what-ran/index.html"}
)

// The block's types. The field names are the names the digest encoding gives each value
// (docs/run-records.md, "The encoding"), so the page's script reads the order it hashes
// in from the specification, not from this file.
type basicsEvidence struct {
	Note         string      `json:"note"`
	PublicKeyPEM string      `json:"public_key_pem"`
	KeyID        string      `json:"key_id"`
	Runs         []basicsRun `json:"runs"`
}

type basicsRun struct {
	Name string `json:"name"`
	Line int    `json:"line"`
	// DurationMs is the response's duration_ms: how long the code ran, as the daemon
	// measured it. It is not in the result digest (it differs on every run).
	DurationMs int64          `json:"duration_ms"`
	Request    basicsRequest  `json:"request"`
	Result     basicsResult   `json:"result"`
	Record     basicsRecord   `json:"record"`
	Envelope   basicsEnvelope `json:"envelope"`
}

// basicsClaims are what the pages' prose says each run printed or how it ended, beyond
// what their script shows from the block: a new recording that changes one fails here,
// so the prose is reread before it ships.
var basicsClaims = map[string]func(r basicsRun) bool{
	"polite": func(r basicsRun) bool {
		return r.Result.Stdout == "Hello from a stranger. 2 + 2 = 4\n" && r.Result.ExitCode == 0
	},
	"network": func(r basicsRun) bool {
		return strings.Count(r.Result.Stdout, ": undefined\n") == 5 && r.Result.ExitCode == 0
	},
	"files": func(r basicsRun) bool {
		return r.Result.Stdout == "open /etc/passwd: null\nlist /: [[],44]\n"
	},
	"memory": func(r basicsRun) bool {
		return r.Result.Stdout == "kept 31 piles of a million numbers, then: InternalError: out of memory\n" && r.Result.ExitCode == 0
	},
	"forever": func(r basicsRun) bool {
		return r.Request.TimeoutMs == 2000 && r.Result.TimedOut && r.Result.ExitCode == 124
	},
}

type basicsRequest struct {
	Protocol           uint32   `json:"protocol"`
	MinimumIsolation   string   `json:"minimum_isolation"`
	TimeoutMs          int32    `json:"timeout_ms"`
	SoftwareMode       string   `json:"software_mode"`
	SoftwareIdentities []string `json:"software_identities"`
	Kind               string   `json:"kind"`
	Code               string   `json:"code"`
	GrantProfile       string   `json:"grant_profile"`
}

type basicsResult struct {
	Kind            string `json:"kind"`
	ExitCode        int32  `json:"exit_code"`
	TimedOut        bool   `json:"timed_out"`
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	StdoutTruncated bool   `json:"stdout_truncated"`
	StderrTruncated bool   `json:"stderr_truncated"`
}

type basicsRecord struct {
	Version          int    `json:"version"`
	RequestSHA256    string `json:"request_sha256"`
	ResultSHA256     string `json:"result_sha256"`
	Unanswered       string `json:"unanswered"`
	Provider         string `json:"provider"`
	Isolation        string `json:"isolation"`
	Environment      string `json:"environment"`
	Policy           string `json:"policy"`
	SoftwareIdentity string `json:"software_identity"`
	SoftwareRuleID   string `json:"software_rule_id"`
	Instance         string `json:"instance"`
	StartedUnixMs    int64  `json:"started_unix_ms"`
	EndedUnixMs      int64  `json:"ended_unix_ms"`
	Session          string `json:"session"`
	Sequence         uint64 `json:"sequence"`
	PreviousSHA256   string `json:"previous_sha256"`
	RecordSHA256     string `json:"record_sha256"`
}

type basicsEnvelope struct {
	PayloadType string `json:"payload_type"`
	Payload     string `json:"payload"`
	KeyID       string `json:"keyid"`
	Sig         string `json:"sig"`
}

func readBasicsBundle(t *testing.T, name string) []attest.Entry {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(basicsEvidenceDir, name))
	if err != nil {
		t.Fatal(err)
	}
	entries, err := attest.ReadBundle(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return entries
}

func basicsVerifier(t *testing.T) (*attest.Verifier, string, string) {
	t.Helper()
	pem := readFile(t, filepath.Join(basicsEvidenceDir, "harness.pub"))
	pub, err := attest.ParsePublicKey([]byte(pem))
	if err != nil {
		t.Fatal(err)
	}
	return attest.NewVerifier(pub), pem, attest.KeyID(pub)
}

// TestSandboxBasicsEvidence builds the evidence block from the verified bundle and
// holds both pages to it.
func TestSandboxBasicsEvidence(t *testing.T) {
	v, pem, keyID := basicsVerifier(t)
	entries := readBasicsBundle(t, "bundle.jsonl")
	report, err := attest.VerifyBundle(entries, v)
	if err != nil {
		t.Fatalf("bundle.jsonl does not verify with harness.pub: %v", err)
	}
	if report.Runs != len(basicsRuns) || len(report.Sessions) != 0 {
		t.Fatalf("bundle.jsonl holds %d single runs and %d sessions, want %d single runs", report.Runs, len(report.Sessions), len(basicsRuns))
	}

	ev := basicsEvidence{
		Note:         "Generated from bundle.jsonl by docs/trainers/sandbox_basics_test.go; run it with -update after a new recording, never edit by hand.",
		PublicKeyPEM: pem,
		KeyID:        keyID,
	}
	for i, e := range entries {
		if len(e.Request) == 0 {
			continue // a checkpoint: a link alone
		}
		req, resp, err := e.Messages()
		if err != nil {
			t.Fatal(err)
		}
		n := len(ev.Runs)
		if n >= len(basicsRuns) {
			t.Fatalf("bundle.jsonl has more calls than the %d the pages describe", len(basicsRuns))
		}
		js, out := req.GetJavascript(), resp.GetJavascript()
		if js == nil || out == nil {
			t.Fatalf("line %d is not a JavaScript run; the pages' script hashes only that kind", i+1)
		}
		if !utf8.Valid(out.GetStdout()) || !utf8.Valid(out.GetStderr()) {
			t.Fatalf("line %d's output is not UTF-8 text; the block carries it as a string", i+1)
		}
		w := resp.GetRecord()
		rec := record.FromWire(w)
		if len(e.Envelope.Signatures) != 1 {
			t.Fatalf("line %d has %d signatures, want 1", i+1, len(e.Envelope.Signatures))
		}
		ev.Runs = append(ev.Runs, basicsRun{
			Name:       basicsRuns[n],
			Line:       i + 1,
			DurationMs: resp.GetDurationMs(),
			Request: basicsRequest{
				Protocol:           req.GetProtocol(),
				MinimumIsolation:   req.GetMinimumIsolation(),
				TimeoutMs:          req.GetTimeoutMs(),
				SoftwareMode:       req.GetSoftwareRule().GetMode(),
				SoftwareIdentities: append([]string{}, req.GetSoftwareRule().GetIdentities()...),
				Kind:               "javascript",
				Code:               js.GetCode(),
				GrantProfile:       js.GetGrantProfile(),
			},
			Result: basicsResult{
				Kind:            "javascript",
				ExitCode:        out.GetExitCode(),
				TimedOut:        out.GetTimedOut(),
				Stdout:          string(out.GetStdout()),
				Stderr:          string(out.GetStderr()),
				StdoutTruncated: out.GetStdoutTruncated(),
				StderrTruncated: out.GetStderrTruncated(),
			},
			Record: basicsRecord{
				Version: rec.Version, RequestSHA256: rec.RequestSHA256, ResultSHA256: rec.ResultSHA256,
				Unanswered: rec.Unanswered, Provider: rec.Provider, Isolation: rec.Isolation,
				Environment: rec.Environment, Policy: rec.Policy, SoftwareIdentity: rec.SoftwareIdentity,
				SoftwareRuleID: rec.SoftwareRuleID, Instance: rec.Instance,
				StartedUnixMs: rec.Started.UnixMilli(), EndedUnixMs: rec.Ended.UnixMilli(),
				Session: rec.Session, Sequence: rec.Sequence, PreviousSHA256: rec.PreviousSHA256,
				RecordSHA256: rec.SHA256,
			},
			Envelope: basicsEnvelope{
				PayloadType: e.Envelope.PayloadType,
				Payload:     e.Envelope.Payload,
				KeyID:       e.Envelope.Signatures[0].KeyID,
				Sig:         e.Envelope.Signatures[0].Sig,
			},
		})
		// What the page's script recomputes, recomputed here from the same values.
		if got := record.RunRequestDigest(req); got != rec.RequestSHA256 {
			t.Errorf("line %d: request digest %s, record states %s", i+1, got, rec.RequestSHA256)
		}
		if got := record.ResultDigest(resp); got != rec.ResultSHA256 {
			t.Errorf("line %d: result digest %s, record states %s", i+1, got, rec.ResultSHA256)
		}
		if got := record.Digest(rec); got != rec.SHA256 {
			t.Errorf("line %d: record digest %s, record states %s", i+1, got, rec.SHA256)
		}
	}
	if len(ev.Runs) != len(basicsRuns) {
		t.Fatalf("bundle.jsonl has %d calls, the pages describe %d", len(ev.Runs), len(basicsRuns))
	}
	for _, r := range ev.Runs {
		if r.Record.Provider != "wasm" || r.Record.Isolation != "process" {
			t.Errorf("run %s states provider %q at %q; the pages say every run was wasm at process", r.Name, r.Record.Provider, r.Record.Isolation)
		}
		if !basicsClaims[r.Name](r) {
			t.Errorf("run %s no longer shows what the pages' prose says it shows (stdout %q, exit %d, timed out %v); reread the prose", r.Name, r.Result.Stdout, r.Result.ExitCode, r.Result.TimedOut)
		}
	}

	block, err := json.MarshalIndent(ev, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	want := basicsBlockOpen + "\n" + string(block) + "\n" + basicsBlockClose
	for _, page := range basicsPages {
		body := readFile(t, page)
		start := strings.Index(body, basicsBlockOpen)
		if start < 0 {
			t.Errorf("%s has no evidence block (%s)", page, basicsBlockOpen)
			continue
		}
		end := strings.Index(body[start:], basicsBlockClose)
		if end < 0 {
			t.Errorf("%s: the evidence block is not closed", page)
			continue
		}
		got := body[start : start+end+len(basicsBlockClose)]
		if got == want {
			continue
		}
		if *update {
			if err := os.WriteFile(page, []byte(body[:start]+want+body[start+end+len(basicsBlockClose):]), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		t.Errorf("%s: the evidence block differs from bundle.jsonl; run go test ./docs/trainers -run TestSandboxBasics -update", page)
	}
}

// TestSandboxBasicsFiles holds the other published files to what the pages say of them.
func TestSandboxBasicsFiles(t *testing.T) {
	v, _, _ := basicsVerifier(t)
	entries := readBasicsBundle(t, "bundle.jsonl")

	// requests/: the five sent, in order, and the refused one, which has no record.
	var recorded []string
	for _, e := range entries {
		if len(e.Request) == 0 {
			continue
		}
		req, _, err := e.Messages()
		if err != nil {
			t.Fatal(err)
		}
		recorded = append(recorded, record.RunRequestDigest(req))
	}
	digestOf := func(name string) string {
		var req plimsollv1.RunRequest
		if err := protojson.Unmarshal([]byte(readFile(t, filepath.Join(basicsEvidenceDir, "requests", name+".json"))), &req); err != nil {
			t.Fatalf("requests/%s.json: %v", name, err)
		}
		return record.RunRequestDigest(&req)
	}
	for i, name := range basicsRuns {
		if i < len(recorded) && digestOf(name) != recorded[i] {
			t.Errorf("requests/%s.json is not the request on the bundle's call %d", name, i+1)
		}
	}
	for _, d := range recorded {
		if d == digestOf("floor") {
			t.Error("requests/floor.json is in the bundle; the pages say it was refused before anything ran, so it has no record")
		}
	}

	// requests-sent.txt: the caller's own list, one request digest per line.
	var sent []string
	for _, line := range strings.Split(strings.TrimSpace(readFile(t, filepath.Join(basicsEvidenceDir, "requests-sent.txt"))), "\n") {
		sent = append(sent, strings.Fields(line)[0])
	}
	if strings.Join(sent, " ") != strings.Join(recorded, " ") {
		t.Errorf("requests-sent.txt lists %v, the bundle's requests are %v", sent, recorded)
	}
	if _, err := attest.VerifyExpected(entries, v, attest.Expected{Requests: sent}); err != nil {
		t.Errorf("bundle.jsonl against requests-sent.txt: %v", err)
	}

	// tampered.jsonl: one byte of the first call's output changed, nothing else.
	tampered := readBasicsBundle(t, "tampered.jsonl")
	if _, err := attest.VerifyBundle(tampered, v); err == nil {
		t.Error("tampered.jsonl verifies as a whole; the page says it is refused")
	}
	if _, err := attest.VerifyCall(v, tampered[0]); !errors.Is(err, record.ErrMismatch) {
		t.Errorf("tampered.jsonl line 1 alone: %v, want record.ErrMismatch (the result no longer matches its signed record)", err)
	}
	_, resp, err := tampered[0].Messages()
	if err != nil {
		t.Fatal(err)
	}
	if got := string(resp.GetJavascript().GetStdout()); got != "Hello from a stranger. 2 + 2 = 5\n" {
		t.Errorf("tampered.jsonl line 1 prints %q; the page says it was changed to 2 + 2 = 5", got)
	}
	for i := 1; i < len(entries); i++ {
		if attest.LineDigest(tampered[i]) != attest.LineDigest(entries[i]) {
			t.Errorf("tampered.jsonl line %d differs from bundle.jsonl; only line 1 was changed", i+1)
		}
	}

	// shortened.jsonl: the bundle cut back to its first checkpoint verifies on its own,
	// and only the caller's list shows the four missing calls.
	shortened := readBasicsBundle(t, "shortened.jsonl")
	if report, err := attest.VerifyBundle(shortened, v); err != nil || report.Runs != 1 {
		t.Errorf("shortened.jsonl: %d runs, %v; the page says it verifies as whole with one run", report.Runs, err)
	}
	if _, err := attest.VerifyExpected(shortened, v, attest.Expected{Requests: sent}); !errors.Is(err, attest.ErrExpected) {
		t.Error("shortened.jsonl passes against requests-sent.txt; the page says the list catches the missing calls")
	}
}
