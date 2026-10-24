package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/attest"
	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// receipts writes a receipts file of signed runs, one per trace and tier given, ending in
// a checkpoint as the MCP server's run segments do.
func receipts(t *testing.T, path string, signer *attest.Signer, runs [][2]string, starts ...time.Time) {
	t.Helper()
	var b bytes.Buffer
	h := attest.NewHarness(signer, &b)
	for i, r := range runs {
		req := &plimsollv1.RunRequest{Protocol: 3, TraceId: r[0], Payload: &plimsollv1.RunRequest_Javascript{
			Javascript: &plimsollv1.JavaScriptRun{Code: "console.log(" + string(rune('0'+i)) + ")"}}}
		resp := &plimsollv1.RunResponse{Sandbox: "docker", Isolation: r[1],
			Result: &plimsollv1.RunResponse_Javascript{Javascript: &plimsollv1.JavaScriptResult{Stdout: []byte("ok\n")}}}
		rec := sandbox.RunRecord{RequestSHA256: record.RunRequestDigest(req)}
		if i < len(starts) {
			rec.Started, rec.Ended = starts[i], starts[i].Add(time.Millisecond)
		}
		resp.Record = record.Stamp(rec, resp)
		if err := h.Record(req, resp); err != nil {
			t.Fatal(err)
		}
		if err := h.Checkpoint(); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRunsSortByTimeAcrossWholeSeconds(t *testing.T) {
	dir := t.TempDir()
	signer, _, pub := keys(t, dir, "operator")
	receipts(t, filepath.Join(dir, "runs-order.jsonl"), signer, [][2]string{{"session", "kernel"}, {"session", "kernel"}},
		time.Unix(100, 100_000_000), time.Unix(100, 0))
	p, err := gather(dir, mustPub(t, pub), "session", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Runs) != 2 || p.Runs[0].Line != 3 || p.Runs[1].Line != 1 {
		t.Fatalf("runs are not chronological: %+v", p.Runs)
	}
}

func TestHookBlocksUnexpectedInputErrors(t *testing.T) {
	for name, input := range map[string]string{
		"invalid Unicode":   `{"session_id":"\ud800","tool_input":{"language":"javascript","code":"1"}}`,
		"excessive nesting": strings.Repeat("[", 1500) + "0" + strings.Repeat("]", 1500),
	} {
		t.Run(name, func(t *testing.T) {
			cmd := exec.Command("python3", "-I", "hook.py")
			cmd.Stdin = strings.NewReader(input)
			out, err := cmd.CombinedOutput()
			if err == nil {
				var answer struct {
					Hook struct {
						Decision string `json:"permissionDecision"`
					} `json:"hookSpecificOutput"`
				}
				if json.Unmarshal(out, &answer) != nil || answer.Hook.Decision != "deny" {
					t.Fatalf("input did not receive a blocking JSON decision: %s", out)
				}
			} else if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 2 {
				t.Fatalf("an unexpected error must block with exit 2: %v, %s", err, out)
			}
		})
	}
}

func keys(t *testing.T, dir, name string) (*attest.Signer, string, string) {
	t.Helper()
	priv, pub, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	keyPath, pubPath := filepath.Join(dir, name+".key"), filepath.Join(dir, name+".pub")
	if err := os.WriteFile(keyPath, priv, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubPath, pub, 0o644); err != nil {
		t.Fatal(err)
	}
	key, err := attest.ParsePrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return attest.NewSigner(key), keyPath, pubPath
}

// A session's statement lists exactly the runs carrying its trace, with the weakest tier
// among them; -check accepts it, counts a later run, and refuses another key's statement,
// an edited receipts file and a statement whose runs were edited.
func TestAgentSessionStatement(t *testing.T) {
	dir := t.TempDir()
	rec := filepath.Join(dir, "receipts")
	if err := os.Mkdir(rec, 0o700); err != nil {
		t.Fatal(err)
	}
	signer, keyPath, pubPath := keys(t, dir, "harness")
	_, otherKey, _ := keys(t, dir, "other")
	session := "3f6c2a9e-1b7d-4e8a-9c0f-2d5b6a7e8f90"
	receipts(t, filepath.Join(rec, "runs-a-1.jsonl"), signer, [][2]string{{session, "kernel"}, {"another", "vm"}, {session, "container"}})
	receipts(t, filepath.Join(rec, "runs-b-1.jsonl"), signer, [][2]string{{session, "vm"}})

	statement := filepath.Join(dir, "session.intoto.json")
	var out bytes.Buffer
	if err := run([]string{"-receipts", rec, "-pub", pubPath, "-session", session, "-key", keyPath, "-out", statement}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "signed 3 run(s)") || !strings.Contains(out.String(), "weakest tier container") || !strings.Contains(out.String(), "from 2 receipts file(s)") {
		t.Errorf("sign: %s", out.String())
	}
	check := func(path string) (string, error) {
		var o bytes.Buffer
		err := run([]string{"-receipts", rec, "-pub", pubPath, "-session", session, "-check", path}, &o)
		return o.String(), err
	}
	if got, err := check(statement); err != nil || !strings.Contains(got, "0 run(s) with the trace it does not cover") {
		t.Fatalf("check: %v %s", err, got)
	}

	// A later run with the trace is reported, not a failure.
	receipts(t, filepath.Join(rec, "runs-c-1.jsonl"), signer, [][2]string{{session, "kernel"}})
	if got, err := check(statement); err != nil || !strings.Contains(got, "1 run(s) with the trace it does not cover") {
		t.Errorf("check after a later run: %v %s", err, got)
	}

	// Signed with a key that is not the receipts key.
	other := filepath.Join(dir, "other.intoto.json")
	if err := run([]string{"-receipts", rec, "-pub", pubPath, "-session", session, "-key", otherKey, "-out", other}, &out); err != nil {
		t.Fatal(err)
	}
	if _, err := check(other); err == nil {
		t.Error("check accepted a statement signed with another key")
	}

	// The statement's tier for one run changed and signed again with the right key: the
	// claim no longer matches the signed record.
	raw, err := os.ReadFile(statement)
	if err != nil {
		t.Fatal(err)
	}
	var env attest.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	var p Predicate
	subs, err := attest.NewVerifier(mustPub(t, pubPath)).OpenStatement(env, PredicateType, &p)
	if err != nil {
		t.Fatal(err)
	}
	for i := range p.Runs {
		if p.Runs[i].Isolation == "container" {
			p.Runs[i].Isolation = "kernel"
		}
	}
	p.WeakestIsolation = weakest(p.Runs)
	forged, err := signer.SignStatement(PredicateType, subs, p)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(forged)
	forgedPath := filepath.Join(dir, "forged.intoto.json")
	if err := os.WriteFile(forgedPath, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := check(forgedPath); err == nil || !strings.Contains(err.Error(), "stated differently") {
		t.Errorf("check of a statement whose tier was raised: %v", err)
	}

	// Signed with the right key, but claiming file bytes it never read, or leaving out a
	// run that was inside what it read.
	resign := func(name string, edit func(*Predicate)) string {
		var q Predicate
		if _, err := attest.NewVerifier(mustPub(t, pubPath)).OpenStatement(env, PredicateType, &q); err != nil {
			t.Fatal(err)
		}
		edit(&q)
		q.WeakestIsolation = weakest(q.Runs)
		env, err := signer.SignStatement(PredicateType, subjects(q.Runs), q)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(env)
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	zeroed := resign("zeroed.intoto.json", func(q *Predicate) { q.Files[0].SHA256 = strings.Repeat("0", 64) })
	if _, err := check(zeroed); err == nil || !strings.Contains(err.Error(), "does not begin with the bytes") {
		t.Errorf("check of a statement with a file digest it never read: %v", err)
	}
	omitted := resign("omitted.intoto.json", func(q *Predicate) { q.Runs = q.Runs[1:] })
	if _, err := check(omitted); err == nil || !strings.Contains(err.Error(), "leaves it out") {
		t.Errorf("check of a statement that leaves out a run it read: %v", err)
	}

	// A receipts file edited after signing stops the check outright.
	seg := filepath.Join(rec, "runs-b-1.jsonl")
	body, err := os.ReadFile(seg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(seg, bytes.Replace(body, []byte(`"`), []byte(`"x`), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := check(statement); err == nil || !strings.Contains(err.Error(), "does not verify whole") {
		t.Errorf("check over an edited receipts file: %v", err)
	}
	var o bytes.Buffer
	if err := run([]string{"-receipts", rec, "-pub", pubPath, "-session", session, "-check", statement, "-ignore-unverified"}, &o); err == nil {
		t.Error("with the edited file skipped, its run is missing, and the check must fail")
	}
}

func mustPub(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := attest.ParsePublicKey(b)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// The hook and this command derive the same trace from a session ID, and the hook's two
// modes answer as documented.
func TestHookAgreesAndAnswers(t *testing.T) {
	ids := []string{"3f6c2a9e-1b7d-4e8a-9c0f-2d5b6a7e8f90", "abc123", "has space and/slash", strings.Repeat("x", 65),
		// A literal ID shaped like another ID's hashed trace is hashed too.
		TraceFor("has space and/slash")}
	if TraceFor(ids[4]) == ids[4] || TraceFor(ids[4]) == TraceFor(ids[2]) {
		t.Errorf("the literal ID %q takes the trace of %q", ids[4], ids[2])
	}
	for _, id := range ids {
		event, _ := json.Marshal(map[string]any{"session_id": id, "tool_name": "mcp__plimsoll__run_code",
			"tool_input": map[string]any{"code": "print(1)", "trace": "made-up"}})
		cmd := exec.Command("python3", "-I", "hook.py")
		cmd.Stdin = bytes.NewReader(event)
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("%q: %v", id, err)
		}
		var answer struct {
			HookSpecificOutput struct {
				PermissionDecision string         `json:"permissionDecision"`
				UpdatedInput       map[string]any `json:"updatedInput"`
			} `json:"hookSpecificOutput"`
		}
		if err := json.Unmarshal(out, &answer); err != nil {
			t.Fatalf("%q: %v: %s", id, err, out)
		}
		in := answer.HookSpecificOutput.UpdatedInput
		if answer.HookSpecificOutput.PermissionDecision != "allow" || in["trace"] != TraceFor(id) || in["code"] != "print(1)" {
			t.Errorf("%q: rewrite gave %s, want trace %s", id, out, TraceFor(id))
		}
		if !traceForm.MatchString(TraceFor(id)) {
			t.Errorf("%q: trace %q breaks plimsoll's rule", id, TraceFor(id))
		}
	}
	require := func(trace any) string {
		t.Helper()
		event, _ := json.Marshal(map[string]any{"session_id": "abc123", "tool_input": map[string]any{"code": "1", "trace": trace}})
		cmd := exec.Command("python3", "-I", "hook.py")
		cmd.Env = append(os.Environ(), "PLIMSOLL_HOOK_MODE=require")
		cmd.Stdin = bytes.NewReader(event)
		out, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}
		return string(out)
	}
	if got := require("abc123"); got != "" {
		t.Errorf("require mode with the right trace answered %q; it should stay silent", got)
	}
	if got := require("other"); !strings.Contains(got, `"permissionDecision": "deny"`) || !strings.Contains(got, `\"trace\": \"abc123\"`) {
		t.Errorf("require mode with the wrong trace: %s", got)
	}
	cmd := exec.Command("python3", "-I", "hook.py")
	cmd.Stdin = strings.NewReader(`{"tool_input": {"code": "1"}}`)
	if out, _ := cmd.Output(); !strings.Contains(string(out), `"deny"`) {
		t.Errorf("no session ID: %s", out)
	}
}
