package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/plimsollmark/plimsoll/attest"
	"github.com/plimsollmark/plimsoll/internal/rpc"
	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandboxtest"
)

// The loop against a scripted model and an in-memory daemon with sessions: the model asks
// for one run, sees its result (the record's digest among it), answers; the bundle
// verifies with the key the program wrote, and the page shows the run and its record.
func TestAgentRunsCodeAndTheBundleVerifies(t *testing.T) {
	calls := 0
	var sawTool string
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var req struct {
			Messages []message `json:"messages"`
			Tools    []tool    `json:"tools"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Tools) != 1 || req.Tools[0].Function.Name != "run_code" {
			http.Error(w, "bad request", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if calls == 1 {
			fmt.Fprint(w, `{"choices":[{"message":{"role":"assistant","content":"","tool_calls":[{"id":"c1","type":"function","function":{"name":"run_code","arguments":"{\"language\":\"python\",\"code\":\"print(2+2)\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":10,"completion_tokens":5}}`)
			return
		}
		last := req.Messages[len(req.Messages)-1]
		sawTool = last.Role + ":" + last.Content
		fmt.Fprint(w, `{"choices":[{"message":{"role":"assistant","content":"I ran print(2+2) and read the output."},"finish_reason":"stop"}],"usage":{"prompt_tokens":20,"completion_tokens":8}}`)
	}))
	t.Cleanup(fake.Close)

	svc := rpc.NewSandboxService(&sandboxtest.Sessions{})
	svc.Sessions = rpc.SessionConfig{MaxSessions: 2, Lifetime: time.Minute, IdleTimeout: time.Minute}
	mux := http.NewServeMux()
	path, h := rpc.NewHandler(svc, connect.WithInterceptors(rpc.AuthInterceptor(nil)))
	mux.Handle(path, h)
	daemon := httptest.NewServer(mux)
	t.Cleanup(daemon.Close)

	m := &chat{base: fake.URL, key: "test-key", model: "fake-nemotron", http: fake.Client()}
	dir := t.TempDir()
	out := filepath.Join(dir, "index.html")
	if err := run(context.Background(), m, "add two and two", daemon.URL, "", "", 4, out); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("model calls = %d, want 2", calls)
	}
	if !strings.HasPrefix(sawTool, "tool:") || !strings.Contains(sawTool, `"record_sha256":"`) || !strings.Contains(sawTool, `"exit_code":0`) {
		t.Fatalf("the model was not shown the run's result and record: %s", sawTool)
	}
	bundle, err := os.ReadFile(filepath.Join(dir, "bundle.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err := os.ReadFile(filepath.Join(dir, "harness.pub"))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := attest.ParsePublicKey(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := attest.ReadBundle(bytes.NewReader(bundle))
	if err != nil {
		t.Fatal(err)
	}
	rep, err := attest.VerifyBundle(entries, attest.NewVerifier(pub))
	if err != nil {
		t.Fatalf("the bundle the program wrote does not verify: %v", err)
	}
	if len(rep.Sessions) != 1 || rep.Sessions[0].Calls != 1 {
		t.Fatalf("report %+v, want one session of one call", rep)
	}
	page, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var ev evidence
	transcript, err := os.ReadFile(filepath.Join(dir, "transcript.json"))
	if err != nil || json.Unmarshal(transcript, &ev) != nil || len(ev.Runs) != 1 || !ev.Verified {
		t.Fatalf("transcript: %v, %+v", err, ev)
	}
	shown := html.UnescapeString(string(page)) // the template escapes "+" and quotes in text
	for _, want := range []string{ev.Runs[0].Record, "print(2+2)", "I ran print(2+2)", "verified"} {
		if !strings.Contains(shown, want) {
			t.Fatalf("the page lacks %q", want)
		}
	}
	// Tampering: one byte of a stored response changes, and the bundle is refused.
	tampered := bytes.Replace(bundle, []byte(`"response":"`), []byte(`"response":"A`), 1)
	if bytes.Equal(tampered, bundle) {
		t.Fatal("the tamper found no response to change")
	}
	if entries, err := attest.ReadBundle(bytes.NewReader(tampered)); err == nil {
		if _, err := attest.VerifyBundle(entries, attest.NewVerifier(pub)); err == nil {
			t.Fatal("a tampered bundle verified")
		}
	}
}

// A model that keeps calling the tool is stopped at the turn budget, and the page says so.
func TestAgentStopsAtItsTurnBudget(t *testing.T) {
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"choices":[{"message":{"role":"assistant","content":"","tool_calls":[{"id":"c","type":"function","function":{"name":"run_code","arguments":"{\"language\":\"javascript\",\"code\":\"1\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`)
	}))
	t.Cleanup(fake.Close)
	svc := rpc.NewSandboxService(&sandboxtest.Sessions{})
	svc.Sessions = rpc.SessionConfig{MaxSessions: 2, Lifetime: time.Minute, IdleTimeout: time.Minute}
	mux := http.NewServeMux()
	path, h := rpc.NewHandler(svc, connect.WithInterceptors(rpc.AuthInterceptor(nil)))
	mux.Handle(path, h)
	daemon := httptest.NewServer(mux)
	t.Cleanup(daemon.Close)
	m := &chat{base: fake.URL, key: "k", model: "fake", http: fake.Client()}
	out := filepath.Join(t.TempDir(), "index.html")
	if err := run(context.Background(), m, "loop", daemon.URL, "", "", 3, out); err != nil {
		t.Fatal(err)
	}
	page, _ := os.ReadFile(out)
	if !strings.Contains(string(page), "budget of 3 turns") {
		t.Fatal("the page does not say the budget ended the agent")
	}
}

// TestWhenAdmittedRetriesOnlyCapacityRefusals: a capacity refusal (admission full, the
// rate limit) is asked again, since no code ran; any other refusal, or an error with no
// not-dispatched mark (execution may have happened), comes back at once.
func TestWhenAdmittedRetriesOnlyCapacityRefusals(t *testing.T) {
	defer func(p time.Duration) { admitPause = p }(admitPause)
	admitPause = time.Millisecond
	capacity := sandbox.NotDispatched(sandbox.RefusalCapacity, fmt.Errorf("rate limit: 30 runs/min per caller"))
	cases := []struct {
		name      string
		errs      []error
		wantCalls int
		wantErr   bool
	}{
		{"admitted after two capacity refusals", []error{capacity, capacity, nil}, 3, false},
		{"capacity every time gives up after the retries", []error{capacity, capacity, capacity, capacity, capacity, capacity, capacity}, admitRetries + 1, true},
		{"a request refusal is not retried", []error{sandbox.NotDispatched(sandbox.RefusalRequest, fmt.Errorf("bad"))}, 1, true},
		{"an unmarked error is not retried", []error{fmt.Errorf("connection reset")}, 1, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			calls := 0
			v, err := whenAdmitted(context.Background(), func() (int, error) {
				err := c.errs[calls]
				calls++
				return calls, err
			})
			if calls != c.wantCalls || (err != nil) != c.wantErr {
				t.Fatalf("calls %d err %v, want %d calls and error %v", calls, err, c.wantCalls, c.wantErr)
			}
			if err == nil && v != calls {
				t.Fatalf("value %d, want the last call's %d", v, calls)
			}
		})
	}
}
