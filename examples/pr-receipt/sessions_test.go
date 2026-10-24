package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// With SESSION_TRAILER, the subject lists the coding-agent sessions that trailer names on the
// pull request's commits. With a base, every commit after it counts and the base is named;
// with none, the head alone. Without SESSION_TRAILER no trailer is read.
func TestReceiptAgentSessionsInTheSubject(t *testing.T) {
	dir := receiptScratch(t)
	project := filepath.Join(dir, "project")
	if out, err := receiptCommand(t, nil, "git", "init", "--quiet", project); err != nil {
		t.Fatalf("%s: %v", out, err)
	}
	commit := func(name, message string) string {
		t.Helper()
		if err := os.WriteFile(filepath.Join(project, name), []byte(name+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		for _, args := range [][]string{{"add", name},
			{"-c", "user.name=Receipt Test", "-c", "user.email=receipt@example.invalid", "-c", "commit.gpgsign=false", "commit", "-q", "-m", message},
		} {
			if out, err := receiptCommand(t, nil, "git", append([]string{"-C", project}, args...)...); err != nil {
				t.Fatalf("git %v: %s: %v", args, out, err)
			}
		}
		out, err := receiptCommand(t, nil, "git", "-C", project, "rev-parse", "HEAD")
		if err != nil {
			t.Fatalf("%s: %v", out, err)
		}
		return strings.TrimSpace(string(out))
	}
	const a, b = "aaaa1111-0000-0000-0000-000000000000", "d13fc871-d294-4c08-b1d4-e7bdcaef6969"
	base := commit("base.mjs", "the base")
	commit("one.mjs", "one\n\nAgent-Session: "+b)
	commit("two.mjs", "two\n\nAgent-Session: "+a+", "+b)
	head := commit("three.mjs", "three, by hand")

	subject := func(name string, extra ...string) (map[string]any, string, error) {
		t.Helper()
		out := filepath.Join(dir, name)
		env := append([]string{"TEST_COMMAND=npm test", "PR_NUMBER=5", "PR_REPOSITORY=example/project"}, extra...)
		log, err := receiptCommand(t, env, "python3", "-I", "prepare.py", project, out)
		if err != nil {
			return nil, string(log), err
		}
		raw, err := os.ReadFile(filepath.Join(out, "request.json"))
		if err != nil {
			t.Fatal(err)
		}
		var q struct {
			Project struct {
				Files []struct{ Path, Content string }
			}
		}
		if err := json.Unmarshal(raw, &q); err != nil {
			t.Fatal(err)
		}
		for _, f := range q.Project.Files {
			if f.Path == ".pr-receipt/subject.json" {
				var s map[string]any
				if err := json.Unmarshal([]byte(f.Content), &s); err != nil {
					t.Fatal(err)
				}
				return s, f.Content, nil
			}
		}
		t.Fatalf("%s: no subject file", name)
		return nil, "", nil
	}

	// No base: the head commit alone, which carries no trailer, so the subject is the
	// three fields it always was.
	s, content, err := subject("head-only")
	if err != nil {
		t.Fatalf("head only: %v: %s", err, content)
	}
	if _, listed := s["agent_sessions"]; listed || s["base"] != nil || len(s) != 3 {
		t.Errorf("head only: %s", content)
	}
	// With the base but no trailer key: the base is named and no trailer is read.
	s, content, err = subject("base-no-key", "PR_BASE_SHA="+base)
	if _, listed := s["agent_sessions"]; err != nil || listed || s["base"] != base {
		t.Errorf("base, no trailer key: %v: %s", err, content)
	}
	// With the base and the key: every commit after the base, each session once, sorted.
	s, content, err = subject("with-base", "PR_BASE_SHA="+base, "SESSION_TRAILER=Agent-Session")
	if err != nil {
		t.Fatalf("with base: %v: %s", err, content)
	}
	if !reflect.DeepEqual(s["agent_sessions"], []any{a, b}) || s["base"] != base || s["commit"] != head {
		t.Errorf("with base: %s", content)
	}
	// A trailer holding something other than session IDs, and a base outside the history,
	// are refused rather than half read.
	commit("four.mjs", "four\n\nAgent-Session: not/an id")
	if _, log, err := subject("bad-key", "SESSION_TRAILER=Agent Session"); err == nil || !strings.Contains(log, "SESSION_TRAILER must be") {
		t.Errorf("a trailer key with a space: %v: %s", err, log)
	}
	if _, log, err := subject("bad-trailer", "PR_BASE_SHA="+base, "SESSION_TRAILER=Agent-Session"); err == nil || !strings.Contains(log, "other than session IDs") {
		t.Errorf("a malformed trailer: %v: %s", err, log)
	}
	if _, log, err := subject("bad-base", "PR_BASE_SHA="+strings.Repeat("ab", 20)); err == nil || !strings.Contains(log, "PR_BASE_SHA must be a commit") {
		t.Errorf("a base outside the history: %v: %s", err, log)
	}
}
