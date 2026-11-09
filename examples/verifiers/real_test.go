package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// runOutput writes what run_attempt.py --model leaves in its directory, for a made-up run of
// one solved attempt and one the relay stopped, and returns the directory. edit changes the
// summary before it is written.
func runOutput(t *testing.T, edit func(s map[string]any)) string {
	t.Helper()
	dir := t.TempDir()
	const calls = 6
	if err := os.WriteFile(filepath.Join(dir, "records.jsonl"), logOf(t, calls, "kernel", true), 0o644); err != nil {
		t.Fatal(err)
	}
	s := map[string]any{
		"vf_eval_exit": 0, "timed_out": false, "floor": "kernel",
		"record_log": map[string]any{"sessions": 1, "records": calls, "closed": 1, "tiers": map[string]int{"kernel": calls}, "incomplete": []any{}},
		"rollouts": []map[string]any{
			{"task_idx": 0, "reward": 1.0, "rewards": map[string]float64{"solved": 1}, "metrics": map[string]float64{"source_uuid_fraction": 1},
				"stop_condition": "agent_completed", "errors": []any{}, "input_tokens": 100000, "cached_input_tokens": 60000, "output_tokens": 10000, "total_tokens": 110000,
				"cost_usd": 0.0066, "model_turns": 12, "tool_results": 11, "answer_first_role": "tool", "relay_refused": nil, "last_finish_reason": "stop"},
			{"task_idx": 1, "reward": nil, "rewards": map[string]float64{}, "metrics": map[string]float64{},
				"stop_condition": "has_error", "errors": []any{"refused"}, "input_tokens": 200000, "cached_input_tokens": 150000, "output_tokens": 20000, "total_tokens": 220000,
				"cost_usd": 0.0123, "model_turns": 30, "tool_results": 29, "answer_first_role": nil, "relay_refused": "attempt_budget", "last_finish_reason": "tool_calls"},
			{"task_idx": 2, "reward": 0.0, "rewards": map[string]float64{"solved": 0}, "metrics": map[string]float64{"source_uuid_fraction": 0},
				"stop_condition": "agent_completed", "errors": []any{}, "input_tokens": 50000, "cached_input_tokens": 20000, "output_tokens": 5000, "total_tokens": 55000,
				"cost_usd": 0.0036, "model_turns": 9, "tool_results": 8, "answer_first_role": nil, "relay_refused": nil, "last_finish_reason": "length"},
		},
		"real_model": map[string]any{
			"dry_run": false, "model": "vendor/some-model", "upstream_host": "api.example.com", "preset": "easy", "tasks": 3, "concurrency": 2,
			"max_total_tokens_per_attempt": 400000, "attempt_token_budget": 32000001, "run_token_budget": 32000001, "max_call_output_tokens": 16384, "cost_cap_usd": 0.96,
			"price_in_per_million": 0.06, "price_cached_per_million": 0.03, "price_out_per_million": 0.24,
			"relay": map[string]any{"prompt_tokens": 350000, "cached_prompt_tokens": 230000, "completion_tokens": 35000, "total_tokens": 385000, "charged_without_usage": 0,
				"tokens_counted": 385000, "token_budget": 32000001, "usd_spent": 0.0225, "usd_budget": 0.96, "forwarded": 51, "refused": 1, "upstream_errors": 0, "usage_missing": 0,
				"budget_reached": false, "answer_key_seen": false},
			"cost_usd": 0.0225, "costs_match_relay": true, "trace_total_tokens": 385000, "traces_match_relay": true,
			"answer_key": map[string]any{"refused_requests": false, "first_role_system_or_user": []any{}},
		},
		"key_check": map[string]any{"files_with_the_key": []any{}, "children_with_the_key": []any{}, "children_checked": 2},
	}
	if edit != nil {
		edit(s)
	}
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "summary.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func realOf(s map[string]any) map[string]any { return s["real_model"].(map[string]any) }

// The section is drawn from the results file alone, says what the score does not mean, and
// sets a stopped attempt apart.
func TestRealModelSectionRendersFromTheResultsFile(t *testing.T) {
	ev, err := loadEvidence(published)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := gatherReal(runOutput(t, nil), dir, "/no/such/repo"); err != nil {
		t.Fatal(err)
	}
	real, err := loadReal(dir)
	if err != nil || real == nil {
		t.Fatalf("results %v, %v", real, err)
	}
	if err := verifyReal(dir, real); err != nil {
		t.Fatal(err)
	}
	if real.Date == "" || real.Log.File != realLogFile || real.Log.Go.Records != 6 {
		t.Errorf("results %+v", real)
	}
	withSection, err := render(ev, real)
	if err != nil {
		t.Fatal(err)
	}
	page := string(withSection)
	for _, want := range []string{
		`id="real-model"`,
		"vendor/some-model",
		"is one small task, so a good or bad score here does not say the model is good or bad at coding",
		"<b>1 of 2 graded</b>",
		"1 of the 3 attempts was never graded: 1 stopped by a token budget before the grader ran",
		"$0.0225",
		"350,000 input tokens",
		"230,000 of them cached",
		"stopped by the attempt&#39;s token budget: says nothing about the model",
		"ended at the per-call output cap of 16,384 tokens, with no answer",
		"none</b> means the grader never ran",
		"every file under the run's output directory",
		"dollar budget",
		"It takes the model's answer and never its opinion of that answer",
		"not a spending limit",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the section does not say %q", want)
		}
	}
	for _, gone := range []string{"which includes any call the traces do not", "The budget at the output price", "It never held the API key", "so it never held the API key"} {
		if strings.Contains(page, gone) {
			t.Errorf("the section still says %q", gone)
		}
	}
	if strings.Contains(page, "A run with a real model is the next step") {
		t.Error("the page still says a real model is the next step")
	}
	if regexp.MustCompile("[–—]| -- ").MatchString(page) {
		t.Error("the section has a dash used as punctuation")
	}
	ids := map[string]bool{}
	for _, m := range regexp.MustCompile(`\sid="([^"]+)"`).FindAllStringSubmatch(page, -1) {
		if ids[m[1]] {
			t.Errorf("id %q appears twice", m[1])
		}
		ids[m[1]] = true
	}
	without, err := render(ev, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(without, []byte(`id="real-model"`)) {
		t.Error("the section renders with no results file")
	}
}

// What must not reach the page does not: a dry run's script, a leaked key, a leaked answer.
func TestGatherRealRefuses(t *testing.T) {
	for name, edit := range map[string]func(s map[string]any){
		"a dry run":                   func(s map[string]any) { realOf(s)["dry_run"] = true },
		"a scripted run":              func(s map[string]any) { delete(s, "real_model") },
		"no key check":                func(s map[string]any) { delete(s, "key_check") },
		"the key in a file":           func(s map[string]any) { s["key_check"].(map[string]any)["files_with_the_key"] = []any{"vf-eval.log"} },
		"the key in a child":          func(s map[string]any) { s["key_check"].(map[string]any)["children_with_the_key"] = []any{"123"} },
		"an answer the relay refused": func(s map[string]any) { realOf(s)["answer_key"].(map[string]any)["refused_requests"] = true },
		"an answer in a user message": func(s map[string]any) {
			realOf(s)["answer_key"].(map[string]any)["first_role_system_or_user"] = []any{"user"}
		},
		"the checkers disagreeing":      func(s map[string]any) { s["record_log"].(map[string]any)["records"] = 5 },
		"a log the Python check failed": func(s map[string]any) { s["record_log"] = map[string]any{"error": "ChainError: gap"} },
		"a loopback upstream":           func(s map[string]any) { realOf(s)["upstream_host"] = "loopback" },
		"a cost that is not the tokens": func(s map[string]any) { realOf(s)["cost_usd"] = 0.001 },
		"an attempt's wrong cost":       func(s map[string]any) { s["rollouts"].([]map[string]any)[0]["cost_usd"] = 0.0001 },
		"an attempt priced without its cached tokens": func(s map[string]any) {
			// What the first real run reported: input without the cache reads, so the costs fall short of the run's.
			row := s["rollouts"].([]map[string]any)[0]
			row["input_tokens"], row["cached_input_tokens"], row["cost_usd"] = 40000, 0, 0.0048
		},
		"attempt costs that do not add up to the run's": func(s map[string]any) { s["rollouts"].([]map[string]any)[0]["cost_usd"] = 0.0066 + 0.0001 },
		"traces that do not match the relay":            func(s map[string]any) { realOf(s)["traces_match_relay"] = false },
		"a cap above the approved 96 cents":             func(s map[string]any) { realOf(s)["cost_cap_usd"] = 0.97 },
		"a run that spent past its cap": func(s map[string]any) {
			relay := realOf(s)["relay"].(map[string]any)
			relay["usd_spent"], realOf(s)["cost_cap_usd"] = 0.0225, 0.01
		},
		"tokens past the budget": func(s map[string]any) {
			relay := realOf(s)["relay"].(map[string]any)
			relay["tokens_counted"], relay["token_budget"] = 5000000, 4000000
		},
		"no attempts": func(s map[string]any) { s["rollouts"] = []map[string]any{} },
		"no tool result in any attempt": func(s map[string]any) {
			for _, row := range s["rollouts"].([]map[string]any) {
				row["tool_results"] = 0
			}
		},
	} {
		if err := gatherReal(runOutput(t, edit), t.TempDir(), "/no/such/repo"); err == nil {
			t.Errorf("%s was gathered", name)
		}
	}
}

// The driver checks a task package against the same pins as this program. The driver is
// Python, so the list is written twice; this holds the two together.
func TestDriverPinsTheSameTaskFiles(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "clients", "python", "frameworks", "verifiers", "attempt", "run_attempt.py"))
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]string{}
	for _, m := range regexp.MustCompile(`(?m)^    "([^"]+)": "([0-9a-f]{64})",$`).FindAllSubmatch(raw, -1) {
		found[string(m[1])] = string(m[2])
	}
	if !reflect.DeepEqual(found, primeFiles) {
		t.Errorf("run_attempt.py pins %v; run.go pins %v", found, primeFiles)
	}
}

// -verify rechecks the results file: a changed record log, or a changed number, fails.
func TestVerifyRealRefusesAChange(t *testing.T) {
	dir := t.TempDir()
	if err := gatherReal(runOutput(t, nil), dir, "/no/such/repo"); err != nil {
		t.Fatal(err)
	}
	real, err := loadReal(dir)
	if err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(dir, filepath.FromSlash(realLogFile))
	raw, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	i := bytes.Index(raw, []byte(`"result_sha256":"`)) + len(`"result_sha256":"`)
	changed := append([]byte{}, raw...)
	if changed[i] == 'a' {
		changed[i] = 'b'
	} else {
		changed[i] = 'a'
	}
	if err := os.WriteFile(log, changed, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyReal(dir, real); err == nil {
		t.Error("a record log with one byte changed rechecked")
	}
	if err := os.WriteFile(log, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	cheaper := *real
	cheaper.CostUSD /= 2
	if err := verifyReal(dir, &cheaper); err == nil {
		t.Error("a halved cost verified")
	}
}
