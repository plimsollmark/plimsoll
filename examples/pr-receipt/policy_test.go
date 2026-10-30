package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// policyFixture is the receipt challenge's project cloned from its bundle, the built
// checker, and the commits the challenge names, so verify.py runs offline on receipts
// that were made under gVisor.
type policyFixture struct {
	dir, sbom, repo string
	commits         map[string]string
	spec            struct {
		Repository  string `json:"repository"`
		PullRequest string `json:"pull_request"`
		Command     string `json:"command"`
		JUnitPath   string `json:"junit_path"`
	}
}

func newPolicyFixture(t *testing.T) *policyFixture {
	t.Helper()
	f := &policyFixture{dir: receiptScratch(t)}
	f.sbom = filepath.Join(f.dir, "sbom")
	if out, err := exec.Command("go", "-C", "../sbom", "build", "-o", f.sbom, ".").CombinedOutput(); err != nil {
		t.Fatalf("build the checker: %v\n%s", err, out)
	}
	for name, v := range map[string]any{"challenge/cases.json": &f.spec, "challenge/commits.json": &f.commits} {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, v); err != nil {
			t.Fatal(err)
		}
	}
	bundle, err := filepath.Abs("challenge/project.bundle")
	if err != nil {
		t.Fatal(err)
	}
	f.repo = filepath.Join(f.dir, "project")
	for _, args := range [][]string{
		{"-c", "advice.detachedHead=false", "clone", "-q", bundle, f.repo},
		{"-C", f.repo, "fetch", "-q", bundle, "+refs/heads/*:refs/remotes/bundle/*"},
	} {
		if out, err := receiptCommand(t, nil, "git", args...); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	return f
}

// policyReport is verify.py's report with the receipt's states.
type policyReport struct {
	verifyReport
	States map[string]struct{ Value, Detail string }
}

// checkNames lists the report's checks in order.
func (r policyReport) checkNames() []string {
	names := make([]string, len(r.Checks))
	for i, c := range r.Checks {
		names[i] = c.Check
	}
	return names
}

// verify runs verify.py on one of the challenge's receipts for the commit it names, checked
// against the operator's key, with extra arguments, and returns the report (or the error a
// crash prints) and the exit code.
func (f *policyFixture) verify(t *testing.T, env []string, receipt, head string, extra ...string) (policyReport, int, string) {
	t.Helper()
	return f.verifyAs(t, env, []string{"--trusted-pub", "challenge/operator.pub"}, receipt, head, extra...)
}

// verifyAs is verify with the signer arguments given: the operator's key, or
// --self-consistent.
func (f *policyFixture) verifyAs(t *testing.T, env, signer []string, receipt, head string, extra ...string) (policyReport, int, string) {
	t.Helper()
	d := filepath.Join("challenge", "receipts", receipt)
	args := append([]string{"-I", "verify.py", "--sbom", f.sbom, "--receipt", filepath.Join(d, "receipt.cdx.json")}, signer...)
	args = append(append(args, "--repo", f.repo, "--repository", f.spec.Repository,
		"--head", f.commits[head], "--pr", f.spec.PullRequest, "--command", f.spec.Command,
		"--junit-path", f.spec.JUnitPath, "--junit", filepath.Join(d, "junit.xml")), extra...)
	out, err := receiptCommand(t, env, "python3", args...)
	code := 0
	if e, ok := err.(*exec.ExitError); ok {
		code = e.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	var r policyReport
	if code != 2 {
		if err := json.Unmarshal(out, &r); err != nil {
			t.Fatalf("not a JSON report (exit %d): %v\n%s", code, err, out)
		}
	}
	return r, code, string(out)
}

// fakeOPA stands in for the opa command: it answers capabilities with a short list that
// includes built-ins the verifier must remove, answers eval as FAKE_OPA_MODE says, and
// logs every call with what it was handed.
const fakeOPA = `#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
entry = {'args': args, 'opa_env': sorted(k for k in os.environ if k.startswith('OPA_'))}
mode = os.environ.get('FAKE_OPA_MODE', 'empty')
query = args[-1]
def answer(value):
    print(json.dumps({'result': [{'expressions': [{'value': value, 'text': query}]}]}))
if args[:2] == ['capabilities', '--current']:
    print(json.dumps({'builtins': [{'name': 'count'}, {'name': 'http.send', 'nondeterministic': True},
                                   {'name': 'opa.runtime', 'nondeterministic': True}, {'name': 'time.now_ns'},
                                   {'name': 'json.match_schema', 'nondeterministic': True}, {'name': 'sprintf'},
                                   {'name': 'crypto.x509.parse_and_verify_certificates'}],
                      'features': ['rego_v1']}))
elif args[:1] == ['eval']:
    entry['capabilities'] = json.load(open(args[args.index('--capabilities') + 1]))
    entry['input'] = json.load(open(args[args.index('--input') + 1]))
    if mode == 'deny':
        answer(['this repository requires the vm tier'])
    elif mode == 'empty':
        answer([])
    elif mode == 'undefined':
        print('{}')
    elif mode == 'nonstring':
        answer([1])
    elif mode == 'error':
        print(json.dumps({'errors': [{'code': 'rego_type_error', 'message': 'undefined ref: input.result.isolaton_rank'}]}))
        sys.exit(2)
else:
    sys.exit(2)
with open(os.environ['FAKE_OPA_LOG'], 'a') as f:
    f.write(json.dumps(entry) + '\n')
`

type opaCall struct {
	Args         []string
	OPAEnv       []string `json:"opa_env"`
	Capabilities struct {
		Builtins []struct{ Name string }
		AllowNet *[]string `json:"allow_net"`
	}
	Input map[string]any
}

func readOPALog(t *testing.T, path string) []opaCall {
	t.Helper()
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	} else if err != nil {
		t.Fatal(err)
	}
	var calls []opaCall
	s := bufio.NewScanner(strings.NewReader(string(b)))
	s.Buffer(nil, 1<<24)
	for s.Scan() {
		var c opaCall
		if err := json.Unmarshal(s.Bytes(), &c); err != nil {
			t.Fatal(err)
		}
		calls = append(calls, c)
	}
	return calls
}

// The policy gate's contract with the opa command, without OPA: what it is handed (the
// offline capabilities, the input schema, the policy files, the query, no OPA_ variable),
// what the input holds (facts from the signed run, nothing a step printed, the shape the
// schema states), and what its answer does: a deny set refuses, an empty one adds nothing,
// and an undefined, malformed or failed evaluation stops the check rather than passing it.
// A policy never runs on a receipt whose signature or head failed, and cannot accept a
// receipt whose tests failed. TestReceiptPolicyGateWithOPA runs the same gate on OPA itself.
func TestReceiptPolicyGate(t *testing.T) {
	f := newPolicyFixture(t)
	opa := filepath.Join(f.dir, "opa")
	if err := os.WriteFile(opa, []byte(fakeOPA), 0o755); err != nil {
		t.Fatal(err)
	}
	policy, err := filepath.Abs("policy/receipt.rego")
	if err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(f.dir, "opa.log")
	sum := sha256.Sum256([]byte(fakeOPA))
	fakeSHA256 := hex.EncodeToString(sum[:])
	runAs := func(t *testing.T, signer []string, mode, receipt, head string, extra ...string) (policyReport, int, string, []opaCall) {
		t.Helper()
		_ = os.Remove(logPath)
		env := []string{"FAKE_OPA_MODE=" + mode, "FAKE_OPA_LOG=" + logPath, "OPA_EVAL_DATA=/nonexistent/extra.rego"}
		r, code, out := f.verifyAs(t, env, signer, receipt, head, append([]string{"--opa", opa, "--opa-sha256", fakeSHA256, "--policy", policy}, extra...)...)
		return r, code, out, readOPALog(t, logPath)
	}
	run := func(t *testing.T, mode, receipt, head string, extra ...string) (policyReport, int, string, []opaCall) {
		t.Helper()
		return runAs(t, []string{"--trusted-pub", "challenge/operator.pub"}, mode, receipt, head, extra...)
	}

	// The gate hashes the binary it is handed before it runs it, and runs a private copy
	// of exactly those bytes: one that is not the pinned build (here the stand-in, without
	// its digest named) is never run, however the harness found it (release review,
	// 2026-10-29: the pin was checked only by opa.sh, a separate step).
	t.Run("an opa binary that is not the pinned build never runs", func(t *testing.T) {
		_ = os.Remove(logPath)
		env := []string{"FAKE_OPA_MODE=empty", "FAKE_OPA_LOG=" + logPath}
		r, code, out := f.verifyAs(t, env, []string{"--trusted-pub", "challenge/operator.pub"}, "honest", "tested", "--opa", opa, "--policy", policy)
		if code != 3 || r.Verified || !strings.Contains(r.Error, "SHA-256") || !strings.Contains(r.Error, "was not run") {
			t.Fatalf("exit %d, error %q; want the binary refused before it runs\n%s", code, r.Error, out)
		}
		if _, err := os.Stat(logPath); !os.IsNotExist(err) {
			t.Fatalf("the stand-in ran (its log: %v)", err)
		}
	})

	t.Run("an honest receipt and a policy that refuses nothing", func(t *testing.T) {
		written := filepath.Join(f.dir, "input.json")
		r, code, out, calls := run(t, "empty", "honest", "tested", "--policy-input", written)
		if code != 0 || !r.Verified {
			t.Fatalf("exit %d: %s", code, out)
		}
		if passed, detail := r.check(t, "policy"); passed == nil || !*passed || !strings.Contains(detail, "refused nothing") {
			t.Fatalf("policy check: %v %q", passed, detail)
		}
		if v := r.States["verdict"].Value; v != "passed" {
			t.Errorf("verdict %q under a policy that refused nothing, want passed", v)
		}
		if len(calls) != 2 || calls[0].Args[0] != "capabilities" || calls[1].Args[0] != "eval" {
			t.Fatalf("opa was called %d times: %+v", len(calls), calls)
		}
		ev := calls[1]
		if len(ev.OPAEnv) != 0 {
			t.Errorf("opa saw %v; an OPA_ variable sets a flag of its own", ev.OPAEnv)
		}
		for _, want := range [][]string{{"--strict-builtin-errors"}, {"--data", policy}, {"--format", "json"}} {
			if i := slices.Index(ev.Args, want[0]); i < 0 || (len(want) == 2 && ev.Args[i+1] != want[1]) {
				t.Errorf("eval args %v lack %v", ev.Args, want)
			}
		}
		if i := slices.Index(ev.Args, "--schema"); i < 0 || !strings.HasSuffix(ev.Args[i+1], "policy/input.schema.json") {
			t.Errorf("eval args %v do not hand OPA the input schema", ev.Args)
		}
		if q := ev.Args[len(ev.Args)-1]; q != "data.plimsoll.receipt.deny" {
			t.Errorf("query %q", q)
		}
		var names []string
		for _, b := range ev.Capabilities.Builtins {
			names = append(names, b.Name)
		}
		if !slices.Equal(names, []string{"count", "sprintf"}) {
			t.Errorf("the policy may call %v; the network, environment, clock, certificate-time and schema-fetching built-ins must be gone", names)
		}
		if ev.Capabilities.AllowNet == nil || len(*ev.Capabilities.AllowNet) != 0 {
			t.Errorf("allow_net is %v, want an empty list (no host)", ev.Capabilities.AllowNet)
		}

		in := ev.Input
		raw, err := os.ReadFile("challenge/receipts/honest/receipt.cdx.json")
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		subject, request, result, record := in["subject"].(map[string]any), in["request"].(map[string]any), in["result"].(map[string]any), in["record"].(map[string]any)
		for what, got := range map[string][2]any{
			"version":            {in["plimsoll_policy_input"], 1.0},
			"receipt digest":     {in["receipt_sha256"], hex.EncodeToString(sum[:])},
			"repository":         {subject["repository"], f.spec.Repository},
			"commit":             {subject["commit"], f.commits["tested"]},
			"pull request":       {subject["pull_request"], f.spec.PullRequest},
			"floor":              {request["minimum_isolation"], "kernel"},
			"floor rank":         {request["minimum_isolation_rank"], 3.0},
			"tier":               {result["isolation"], "kernel"},
			"tier rank":          {result["isolation_rank"], 3.0},
			"outcome":            {result["outcome"], "completed"},
			"provider":           {result["provider"], "docker"},
			"record version":     {record["version"], 4.0},
			"signer":             {in["signer"], "trusted_key"},
			"checks":             {mustJSON(t, in["checks"]), `{"head":true,"junit":true,"result":true,"signature":true,"tests":true}`},
			"steps asked for":    {mustJSON(t, request["steps"]), mustJSON(t, []string{f.spec.Command})},
			"step exit and time": {mustJSON(t, result["steps"].([]any)[0].(map[string]any)["exit_code"]), "0"},
		} {
			if got[0] != got[1] {
				t.Errorf("%s: input has %v, want %v", what, got[0], got[1])
			}
		}
		arts := result["artifacts"].([]any)
		if len(arts) != 1 || arts[0].(map[string]any)["path"] != f.spec.JUnitPath || arts[0].(map[string]any)["bytes"].(float64) <= 0 {
			t.Errorf("artifacts %v, want the JUnit report by digest and size", arts)
		}
		// Nothing the tested code wrote reaches the policy: no output, no file content.
		assertNoKey(t, in, "stdout", "stderr", "content", "outcome_detail")
		// The input is the shape the schema states, and the schema states no field the
		// input never has.
		assertMatchesSchema(t, in, "policy/input.schema.json")
		b, err := os.ReadFile(written)
		if err != nil {
			t.Fatal(err)
		}
		var wrote map[string]any
		if err := json.Unmarshal(b, &wrote); err != nil || mustJSON(t, wrote) != mustJSON(t, in) {
			t.Fatalf("--policy-input wrote another input than the policy read (%v)", err)
		}
	})

	t.Run("a policy refuses an honest receipt", func(t *testing.T) {
		r, code, out, _ := run(t, "deny", "honest", "tested")
		if code != 1 || r.Verified {
			t.Fatalf("exit %d: %s", code, out)
		}
		if passed, detail := r.check(t, "policy"); passed == nil || *passed || detail != "this repository requires the vm tier" {
			t.Fatalf("policy check: %v %q", passed, detail)
		}
		if passed, _ := r.check(t, "result"); passed == nil || !*passed {
			t.Fatal("the result check should still pass; the policy refused")
		}
		// The states agree with the exit code: a policy's refusal is a failed verdict, which
		// names the policy and how many refusals, and never echoes their text.
		if v := r.States["verdict"]; v.Value != "failed" || !strings.Contains(v.Detail, "policy refused it (1 refusal") || strings.Contains(v.Detail, "vm tier") {
			t.Fatalf("verdict %+v, want failed by the policy", v)
		}
		if names := r.checkNames(); names[len(names)-1] != "policy" || !slices.Contains(names, "tests") {
			t.Fatalf("checks %v: the policy check comes last, after the tests check it reads", names)
		}
	})

	t.Run("a policy reads a self-consistent receipt as one", func(t *testing.T) {
		r, code, out, calls := runAs(t, []string{"--self-consistent"}, "empty", "honest", "tested")
		if code != 1 || r.Verified || len(calls) != 2 {
			t.Fatalf("exit %d, %d opa calls: %s", code, len(calls), out)
		}
		if s := calls[1].Input["signer"]; s != "self_consistent" {
			t.Fatalf("the policy read signer %v, want self_consistent: a signature checked against the receipt's own key is not the operator's", s)
		}
		if v := r.States["verdict"].Value; v != "incomplete" {
			t.Fatalf("verdict %q, want incomplete (self-consistent, policy refused nothing)", v)
		}
	})

	t.Run("a policy cannot accept failing tests", func(t *testing.T) {
		r, code, out, calls := run(t, "empty", "failing", "broken")
		if code != 1 || r.Verified {
			t.Fatalf("exit %d: %s", code, out)
		}
		if passed, _ := r.check(t, "policy"); passed == nil || !*passed {
			t.Fatalf("the permissive policy should have run and refused nothing: %s", out)
		}
		in := calls[1].Input
		if c := in["checks"].(map[string]any); c["result"] != false {
			t.Errorf("the policy was not told the result check failed: %v", c)
		}
	})

	for _, c := range []struct{ name, receipt, head, why string }{
		{"another signer", "other-signer", "tested", "an unverified receipt proves nothing"},
		{"an edited result", "altered-result", "tested", "an unverified receipt proves nothing"},
		{"another commit", "honest", "later", "not this pull request's"},
	} {
		t.Run("no policy runs on "+c.name, func(t *testing.T) {
			written := filepath.Join(f.dir, "never.json")
			r, code, out, calls := run(t, "empty", c.receipt, c.head, "--policy-input", written)
			if code != 1 || r.Verified || len(calls) != 0 {
				t.Fatalf("exit %d, %d opa calls: %s", code, len(calls), out)
			}
			if passed, detail := r.check(t, "policy"); passed != nil || !strings.Contains(detail, c.why) {
				t.Fatalf("policy check: %v %q", passed, detail)
			}
			if _, err := os.Stat(written); !os.IsNotExist(err) {
				t.Fatalf("an input was written for a receipt that did not verify: %v", err)
			}
		})
	}

	for _, c := range []struct{ mode, want string }{
		{"undefined", "defines no data.plimsoll.receipt.deny"},
		{"nonstring", "must be a set of strings"},
		{"error", "rego_type_error: undefined ref: input.result.isolaton_rank"},
	} {
		t.Run("a policy that cannot be evaluated stops the check: "+c.mode, func(t *testing.T) {
			r, code, out, _ := run(t, c.mode, "honest", "tested")
			if code != 3 || r.Verified || !strings.Contains(r.Error, c.want) {
				t.Fatalf("exit %d, error %q: %s", code, r.Error, out)
			}
		})
	}

	t.Run("a policy needs opa", func(t *testing.T) {
		_, code, out := f.verify(t, nil, "honest", "tested", "--policy", policy)
		if code != 2 || !strings.Contains(out, "--policy needs --opa") {
			t.Fatalf("exit %d: %s", code, out)
		}
	})
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func assertNoKey(t *testing.T, v any, keys ...string) {
	t.Helper()
	switch x := v.(type) {
	case map[string]any:
		for k, w := range x {
			if slices.Contains(keys, k) {
				t.Errorf("the policy input holds %q", k)
			}
			assertNoKey(t, w, keys...)
		}
	case []any:
		for _, w := range x {
			assertNoKey(t, w, keys...)
		}
	}
}

// assertMatchesSchema checks every object in v has only properties the schema names, with
// the JSON type it states, and every property the schema names but the optional checks.
func assertMatchesSchema(t *testing.T, v any, path string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(b, &schema); err != nil {
		t.Fatal(err)
	}
	optional := []string{"$.checks.junit", "$.checks.test_result", "$.checks.coverage", "$.checks.tests"}
	types := map[string]func(any) bool{
		"object":  func(v any) bool { _, ok := v.(map[string]any); return ok },
		"array":   func(v any) bool { _, ok := v.([]any); return ok },
		"string":  func(v any) bool { _, ok := v.(string); return ok },
		"boolean": func(v any) bool { _, ok := v.(bool); return ok },
		"integer": func(v any) bool { n, ok := v.(float64); return ok && n == float64(int64(n)) },
	}
	var walk func(at string, s map[string]any, v any)
	walk = func(at string, s map[string]any, v any) {
		typ, _ := s["type"].(string)
		if is, ok := types[typ]; !ok || !is(v) {
			t.Errorf("%s: %v is not %s", at, v, typ)
			return
		}
		switch typ {
		case "object":
			props, _ := s["properties"].(map[string]any)
			obj := v.(map[string]any)
			for k := range obj {
				if _, ok := props[k]; !ok {
					t.Errorf("%s.%s is in the input but not the schema", at, k)
				}
			}
			for k, p := range props {
				if w, ok := obj[k]; ok {
					walk(at+"."+k, p.(map[string]any), w)
				} else if !slices.Contains(optional, at+"."+k) {
					t.Errorf("%s.%s is in the schema but not the input", at, k)
				}
			}
		case "array":
			items, _ := s["items"].(map[string]any)
			for _, w := range v.([]any) {
				walk(at+"[]", items, w)
			}
		}
	}
	walk("$", schema, v)
}

// The gate on OPA itself, the release pinned in policy/opa.version: the example policy's
// own tests, the honest receipt accepted, the failing one refused by the result check and
// the policy, and every way a policy can be wrong stopping the check (a misspelled field,
// a forbidden built-in, the wrong package, a deny set that is not strings, a built-in
// that errors). make policy-suite fetches OPA, checks its SHA-256 and runs this; without
// PLIMSOLL_OPA it skips, and the suite fails on a skip.
func TestReceiptPolicyGateWithOPA(t *testing.T) {
	opa := os.Getenv("PLIMSOLL_OPA")
	if opa == "" {
		t.Skip("set PLIMSOLL_OPA to the pinned opa binary (make policy-suite)")
	}
	if out, err := exec.Command(opa, "test", "-v", "policy/receipt.rego", "policy/receipt_test.rego").CombinedOutput(); err != nil {
		t.Fatalf("opa test: %v\n%s", err, out)
	}
	f := newPolicyFixture(t)
	example, err := filepath.Abs("policy/receipt.rego")
	if err != nil {
		t.Fatal(err)
	}
	r, code, out := f.verify(t, nil, "honest", "tested", "--opa", opa, "--policy", example)
	if code != 0 || !r.Verified {
		t.Fatalf("the honest receipt under the example policy: exit %d\n%s", code, out)
	}
	r, code, out = f.verify(t, nil, "failing", "broken", "--opa", opa, "--policy", example)
	if passed, detail := r.check(t, "policy"); code != 1 || passed == nil || *passed || !strings.Contains(detail, "exited") {
		t.Fatalf("the failing receipt under the example policy: exit %d, %v %q\n%s", code, passed, detail, out)
	}

	write := func(name, body string) string {
		p := filepath.Join(f.dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	r, code, out = f.verify(t, nil, "honest", "tested", "--opa", opa, "--policy",
		write("vm.rego", "package plimsoll.receipt\n\ndeny contains \"this repository requires the vm tier\" if input.result.isolation_rank < 4\n"))
	if passed, detail := r.check(t, "policy"); code != 1 || passed == nil || *passed || detail != "this repository requires the vm tier" {
		t.Fatalf("a vm-only policy on a kernel run: exit %d, %v %q\n%s", code, passed, detail, out)
	}
	r, code, out = f.verify(t, nil, "honest", "tested", "--opa", opa, "--policy",
		write("none.rego", "package plimsoll.receipt\n\ndeny contains \"never\" if input.result.isolation_rank > 99\n"))
	if code != 0 || !r.Verified {
		t.Fatalf("a deny set no rule adds to must be defined and empty: exit %d\n%s", code, out)
	}
	for _, c := range []struct{ name, body, want string }{
		{"a misspelled field", "deny contains \"x\" if input.result.isolaton_rank < 3", "undefined ref"},
		{"a network call", "deny contains \"x\" if http.send({\"method\": \"get\", \"url\": \"https://example.com\"}).status_code == 200", "http.send"},
		{"the environment", "deny contains \"x\" if opa.runtime().env.HOME != \"\"", "opa.runtime"},
		{"the clock", "deny contains \"x\" if time.now_ns() > 0", "time.now_ns"},
		{"a remote schema", "deny contains \"x\" if json.match_schema({}, {\"$ref\": \"https://example.com/s.json\"})[0]", "json.match_schema"},
		{"a certificate checked against today", "deny contains \"x\" if crypto.x509.parse_and_verify_certificates(\"\")[0]", "crypto.x509.parse_and_verify_certificates"},
		{"a deny set of numbers", "deny contains 1 if true", "set of strings"},
		{"a built-in that errors", "deny contains \"x\" if to_number(input.result.isolation) > 0", "to_number"},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := write(strings.ReplaceAll(c.name, " ", "-")+".rego", "package plimsoll.receipt\n\n"+c.body+"\n")
			r, code, out := f.verify(t, nil, "honest", "tested", "--opa", opa, "--policy", p)
			if code != 3 || !strings.Contains(r.Error, c.want) {
				t.Fatalf("exit %d, error %q\n%s", code, r.Error, out)
			}
		})
	}
	r, code, out = f.verify(t, nil, "honest", "tested", "--opa", opa, "--policy",
		write("signer.rego", "package plimsoll.receipt\n\ndeny contains \"signed with the receipt's own key only\" if input.signer != \"trusted_key\"\n"))
	if code != 0 || !r.Verified {
		t.Fatalf("a policy reading the signer, on the operator's key: exit %d\n%s", code, out)
	}
	r, code, out = f.verify(t, nil, "honest", "tested", "--opa", opa, "--policy", write("other.rego", "package other\n\ndeny contains \"x\" if true\n"))
	if code != 3 || !strings.Contains(r.Error, "defines no") {
		t.Fatalf("a policy in another package: exit %d, error %q\n%s", code, r.Error, out)
	}
}
