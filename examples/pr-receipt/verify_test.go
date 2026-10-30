package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type verifyReport struct {
	Verified bool
	Error    string
	Checks   []struct {
		Check  string
		Passed *bool
		Detail string
	}
}

func (r verifyReport) check(t *testing.T, name string) (*bool, string) {
	t.Helper()
	for _, c := range r.Checks {
		if c.Check == name {
			return c.Passed, c.Detail
		}
	}
	t.Fatalf("no %s check in %+v", name, r)
	return nil, ""
}

// The verifier on the published receipt, offline: the operator's key passes, another key
// or an edited receipt is refused before anything inside it is believed, the receipt does
// not pass for a commit it did not test, the JUnit file is checked byte for byte against
// the signed result, and pass or fail comes from the signed exit codes. That it accepts a
// receipt for the commit it tested is proven by TestReceiptScriptEndToEnd under gVisor.
func TestReceiptVerifierOnThePublishedReceipt(t *testing.T) {
	dir := receiptScratch(t)
	sbom := filepath.Join(dir, "sbom")
	if out, err := exec.Command("go", "-C", "../sbom", "build", "-o", sbom, ".").CombinedOutput(); err != nil {
		t.Fatalf("build the checker: %v\n%s", err, out)
	}
	boms, err := filepath.Glob("evidence/run-*.cdx.json")
	if err != nil || len(boms) != 1 {
		t.Fatalf("want one published receipt, found %v (%v)", boms, err)
	}
	receipt, err := filepath.Abs(boms[0])
	if err != nil {
		t.Fatal(err)
	}
	operator, err := filepath.Abs("evidence/harness.pub")
	if err != nil {
		t.Fatal(err)
	}
	project, commit := receiptFixture(t, dir)
	verify := func(receipt, pub string, extra ...string) (verifyReport, int) {
		t.Helper()
		args := append([]string{"-I", "verify.py", "--sbom", sbom, "--receipt", receipt, "--trusted-pub", pub,
			"--repo", project, "--repository", "example/pr-receipt-fixture", "--head", commit, "--pr", "0", "--command", "npm test"}, extra...)
		out, err := receiptCommand(t, nil, "python3", args...)
		code := 0
		if e, ok := err.(*exec.ExitError); ok {
			code = e.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		var r verifyReport
		if err := json.Unmarshal(out, &r); err != nil {
			t.Fatalf("not a JSON report (exit %d): %v\n%s", code, err, out)
		}
		return r, code
	}

	// The operator's key: the signature passes, and the run passed, but this fixture is a
	// commit of its own, so the receipt for the published commit does not count for it.
	r, code := verify(receipt, operator)
	if code != 1 || r.Verified {
		t.Fatalf("a receipt for another commit was accepted (exit %d): %+v", code, r)
	}
	if ok, detail := r.check(t, "signature"); ok == nil || !*ok {
		t.Errorf("signature under the operator's key: %v %s", ok, detail)
	}
	if ok, detail := r.check(t, "head"); ok == nil || *ok || !strings.Contains(detail, "tested commit '627534fc71de") || !strings.Contains(detail, commit) {
		t.Errorf("head: %v %s", ok, detail)
	}
	if ok, detail := r.check(t, "result"); ok == nil || !*ok || !strings.Contains(detail, "kernel") {
		t.Errorf("result of a passing run: %v %s", ok, detail)
	}

	// junit.xml as receipt.sh writes it passes; one byte changed does not.
	steps := filepath.Join(dir, "steps")
	if err := os.Mkdir(steps, 0o755); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(steps, filepath.Base(receipt)), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := receiptCommand(t, nil, "python3", "-I", "junit.py", steps); err != nil {
		t.Fatalf("junit.py: %v\n%s", err, out)
	}
	report := filepath.Join(steps, "junit.xml")
	r, _ = verify(receipt, operator, "--junit", report)
	if ok, detail := r.check(t, "junit"); ok == nil || !*ok {
		t.Errorf("junit.xml as built: %v %s", ok, detail)
	}
	built, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	edited := filepath.Join(dir, "edited-junit.xml")
	if err := os.WriteFile(edited, []byte(strings.Replace(string(built), `failures="0"`, `failures="1"`, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	r, _ = verify(receipt, operator, "--junit", edited)
	if ok, detail := r.check(t, "junit"); ok == nil || *ok {
		t.Errorf("an edited junit.xml: %v %s", ok, detail)
	}
	// The receipt asked for no JUnit file, so naming one is a different request.
	r, _ = verify(receipt, operator, "--junit-path", "reports/junit.xml")
	if ok, detail := r.check(t, "head"); ok == nil || *ok || !strings.Contains(detail, "JUnit path") {
		t.Errorf("a JUnit path the receipt was not made with: %v %s", ok, detail)
	}

	// The receipt asked for no test report, so it has no tests check; a minimum given anyway
	// cannot be met, since there is nothing to count.
	for _, c := range r.Checks {
		if c.Check == "tests" {
			t.Errorf("a receipt with no test report has a tests check: %+v", c)
		}
	}
	r, _ = verify(receipt, operator, "--min-tests", "1")
	if ok, detail := r.check(t, "tests"); ok == nil || *ok || !strings.Contains(detail, "no test report was requested") || !strings.Contains(detail, "at least 1 test that ran") {
		t.Errorf("a minimum with no test report: %v %s", ok, detail)
	}
	for _, bad := range []string{"0", "01", "-1", "two"} {
		out, err := receiptCommand(t, nil, "python3", "-I", "verify.py", "--sbom", sbom, "--receipt", receipt, "--trusted-pub", operator,
			"--repo", project, "--repository", "example/pr-receipt-fixture", "--head", commit, "--pr", "0", "--command", "npm test", "--min-tests", bad)
		if e, ok := err.(*exec.ExitError); !ok || e.ExitCode() != 2 || !strings.Contains(string(out), "--min-tests") {
			t.Errorf("--min-tests %s: %v\n%s", bad, err, out)
		}
	}

	// The receipt was made with no base, so a base names a different subject.
	r, _ = verify(receipt, operator, "--base", commit)
	if ok, detail := r.check(t, "head"); ok == nil || *ok || !strings.Contains(detail, "names base") {
		t.Errorf("a base the receipt was not made with: %v %s", ok, detail)
	}

	// Another key, and an edited receipt: refused, and nothing inside is believed.
	keys := filepath.Join(dir, "keys")
	if err := os.Mkdir(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	if out, err := receiptCommand(t, nil, "go", "run", "../../cmd/plimsoll-attest", "keygen", "-out", filepath.Join(keys, "other")); err != nil {
		t.Fatalf("keygen: %v\n%s", err, out)
	}
	// The edit is the only change: one exit code inside the attached exchange, the rest of
	// the receipt byte for byte as published.
	var bom map[string]any
	if err := json.Unmarshal(raw, &bom); err != nil {
		t.Fatal(err)
	}
	var tampered []byte
	data := bom["declarations"].(map[string]any)["evidence"].([]any)[0].(map[string]any)["data"].([]any)
	for _, d := range data {
		d := d.(map[string]any)
		if d["name"] != "exchange.json" {
			continue
		}
		old := d["contents"].(map[string]any)["attachment"].(map[string]any)["content"].(string)
		x, err := base64.StdEncoding.DecodeString(old)
		if err != nil {
			t.Fatal(err)
		}
		changed := strings.Replace(string(x), `"exit_code":0`, `"exit_code":1`, 1)
		if changed == string(x) || strings.Count(string(raw), old) != 1 {
			t.Fatalf("the exit code edit did not apply (or the attachment is not unique):\n%.300s", x)
		}
		tampered = []byte(strings.Replace(string(raw), old, base64.StdEncoding.EncodeToString([]byte(changed)), 1))
	}
	edit := filepath.Join(dir, "edited.cdx.json")
	if err := os.WriteFile(edit, tampered, 0o644); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct{ receipt, pub, want string }{
		"another key":    {receipt, filepath.Join(keys, "other.pub"), "signed with a key other than the operator's"},
		"edited receipt": {edit, operator, ""},
	} {
		r, code := verify(c.receipt, c.pub, "--min-tests", "2")
		ok, detail := r.check(t, "signature")
		if code != 1 || r.Verified || ok == nil || *ok || !strings.Contains(detail, c.want) {
			t.Errorf("%s: exit %d, signature %v %q", name, code, ok, detail)
		}
		for _, later := range []string{"head", "result", "tests"} {
			if ok, detail := r.check(t, later); ok != nil || !strings.Contains(detail, "not checked") {
				t.Errorf("%s: %s was judged on an unverified receipt: %v %s", name, later, ok, detail)
			}
		}
	}

	// An empty key file cannot stand for the operator: the check could not run (exit 3),
	// never a pass. A malformed number is a usage error (exit 2).
	empty := filepath.Join(dir, "empty.pub")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if r, code := verify(receipt, empty); code != 3 || r.Verified {
		t.Errorf("an empty operator key: exit %d, %+v", code, r)
	}
	out, err := receiptCommand(t, nil, "python3", "-I", "verify.py", "--sbom", sbom, "--receipt", receipt, "--trusted-pub", operator,
		"--repo", project, "--repository", "example/pr-receipt-fixture", "--head", commit, "--pr", "042", "--command", "npm test")
	if e, ok := err.(*exec.ExitError); !ok || e.ExitCode() != 2 {
		t.Errorf("--pr 042: %v\n%s", err, out)
	}
}
