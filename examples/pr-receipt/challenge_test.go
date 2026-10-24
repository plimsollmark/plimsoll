package main

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The receipt challenge's reference answers: the honest receipt is accepted and every
// forged or mismatched one is refused at the check cases.json names. No sandbox runs; the
// receipts were made under gVisor by challenge/generate.sh.
func TestReceiptChallengeCasesComeOutAsStated(t *testing.T) {
	dir := receiptScratch(t)
	sbom := filepath.Join(dir, "sbom")
	if out, err := exec.Command("go", "-C", "../sbom", "build", "-o", sbom, ".").CombinedOutput(); err != nil {
		t.Fatalf("build the checker: %v\n%s", err, out)
	}
	out, err := receiptCommand(t, nil, "python3", "-I", "challenge/check.py", "--sbom", sbom)
	if err != nil || !strings.Contains(string(out), "every case as expected") {
		t.Fatalf("check.py: %v\n%s", err, out)
	}
	for _, s := range []string{"honest", "refuse at signature", "refuse at result", "refuse at junit", "refuse at head"} {
		if !strings.Contains(string(out), s) {
			t.Errorf("check.py printed no %q:\n%s", s, out)
		}
	}
}
