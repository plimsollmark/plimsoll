package warmpool

import (
	"os/exec"
	"testing"
)

func TestCommittedPageMatchesData(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not installed")
	}
	cmd := exec.Command(python, "measurements/warm-pool/report.py", "--check")
	cmd.Dir = "../.."
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("warm-pool report check failed: %v\n%s", err, output)
	}
}
