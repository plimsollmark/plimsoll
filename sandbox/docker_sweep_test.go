package sandbox_test

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/sandbox/internal/sessionkit"
)

// sweepIn runs script (sh, with $SWEEP holding the sweep's program) in a throwaway
// container of the project image. The sweep kills every process but its ancestors,
// so it can only be tried inside a container of its own.
func sweepIn(t *testing.T, script string, docker ...string) string {
	t.Helper()
	d := sessionDocker(t) // the same skip-or-require rules as the session tests
	args := append([]string{"run", "--rm", "--network", "none", "--user", "61000:61000" /* the provider's default guest uid */, "-e", "SWEEP=" + sessionkit.SweepScript}, docker...)
	args = append(args, "--entrypoint", "sh", d.ProjectImage, "-c", script)
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	return strings.TrimSpace(string(out))
}

// A disk budget of 0 means no bound, so the sweep measures nothing: past the entry
// bound, or at a directory it cannot read, it used to end the session anyway.
func TestDockerSweepWithNoBudgetMeasuresNothing(t *testing.T) {
	got := sweepIn(t, `node -e 'const fs = require("fs"); fs.mkdirSync("/tmp/d"); for (let i = 0; i <= 200000; i++) fs.writeFileSync("/tmp/d/" + i, "")'
node -e "$SWEEP" 0 200000 walk /tmp >/dev/null; echo "none=$?"
node -e "$SWEEP" 1073741824 200000 walk /tmp >/dev/null; echo "budget=$?"`)
	if got != "none=0\nbudget=10" {
		t.Fatalf("got %q; want no verdict on files without a budget (none=0), and the entry bound with one (budget=10)", got)
	}
}

// Measured by statfs, a session's tmpfs counts a file deleted while a process still
// holds it open, which a walk of the directory cannot see.
func TestDockerSweepStatfsCountsAnOpenDeletedFile(t *testing.T) {
	got := sweepIn(t, `node -e 'require("fs").writeFileSync("/m/big", Buffer.alloc(16 << 20))'
exec 3</m/big; rm /m/big
node -e "$SWEEP" 8388608 200000 statfs /m >/dev/null; echo "statfs=$?"
node -e "$SWEEP" 8388608 200000 walk /m >/dev/null; echo "walk=$?"`, "--tmpfs", "/m:size=32m")
	if got != "statfs=10\nwalk=0" {
		t.Fatalf("got %q; want the deleted 16 MiB over an 8 MiB budget by statfs (10) and invisible to the walk (0)", got)
	}
}
