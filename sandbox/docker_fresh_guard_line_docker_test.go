package sandbox

import (
	"context"
	"encoding/base64"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// markerLostSh stands in, in a throwaway image, for a fresh run whose code won the race for its
// start marker: it is the image's /bin/sh, and when it is started as plimsoll's start script
// (sh -c SCRIPT sh MARKER ...), it hands the script an empty marker, which the script then does not
// write (startScript), and starts everything else as given. Every other use of /bin/sh is
// busybox's own shell. So the run's code starts as always, behind the guard, and the container's
// standard error never holds the marker: what a reader of that stream ahead of docker would leave.
const markerLostSh = `#!/bin/busybox sh
if [ "$1" = -c ] && [ "$#" -ge 4 ] && [ "$3" = sh ]; then
  case "$4" in plimsoll-started:*) s=$2; shift 4; exec /bin/busybox sh -c "$s" sh "" "$@";; esac
fi
exec /bin/busybox sh "$@"
`

// stderrReopen is snippet code that first does what a winner of the race does: it opens its own
// standard error for reading through /proc/self/fd/2 and reads what it can, without waiting.
const stderrReopen = `const fs = require("node:fs");
try { const fd = fs.openSync("/proc/self/fd/2", fs.constants.O_RDONLY | fs.constants.O_NONBLOCK); try { fs.readSync(fd, Buffer.alloc(4096)); } catch {} fs.closeSync(fd); } catch {}
`

// TestDockerFreshRunGuardLineIsNeverMarked: a fresh run whose own code writes the guest guard's
// refusal line as the last line of its standard error and exits with that step's code is never
// answered as not dispatched, under the runtime the suite runs (SANDBOX_DOCKER_RUNTIME; the
// docker suite runs it under runc and gVisor). Two images:
//
//   - the snippet image as built: the code reopens its standard error first, which under runc it
//     can (measured 2026-11-20: 40 of 40 got the descriptor and read nothing, docker having
//     taken the marker), so the marker stays and the run is the code's own exit 123, a result;
//   - the same image with markerLostSh as /bin/sh, the case where the marker did not reach
//     plimsoll: the answer is an error, unmarked, saying whether the run's code ran is not known.
//     Before the rule (unstartedRun) this was marked not dispatched, reason environment.
//
// A project's step that writes the same line to its own standard error, and tries process 1's,
// and exits 123, is the runner's authenticated report in both images: a result, never marked.
func TestDockerFreshRunGuardLineIsNeverMarked(t *testing.T) {
	t.Parallel()
	base := testDocker()
	requireProjectImage(t, base)
	lost := throwawayTag("marker-lost-sh")
	build := exec.Command("docker", "build", "-q", "-t", lost, "-")
	build.Stdin = strings.NewReader("FROM " + base.ProjectImage + "\nUSER root\nRUN echo " +
		base64.StdEncoding.EncodeToString([]byte(markerLostSh)) + " | base64 -d > /tmp/sh && chmod 755 /tmp/sh && mv /tmp/sh /bin/sh\nUSER node\n")
	if out, err := build.CombinedOutput(); err != nil {
		infraSkip(t, "cannot build throwaway image: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rmi", "-f", lost).Run() })
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	line := strings.TrimSuffix(impersonatorLine, "\n")
	step := `echo "` + line + `" >&2; { echo "` + line + `" > /proc/1/fd/2; } 2>/dev/null; exit 123`
	for _, c := range []struct {
		image  string
		marker bool
	}{{base.ProjectImage, true}, {lost, false}} {
		d := testDocker()
		d.Image, d.ProjectImage = c.image, c.image
		if err := d.Preflight(ctx); err != nil {
			t.Fatalf("%s: %v", c.image, err)
		}
		r, err := d.RunJavaScript(ctx, Request{Code: stderrReopen + impersonatorJS(123)})
		if reason, marked := NotDispatchedReason(err); marked {
			t.Fatalf("%s: a snippet whose code wrote the guard's line came back marked not dispatched (reason %v): %v", c.image, reason, err)
		}
		switch {
		case c.marker && err != nil && strings.Contains(err.Error(), "is not known"):
			// The code took its own marker ahead of docker: the race this test stands in for, won.
			t.Logf("%s: the snippet's code took its start marker; the answer came back unmarked: %v", c.image, err)
		case c.marker && (err != nil || r.ExitCode != 123 || !strings.HasSuffix(r.Stderr, impersonatorLine)):
			t.Errorf("%s: %+v, %v; want the code's own exit 123 with the line it wrote, a result", c.image, r, err)
		case !c.marker && (err == nil || !strings.Contains(err.Error(), "step self-check") || !strings.Contains(err.Error(), "is not known")):
			t.Errorf("%s: %+v, %v; want an unmarked error naming the guard's step and saying whether the code ran is not known", c.image, r, err)
		}
		pr, err := d.RunProject(ctx, ProjectRequest{Steps: []string{step}})
		if reason, marked := NotDispatchedReason(err); marked {
			t.Fatalf("%s: a project whose step wrote the guard's line came back marked not dispatched (reason %v): %v", c.image, reason, err)
		}
		if err != nil || len(pr.Steps) != 1 || pr.Steps[0].ExitCode != 123 {
			t.Errorf("%s: %+v, %v; want the runner's report of the step's own exit 123", c.image, pr, err)
		}
	}
}
