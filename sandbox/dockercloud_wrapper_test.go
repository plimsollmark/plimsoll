package sandbox

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"regexp"
	"strconv"
	"testing"
	"time"
)

// The Docker Cloud exec API has no timeout and no output bound, so dcExecWrapper
// supplies both inside the guest. These tests run the wrapper itself, with fixed
// test commands, under the two shells and tool sets it must work with: the host's
// (dash or bash with coreutils, which the hosted CI runner also has) and busybox
// (the alpine toolchain image, through the docker provider).

func runWrapperOnHost(t *testing.T, limit, cap int, argv ...string) (stdout, stderr []byte, rc int, elapsed time.Duration) {
	t.Helper()
	args := append([]string{"-c", dcExecWrapper, "plimsoll-exec", strconv.Itoa(limit), strconv.Itoa(cap)}, argv...)
	cmd := exec.Command("sh", args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	start := time.Now()
	err := cmd.Run()
	elapsed = time.Since(start)
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr):
		rc = exitErr.ExitCode()
	default:
		t.Fatalf("run wrapper: %v", err)
	}
	return out.Bytes(), errb.Bytes(), rc, elapsed
}

func TestDockerCloudExecWrapperOnHostShell(t *testing.T) {
	for _, tool := range []string{"sh", "timeout", "head", "yes", "sleep"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not on PATH", tool)
		}
	}

	t.Run("streams and exit status pass through unmarked", func(t *testing.T) {
		out, errb, rc, _ := runWrapperOnHost(t, 5, 11, "sh", "-c", `printf 'out\000\377'; printf err >&2; exit 3`)
		if string(out) != "out\x00\xff" || string(errb) != "err" || rc != 3 {
			t.Fatalf("stdout=%q stderr=%q rc=%d", out, errb, rc)
		}
	})
	t.Run("stdout flood is capped in the guest and fails the run", func(t *testing.T) {
		out, errb, rc, _ := runWrapperOnHost(t, 5, 11, "yes")
		if len(out) != 11 || len(errb) != 0 || rc == 0 {
			t.Fatalf("len(stdout)=%d len(stderr)=%d rc=%d", len(out), len(errb), rc)
		}
	})
	t.Run("stderr flood is capped separately", func(t *testing.T) {
		out, errb, rc, _ := runWrapperOnHost(t, 5, 11, "sh", "-c", "yes >&2")
		if len(out) != 0 || len(errb) != 11 || rc == 0 {
			t.Fatalf("len(stdout)=%d len(stderr)=%d rc=%d", len(out), len(errb), rc)
		}
	})
	t.Run("time limit kills with 137", func(t *testing.T) {
		_, _, rc, elapsed := runWrapperOnHost(t, 1, 11, "sleep", "30")
		if rc != 137 || elapsed < time.Second || elapsed > 10*time.Second {
			t.Fatalf("rc=%d elapsed=%v, want 137 after about 1s", rc, elapsed)
		}
	})
}

// TestDockerCloudExecWrapperUnderBusyboxDocker runs the same cases inside the
// toolchain image, whose sh, timeout and head are busybox. It runs in the docker
// suite (its name matches that selection) and needs the project image.
//
// It runs under docker's built-in seccomp profile, not the shipped one the suite
// otherwise applies. The shipped profile denies kill(2), and busybox `timeout`
// then fails open: its watcher reads the refused kill(pid, 0) as "the process is
// gone" and exits, so the command runs to completion (observed: sleep 30 returned
// 0 after 31s). That is a property of the docker provider's profile, not of the
// wrapper, and the Docker Cloud guest applies no such profile; SmokeTest proves the
// limit really holds in the configured guest.
func TestDockerCloudExecWrapperUnderBusyboxDocker(t *testing.T) {
	d := testDocker()
	d.Seccomp = ""
	requireProjectImage(t, d)
	const script = `sh wrapper.sh 5 11 sh -c 'printf out; printf err >&2; exit 3' >o1 2>e1; echo "case1 rc=$? out=$(cat o1) err=$(cat e1)"
sh wrapper.sh 5 11 yes >o2 2>e2; echo "case2 rc=$? outlen=$(wc -c <o2 | tr -d ' ')"
sh wrapper.sh 5 11 sh -c 'yes >&2' >o3 2>e3; echo "case3 rc=$? errlen=$(wc -c <e3 | tr -d ' ')"
start=$(date +%s); sh wrapper.sh 1 11 sleep 30 >o4 2>e4; echo "case4 rc=$? secs=$(( $(date +%s) - start ))"
`
	res, err := d.RunProject(context.Background(), ProjectRequest{
		Files:   []File{{Path: "wrapper.sh", Content: dcExecWrapper}, {Path: "cases.sh", Content: script}},
		Steps:   []string{"sh cases.sh"},
		Timeout: 60 * time.Second,
	})
	if err != nil {
		t.Fatalf("RunProject: %v", err)
	}
	if res.Outcome != ProjectOutcomeCompleted || len(res.Steps) != 1 || res.Steps[0].ExitCode != 0 {
		t.Fatalf("result = %+v", res)
	}
	out := res.Steps[0].Stdout
	for _, want := range []*regexp.Regexp{
		regexp.MustCompile(`(?m)^case1 rc=3 out=out err=err$`),
		regexp.MustCompile(`(?m)^case2 rc=[1-9][0-9]* outlen=11$`),
		regexp.MustCompile(`(?m)^case3 rc=[1-9][0-9]* errlen=11$`),
		regexp.MustCompile(`(?m)^case4 rc=137 secs=[1-4]$`),
	} {
		if !want.MatchString(out) {
			t.Errorf("busybox wrapper output does not match %s:\n%s\nstderr: %s", want, out, res.Steps[0].Stderr)
		}
	}
}
