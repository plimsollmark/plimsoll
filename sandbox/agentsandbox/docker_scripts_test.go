package agentsandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandbox/internal/dockertest"
)

// The scripts the smoke test sends into a pod, run offline in the docker suite's
// locked-down container (sandbox/guest_scripts_test.go lists every such script). Docker is
// not agent-sandbox, so these prove the scripts run and their reports parse and judge as
// the provider expects of a container that docker locks down, not anything about a pod.

// TestDockerRunsTheAgentSandboxBoundaryScript runs the boundary script as a docker
// snippet and holds its report to what docker's lockdown gives: the guest uid with no
// capability, writes only in docker's tmpfs mounts (and a message queue), /tmp refusing
// writes at its size, no connection out, the kernel and seccomp checks for docker's tier.
func TestDockerRunsTheAgentSandboxBoundaryScript(t *testing.T) {
	d := dockertest.Sandbox(t)
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	const tmpSize = 16 << 20 // docker's default /tmp, which the snippet container mounts
	code := fmt.Sprintf(boundaryScript, `[]`, fmt.Sprintf(`[["/tmp", %d]]`, tmpSize))
	res, err := d.RunJavaScript(ctx, sandbox.Request{Code: code, Timeout: 60 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 || res.StdoutTruncated {
		t.Fatalf("exit %d (truncated %t): %s", res.ExitCode, res.StdoutTruncated, res.Stderr)
	}
	var r boundaryReport
	if err := json.Unmarshal([]byte(res.Stdout), &r); err != nil {
		t.Fatalf("unparseable report %q: %v", truncate(res.Stdout, 300), err)
	}
	tier := d.IsolationClass()
	t.Logf("tier %s: swept %d, writable %v, files %v, created %v, egress %v, seccomp %q, msgqueue %q, kernel %q",
		tier, r.Swept, r.Writable, r.Files, r.Created, r.Egress, r.Seccomp, r.Msgqueue, r.Dmesg)

	uid := fmt.Sprint(guestUID)
	ids := strings.Join([]string{uid, uid, uid, uid}, "\t")
	if r.UID != ids || r.CapEff != "0000000000000000" || r.NoNewPrivs != "1" || r.Node == "" {
		t.Errorf("identity: uid %q capEff %q noNewPrivs %q node %q", r.UID, r.CapEff, r.NoNewPrivs, r.Node)
	}
	created, err := checkMqueue(r)
	if err != nil {
		t.Error(err)
	}
	roots := []string{"/dev/shm", "/tmp"}
	if err := checkWritable(r.Swept, slices.Concat(r.Writable, created), r.Files, append(roots, workDir)); err != nil &&
		!strings.Contains(err.Error(), workDir+" does not accept") {
		t.Error(err) // a snippet container has no /work; anything else is a finding
	}
	if err := checkFill(r, map[string]int64{"/tmp": tmpSize}); err != nil {
		t.Error(err)
	}
	if len(r.Egress) != 5 { // the five fixed targets (three IPv4, two IPv6); no API server, and no default route to add a kubelet
		t.Errorf("egress %v", r.Egress)
	}
	if err := checkEgress(r.Egress, "no route"); err != nil {
		t.Error(err)
	}
	if err := checkKernel(tier, r.Dmesg); err != nil {
		t.Error(err)
	}
	if err := checkSeccompMode(tier, r.Seccomp); err != nil {
		t.Error(err)
	}
}

// TestDockerRunsTheAgentSandboxRunnerScript runs the runner script as a project step
// under docker's /runner.mjs: it must find the runner among its ancestors and be refused
// the runner's plan and report descriptors and memory. In a pod, pid 1 is sandboxd, run as
// root; under docker run it is the runner itself, so every check meets the guard.
func TestDockerRunsTheAgentSandboxRunnerScript(t *testing.T) {
	d := dockertest.Sandbox(t)
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	res, err := d.RunProject(ctx, sandbox.ProjectRequest{
		Files: []sandbox.File{{Path: "runner-check.js", Content: runnerScript}},
		Steps: []string{"node runner-check.js"}, Timeout: 60 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Steps) != 1 {
		t.Fatalf("%s %q steps %+v", res.Outcome, res.Detail, res.Steps)
	}
	step := res.Steps[0]
	t.Logf("exit %d: %s %s", step.ExitCode, step.Stdout, step.Stderr)
	var got map[string]string
	if err := json.Unmarshal([]byte(step.Stdout), &got); err != nil {
		t.Fatalf("exit %d, unparseable report %q: %v", step.ExitCode, step.Stdout, err)
	}
	if step.ExitCode != 0 || len(got) < 4 {
		t.Errorf("exit %d, %d checks reported: %v", step.ExitCode, len(got), got)
	}
	for k, v := range got {
		if v != "EACCES" && v != "EPERM" {
			t.Errorf("%s: %s", k, v)
		}
	}
}

// TestDockerRunsTheAgentSandboxTierCheck runs the shell command every run sends into its pod
// before any code (tierCheck, without the setpriv and env -i that drop to the guest in a
// pod: docker's snippet already runs as the guest) and holds its output to the parser and
// to the kernel and seccomp checks for docker's own tier: under runc a filter is in force
// (and the kernel log unreadable), under runsc the log begins with gVisor's boot line; under
// either the boot ID reads as one.
func TestDockerRunsTheAgentSandboxTierCheck(t *testing.T) {
	d := dockertest.Sandbox(t)
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	script, err := json.Marshal(tierCheck[len(tierCheck)-1])
	if err != nil {
		t.Fatal(err)
	}
	code := `process.stdout.write(require("child_process").execFileSync("sh", ["-c", ` + string(script) + `]))`
	res, err := d.RunJavaScript(ctx, sandbox.Request{Code: code, Timeout: 30 * time.Second})
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("exit %d, %v: %s", res.ExitCode, err, res.Stderr)
	}
	tc, ok := parseTierCheck([]byte(res.Stdout))
	if !ok {
		t.Fatalf("unparseable tier check output %q", res.Stdout)
	}
	tier := d.IsolationClass()
	t.Logf("tier %s: kernel log %q, boot ID %q, seccomp %q", tier, tc.kernel, tc.boot, tc.seccomp)
	if err := errors.Join(checkKernel(tier, tc.kernel), checkSeccompMode(tier, tc.seccomp)); err != nil {
		t.Error(err)
	}
	if err := errors.Join(checkNestedMounts(tc.mounts, []string{"/tmp", "/dev/shm"}), checkRootMountKinds(tc.mounts, []string{"/tmp", "/dev/shm"}, []string{"tmpfs"})); err != nil {
		t.Error(err)
	}
	if !bootID.MatchString(tc.boot) {
		t.Errorf("the boot ID reads %q", tc.boot)
	}
}
