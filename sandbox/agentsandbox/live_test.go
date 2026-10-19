package agentsandbox

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// liveProvider is the provider for a real cluster, built by FromEnv from the variables
// plimsolld reads (SANDBOX_AGENTSANDBOX_* and the shared ones); the test skips unless
// AGENTSANDBOX_LIVE=1. Free, but it needs a cluster with agent-sandbox, a warm pool and a
// template that passes the read-back (docs/agentsandbox.md), and a route to the pods'
// addresses. AGENTSANDBOX_TIER is the tier the operator expects (vm, kernel or container),
// stated outside the provider so the test does not take the provider's own reading as
// its answer.
func liveProvider(t *testing.T) *Provider {
	t.Helper()
	if os.Getenv("AGENTSANDBOX_LIVE") != "1" {
		t.Skip("set AGENTSANDBOX_LIVE=1, AGENTSANDBOX_TIER and the SANDBOX_AGENTSANDBOX_* settings to run against a cluster")
	}
	built, err := FromEnv(os.Getenv)
	if err != nil {
		t.Fatal(err)
	}
	p := built.Sandbox.(*Provider)
	if err := p.Preflight(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := sandbox.ParseIsolationClass(os.Getenv("AGENTSANDBOX_TIER"))
	if want != sandbox.IsolationVM && want != sandbox.IsolationKernel && want != sandbox.IsolationContainer {
		t.Fatalf("AGENTSANDBOX_TIER is %q; set vm, kernel or container", os.Getenv("AGENTSANDBOX_TIER"))
	}
	if p.IsolationClass() != want {
		t.Fatalf("the provider reads tier %s, and the cluster was set up for %s", p.IsolationClass(), want)
	}
	return p
}

func TestRunsLive(t *testing.T) {
	p := liveProvider(t)
	ctx := context.Background()
	tier := p.IsolationClass()

	start := time.Now()
	res, err := p.RunJavaScript(ctx, sandbox.Request{Code: `
const fs = require("fs");
console.log(JSON.stringify({
  sum: 1 + 1, uid: process.getuid(), gid: process.getgid(),
  env: Object.keys(process.env).sort(),
  status: fs.readFileSync("/proc/self/status", "utf8").split("\n").filter(l => /^(CapEff|NoNewPrivs|Groups)/.test(l)),
  resolv: fs.readFileSync("/etc/resolv.conf", "utf8"),
  token: fs.existsSync("/var/run/secrets/kubernetes.io/serviceaccount/token"),
}));`, MinimumIsolation: tier, Timeout: 20 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("snippet in %s: exit %d, tier %s, stdout %s stderr %q", time.Since(start).Round(time.Millisecond), res.ExitCode, res.Isolation, res.Stdout, res.Stderr)
	var got struct {
		Sum, UID, GID int
		Env           []string
		Status        []string
		Resolv        string
		Token         bool
	}
	if err := json.Unmarshal([]byte(res.Stdout), &got); err != nil {
		t.Fatalf("stdout %q: %v", res.Stdout, err)
	}
	if got.Sum != 2 || got.UID != guestUID || got.GID != guestUID || got.Token || res.Isolation != tier {
		t.Fatalf("snippet %+v", got)
	}
	for _, l := range got.Status {
		if strings.HasPrefix(l, "CapEff") && !strings.HasSuffix(l, "0000000000000000") || strings.HasPrefix(l, "NoNewPrivs") && !strings.HasSuffix(l, "1") {
			t.Fatalf("guest status %v", got.Status)
		}
	}

	egress, err := p.RunJavaScript(ctx, sandbox.Request{Code: `
const net = require("net");
const s = net.connect({host: "1.1.1.1", port: 443, timeout: 3000});
s.on("connect", () => { console.log("connected"); process.exit(0); });
s.on("timeout", () => { console.log("timeout"); process.exit(0); });
s.on("error", e => { console.log("error " + e.code); process.exit(0); });`, Timeout: 20 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("egress: %q", egress.Stdout)
	if strings.Contains(egress.Stdout, "connected") {
		t.Fatal("the guest reached 1.1.1.1")
	}

	start = time.Now()
	pr, err := p.RunProject(ctx, sandbox.ProjectRequest{
		Files: []sandbox.File{{Path: "main.js", Content: `require("fs").writeFileSync("out.txt", "made by " + process.getuid()); console.log("ran")`}},
		Steps: []string{"node main.js"}, Artifacts: []string{"out.txt"}, Timeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("project in %s: %s %q steps %+v", time.Since(start).Round(time.Millisecond), pr.Outcome, pr.Detail, pr.Steps)
	if pr.Outcome != sandbox.ProjectOutcomeCompleted || len(pr.Steps) != 1 || pr.Steps[0].ExitCode != 0 ||
		len(pr.Artifacts) != 1 || string(pr.Artifacts[0].Content) != "made by "+strconv.Itoa(guestUID) {
		t.Fatalf("project %+v", pr)
	}

	if above, ok := map[sandbox.IsolationClass]sandbox.IsolationClass{sandbox.IsolationContainer: sandbox.IsolationKernel, sandbox.IsolationKernel: sandbox.IsolationVM}[tier]; ok {
		// A caller's floor above the cluster's tier is refused before any pod is claimed.
		_, err := p.RunJavaScript(ctx, sandbox.Request{Code: "1", MinimumIsolation: above, Timeout: 5 * time.Second})
		if reason, ok := sandbox.NotDispatchedReason(err); !errors.Is(err, sandbox.ErrInsufficientIsolation) || !ok || reason != sandbox.RefusalIsolation {
			t.Fatalf("a %s floor on the %s tier: %v", above, tier, err)
		}
	}

	hung, err := p.RunJavaScript(ctx, sandbox.Request{Code: `setInterval(() => {}, 1000)`, Timeout: 8 * time.Second})
	if err != nil || !hung.TimedOut {
		t.Fatalf("a hung snippet: timed out %v, %v", hung.TimedOut, err)
	}

	dctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if err := p.Drain(dctx); err != nil {
		t.Fatal(err)
	}
	if n, err := p.ReconcileOrphans(ctx); err != nil || n != 0 {
		t.Fatalf("reconcile: %d, %v", n, err)
	}
}

// TestSmokeLive runs the startup smoke test against the cluster and logs what it
// measured; on a failure it logs the boundary report it judged.
func TestSmokeLive(t *testing.T) {
	p := liveProvider(t)
	defer drained(t, p)
	if err := p.SmokeTest(context.Background()); err != nil {
		ev, berr := p.smokeBoundary(context.Background(), p.IsolationClass())
		b, _ := json.MarshalIndent(ev, "", "  ")
		t.Fatalf("%v\nboundary report (%v):\n%s", err, berr, b)
	}
	b, err := json.MarshalIndent(p.lastSmoke(), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("smoke evidence:\n%s", b)
	// The smoke test pinned the template it proved; past the check's cache, a fresh read of
	// the same template must still match it, or every later run would be refused.
	time.Sleep(preflightTTL + time.Second)
	if err := p.Preflight(context.Background()); err != nil {
		t.Fatalf("the proven template, read again: %v", err)
	}
}
