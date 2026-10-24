package openshell

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandbox/internal/dockertest"
)

// The programs this provider sends into an OpenShell sandbox, run offline in the docker
// suite's locked-down container (sandbox/guest_scripts_test.go lists every such program).
// Docker is not OpenShell, so these prove each program runs and answers in the form the
// provider reads, not anything about a gateway's sandbox; the live suite proves that.

// TestDockerRunsTheOpenShellSmokeScript runs the smoke test's sweep and egress script as
// a docker snippet and parses its report as smokeProbe does.
func TestDockerRunsTheOpenShellSmokeScript(t *testing.T) {
	d := dockertest.Sandbox(t)
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	res, err := d.RunJavaScript(ctx, sandbox.Request{Code: smokeProbeScript, Timeout: 60 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 || res.StdoutTruncated {
		t.Fatalf("exit %d (truncated %t): %s", res.ExitCode, res.StdoutTruncated, res.Stderr)
	}
	var r smokeReport
	if err := json.Unmarshal([]byte(res.Stdout), &r); err != nil {
		t.Fatalf("unparseable report %q: %v", truncate([]byte(res.Stdout), 300), err)
	}
	t.Logf("swept %d, writable %v, files %v, egress %v, dns %q, interfaces %v, memory %q, pids %q, tmp %q",
		r.Swept, r.Writable, r.WritableFiles, r.Egress, r.DNS, r.Interfaces, r.MemoryMax, r.PidsMax, r.TmpMount)
	if r.Node == "" || r.Swept < minSwept || !slices.Contains(r.Writable, "/tmp") || r.DNS == "" || r.MemoryMax == "" || r.TmpMount == "" {
		t.Errorf("report %+v", r)
	}
	if len(r.Egress) != 5 { // IPv4 and IPv6 addresses, and one name
		t.Errorf("egress %v", r.Egress)
	}
	if err := checkEgress(r.Egress); err != nil {
		t.Error(err)
	}
	if err := checkInterfaces(r.Interfaces); err != nil { // --network none: loopback alone, as OpenShell's sandboxes
		t.Error(err)
	}
}

// TestDockerRunsTheOpenShellSmokeProject runs the smoke test's project as a docker project:
// its step is refused the runner's descriptors and memory, and writes the blob's length and
// digest the host expects.
func TestDockerRunsTheOpenShellSmokeProject(t *testing.T) {
	d := dockertest.Sandbox(t)
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	req, want := smokeProject()
	req.Timeout = 60 * time.Second
	res, err := d.RunProject(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != sandbox.ProjectOutcomeCompleted || len(res.Steps) != 1 || res.Steps[0].ExitCode != 0 {
		t.Fatalf("%s %q steps %+v", res.Outcome, res.Detail, res.Steps)
	}
	if len(res.Artifacts) != 1 || string(res.Artifacts[0].Content) != want {
		t.Fatalf("artifacts %+v, want %q", res.Artifacts, want)
	}
}

// relayDriver runs the grant relay as OpenShell runs it (node -e, the port and socket in
// argv) and plays both sides: a guest connection on the Unix socket and plimsoll's
// connection on the loopback port. A guest that arrives first makes the relay ask for a
// connection ("need") and is paired once one arrives; a plimsoll connection that waits
// idle is paired with the next guest without a "need". Bytes cross both ways each time.
const relayDriver = `const cp = require("child_process"), net = require("net");
const script = %s, port = 20000 + process.pid %% 20000, sock = "/tmp/relay-" + process.pid + ".sock";
const relay = cp.spawn(process.execPath, ["-e", script, String(port), sock], { stdio: ["ignore", "pipe", "pipe"] });
let out = "", errOut = "";
relay.stdout.on("data", d => out += d);
relay.stderr.on("data", d => errOut += d);
const lines = () => out.split("\n").filter(Boolean);
const until = (what, f) => new Promise((done, fail) => {
  const t0 = Date.now();
  const tick = () => f() ? done() : Date.now() - t0 > 10000 ? fail(new Error("no " + what + "; relay said " + JSON.stringify(out) + " " + errOut)) : setTimeout(tick, 10);
  tick();
});
const open = (conn) => new Promise((done, fail) => { conn.once("connect", () => done(conn)); conn.once("error", fail); });
const cross = async (from, to, text) => {
  let got = "";
  to.on("data", d => got += d);
  from.write(text);
  await until(JSON.stringify(text) + " across the relay", () => got === text);
  to.removeAllListeners("data");
};
(async () => {
  await until("ready", () => lines().includes("ready"));
  const g1 = await open(net.connect(sock));
  await until("need", () => lines().filter(l => l === "need").length === 1);
  const u1 = await open(net.connect(port, "127.0.0.1"));
  await cross(g1, u1, "guest to plimsoll");
  await cross(u1, g1, "plimsoll to guest");
  const u2 = await open(net.connect(port, "127.0.0.1"));
  await new Promise(r => setTimeout(r, 100));
  const g2 = await open(net.connect(sock));
  await cross(g2, u2, "second guest");
  await cross(u2, g2, "second answer");
  const needs = lines().filter(l => l === "need").length;
  for (const c of [g1, u1, g2, u2]) c.destroy();
  relay.kill();
  process.stdout.write(JSON.stringify({ lines: lines(), needs }));
})().catch(e => { relay.kill(); console.error(String(e)); process.exit(3); });
`

func TestDockerRunsTheOpenShellGrantRelay(t *testing.T) {
	d := dockertest.Sandbox(t)
	// The relay listens on a loopback TCP port, and plimsoll's docker profile
	// (docker/seccomp.json, which the suite selects) refuses every inet socket. An OpenShell
	// sandbox does not run under that profile, so this run takes docker's default one; the
	// rest of the lockdown is the same.
	d.Seccomp = ""
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	script, err := json.Marshal(relayScript)
	if err != nil {
		t.Fatal(err)
	}
	res, err := d.RunJavaScript(ctx, sandbox.Request{Code: fmt.Sprintf(relayDriver, script), Timeout: 60 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit %d: %s %s", res.ExitCode, res.Stdout, res.Stderr)
	}
	var got struct {
		Lines []string `json:"lines"`
		Needs int      `json:"needs"`
	}
	if err := json.Unmarshal([]byte(res.Stdout), &got); err != nil {
		t.Fatalf("unparseable %q: %v", res.Stdout, err)
	}
	if !slices.Equal(got.Lines, []string{"ready", "need"}) || got.Needs != 1 {
		t.Fatalf("the relay said %v, want ready then one need (the second guest found a waiting connection)", got.Lines)
	}
}
