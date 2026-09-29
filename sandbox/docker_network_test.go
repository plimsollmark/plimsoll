package sandbox

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestDockerLockdownHasNoNetwork pins the flag the whole capability model rests on:
// without a grant a run reaches nothing, and with one it reaches only the broker's
// Unix socket. No daemon needed, so the plain gate catches a deletion too. The flag
// must appear exactly once, so a later argument cannot override it.
func TestDockerLockdownHasNoNetwork(t *testing.T) {
	d := DefaultDocker("")
	for _, runtime := range []string{"", "runsc"} {
		for _, workTmpfs := range []bool{false, true} {
			args := d.lockdownArgs("c", workTmpfs, runtime)
			n := 0
			for i, a := range args {
				if a == "--network" || strings.HasPrefix(a, "--network=") || a == "--net" || strings.HasPrefix(a, "--net=") {
					n++
					if a != "--network" || i+1 >= len(args) || args[i+1] != "none" {
						t.Fatalf("runtime %q, work tmpfs %v: network flag is not --network none: %v", runtime, workTmpfs, args)
					}
				}
			}
			if n != 1 {
				t.Fatalf("runtime %q, work tmpfs %v: %d network flags, want exactly one --network none: %v", runtime, workTmpfs, n, args)
			}
		}
	}
}

func TestCheckLoopbackOnly(t *testing.T) {
	if err := checkLoopbackOnly([]string{"lo"}); err != nil {
		t.Fatalf("loopback alone refused: %v", err)
	}
	for _, bad := range [][]string{nil, {}, {"lo", "eth0"}, {"eth0"}, {"lo", "lo"}} {
		if err := checkLoopbackOnly(bad); err == nil {
			t.Fatalf("interfaces %q accepted", bad)
		}
	}
}

// egressProbe reports the network interfaces the run sees and how an attempt to
// reach a public address ended, as one JSON line.
const egressProbe = `(function () {
  const fs = require("node:fs");
  const interfaces = fs.readFileSync("/proc/net/dev", "utf8").split("\n").slice(2)
    .map(l => l.split(":")[0].trim()).filter(Boolean);
  const done = egress => { console.log(JSON.stringify({ interfaces, egress })); };
  let s;
  try { s = require("node:net").connect({host: "1.1.1.1", port: 443}); } catch (e) { done("THROW " + e.code); return; }
  s.setTimeout(5000);
  s.on("connect", () => { done("OPEN"); s.destroy(); });
  s.on("error", e => done("ERROR " + e.code));
  s.on("timeout", () => { done("TIMEOUT"); s.destroy(); });
})();
`

// checkEgressProbe holds a run to loopback alone and to the expected refusal. Under
// --network none the connect fails at once with ENETUNREACH (measured under runc and
// runsc, 2026-09-29); where the shipped seccomp profile applies (runc with a profile),
// it refuses the non-Unix socket first, with EPERM. A timeout is never denial: on an
// offline host a container with a network would time out too. The interface list is
// what proves the missing network under both, since a refused socket says nothing
// about it.
func checkEgressProbe(t *testing.T, d *DockerSandbox, kind, stdout string) {
	t.Helper()
	var got struct {
		Interfaces []string `json:"interfaces"`
		Egress     string   `json:"egress"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &got); err != nil {
		t.Fatalf("%s: unreadable probe output %q: %v", kind, stdout, err)
	}
	if err := checkLoopbackOnly(got.Interfaces); err != nil {
		t.Fatalf("%s: %v", kind, err)
	}
	want := "ERROR ENETUNREACH"
	if d.Seccomp != "" && d.Runtime != "runsc" {
		want = "ERROR EPERM"
	}
	if got.Egress != want {
		t.Fatalf("%s: a connect to a public address ended %q, want %q", kind, got.Egress, want)
	}
}

// TestDockerRunHasNoEgress runs the probe as a snippet and as a project step, the two
// lockdown shapes.
func TestDockerRunHasNoEgress(t *testing.T) {
	d := testDocker()
	requireSnippetImage(t, d)
	res, err := d.RunJavaScript(context.Background(), Request{Timeout: 30 * time.Second, Code: egressProbe})
	if err != nil {
		t.Fatalf("snippet run: %v", err)
	}
	checkEgressProbe(t, d, "snippet", res.Stdout)

	requireProjectImage(t, d)
	pres, err := d.RunProject(context.Background(), ProjectRequest{
		Files:   []File{{Path: "probe.js", Content: egressProbe}},
		Steps:   []string{"node probe.js"},
		Timeout: 60 * time.Second,
	})
	if err != nil {
		t.Fatalf("project run: %v", err)
	}
	if len(pres.Steps) != 1 {
		t.Fatalf("project run: outcome %s, %d steps (%s)", pres.Outcome, len(pres.Steps), pres.Detail)
	}
	checkEgressProbe(t, d, "project step", pres.Steps[0].Stdout)
}
