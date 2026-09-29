package sandbox

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The process floors TestDockerGuestGetsItsProcessBudget holds a guest to at the
// default SANDBOX_PIDS of 256. Under runc the limit counts only the guest's own tasks,
// and 64 below it leaves room for the runner's and the step's node threads. Under
// runsc it also counts gVisor's tasks, about two host tasks per guest process: a guest
// held 112 single-threaded processes before ENOMEM (measured 2026-09-29, gVisor release
// 20260907.0, docs/gvisor.md), and 96 is that less about a seventh, so run-to-run noise
// passes and a release that grew the per-process cost fails.
const (
	runcPidsFloor  = 256 - 64
	runscPidsFloor = 96
)

// TestDockerGuestGetsItsProcessBudget: with the default SANDBOX_PIDS of 256, a guest
// can hold its runtime's floor of processes at once. The smoke test proves the cap on
// the enforcing cgroup; this proves the floor, which gVisor's overhead moves. It stops
// below the limit on purpose: at the limit, runsc runs sometimes end with exit status 2
// and no output (docs/gvisor.md). External review of v0.10.0, documentation item 6
// (2026-09-28).
func TestDockerGuestGetsItsProcessBudget(t *testing.T) {
	d := testDocker()
	requireSnippetImage(t, d)
	requireProjectImage(t, d)
	d.PidsLimit = "256"
	want := runcPidsFloor
	if d.Runtime == "runsc" {
		want = runscPidsFloor
	}
	hold := `const {spawn}=require("node:child_process");const want=+process.argv[2];
const kids=[];let ok=0,failed=0,first="";
const done=()=>{if(ok+failed<want)return;for(const k of kids){try{k.kill("SIGKILL")}catch{}}
console.log(JSON.stringify({ok,failed,first}));process.exit(0)};
for(let i=0;i<want;i++){let k;try{k=spawn("sleep",["30"],{stdio:"ignore"})}catch(e){failed++;if(!first)first=e.code;done();continue}
kids.push(k);k.on("spawn",()=>{ok++;done()});k.on("error",e=>{failed++;if(!first)first=e.code;done()})}
`
	res, err := d.RunProject(context.Background(), ProjectRequest{
		Files:   []File{{Path: "hold.js", Content: hold}},
		Steps:   []string{"node hold.js " + strconv.Itoa(want)},
		Timeout: 90 * time.Second,
	})
	if err != nil {
		t.Fatalf("RunProject: %v", err)
	}
	if res.Outcome != ProjectOutcomeCompleted || len(res.Steps) != 1 {
		t.Fatalf("runtime %q: outcome %s (%s), %d steps", d.Runtime, res.Outcome, res.Detail, len(res.Steps))
	}
	out := strings.TrimSpace(res.Steps[0].Stdout)
	t.Logf("runtime %q: %s", d.Runtime, out)
	if !strings.HasPrefix(out, `{"ok":`+strconv.Itoa(want)+`,"failed":0`) {
		t.Fatalf("a guest under SANDBOX_PIDS=256 and runtime %q could not hold %d processes: %s (stderr %q)", d.Runtime, want, out, res.Steps[0].Stderr)
	}
}
