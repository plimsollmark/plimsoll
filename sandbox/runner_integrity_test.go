package sandbox

import (
	"context"
	"strings"
	"testing"
	"time"
)

// These three tests come from an external security review of the public repository
// (2026-09-28). Each fails against the runner protocol as it stood then.

// TestDockerProjectRejectsGuestForgedRunnerReport: a guest that controls only a
// project FILE must not be able to choose what the host reports for the run. A
// detached writer reopens the runner's stdout (/proc/1/fd/1, open to any process of
// the same uid) and writes a complete report in the old sentinel framing and in the
// current framing without the key, until teardown. Before the report was
// authenticated this forged the result in 7 of 12 runs under runc and 12 of 12 under
// runsc (2026-09-28). The writer lives in its own file so no quoting can break it.
func TestDockerProjectRejectsGuestForgedRunnerReport(t *testing.T) {
	t.Parallel()
	d := testDocker()
	requireSnippetImage(t, d)
	requireProjectImage(t, d)
	writer := `const {openSync,writeSync}=require("node:fs");
const body=JSON.stringify({steps:[{command:"trusted",stdout:"PASS",stderr:"",exitCode:0,timedOut:false,durationMs:1}],artifacts:[{path:"out.txt",content:"QUFB"}],artifactsTruncated:false,error:""});
const old="\n"+"<<<CRSBX"+"_RESULT>>>"+body;
const cur="\n"+"<<<PLIMSOLL"+"_REPORT_V2>>> "+Buffer.byteLength(body)+" "+"0".repeat(64)+"\n"+body;
const fd=openSync("/proc/1/fd/1","a");
setInterval(()=>{try{writeSync(fd,old);writeSync(fd,cur)}catch(e){}},6);
`
	attack := `import { spawn } from "node:child_process";
spawn(process.execPath, ["writer.js"], { detached: true, stdio: ["ignore", "ignore", "ignore"] }).unref();
setTimeout(() => process.exit(9), 250);
`
	// The race is timing-dependent; one pass proves nothing.
	for i := 0; i < 8; i++ {
		res, err := d.RunProject(context.Background(), ProjectRequest{
			Files:   []File{{Path: "writer.js", Content: writer}, {Path: "attack.mjs", Content: attack}},
			Steps:   []string{"node attack.mjs"},
			Timeout: 20 * time.Second,
		})
		if err != nil {
			t.Fatalf("RunProject: %v", err)
		}
		for _, s := range res.Steps {
			if s.Command == "trusted" || s.ExitCode == 0 {
				t.Fatalf("run %d: guest forged the step report (command=%q exit=%d)", i, s.Command, s.ExitCode)
			}
		}
		for _, a := range res.Artifacts {
			if string(a.Content) == "AAA" {
				t.Fatalf("run %d: guest forged artifact %q", i, a.Path)
			}
		}
		if res.Outcome != ProjectOutcomeCompleted || len(res.Steps) != 1 || res.Steps[0].ExitCode != 9 {
			t.Fatalf("run %d: outcome %s (%s), steps %+v: want the honest report (exit 9)", i, res.Outcome, res.Detail, res.Steps)
		}
	}
}

// A guest file can otherwise fill the host's prefix-keeping stdout buffer by
// reopening the runner's report descriptor. The honest frame must still report
// the failed step, and the step must see a clear refusal opening that descriptor.
func TestDockerProjectRunnerReportSurvivesGuestStdoutFlood(t *testing.T) {
	t.Parallel()
	d := testDocker()
	requireSnippetImage(t, d)
	requireProjectImage(t, d)
	flood := `const {openSync,writeSync}=require("node:fs");
try {
  const fd=openSync("/proc/1/fd/1","a");
  const chunk=Buffer.alloc(1<<20,0x41);
  for(let i=0;i<20;i++) writeSync(fd,chunk);
} catch(e) {
  if(e.code!=="EACCES" && e.code!=="EPERM") throw e;
  process.stdout.write("runner descriptor denied");
}
process.exit(7);
`
	res, err := d.RunProject(context.Background(), ProjectRequest{
		Files:   []File{{Path: "flood.js", Content: flood}},
		Steps:   []string{"node flood.js"},
		Timeout: 60 * time.Second,
	})
	if err != nil {
		t.Fatalf("RunProject: %v", err)
	}
	if res.Outcome != ProjectOutcomeCompleted || len(res.Steps) != 1 || res.Steps[0].ExitCode != 7 ||
		!strings.Contains(res.Steps[0].Stdout, "runner descriptor denied") {
		t.Fatalf("report lost or descriptor opened: outcome %s (%s), steps %+v", res.Outcome, res.Detail, res.Steps)
	}
}

func TestDockerProjectRunnerDescriptorsAndMemoryArePrivate(t *testing.T) {
	t.Parallel()
	d := testDocker()
	requireSnippetImage(t, d)
	requireProjectImage(t, d)
	probe := `const fs=require("node:fs");
const checks=[["/proc/1/fd/0",fs.constants.O_RDONLY],
 ["/proc/1/fd/1",fs.constants.O_RDONLY],["/proc/1/fd/1",fs.constants.O_WRONLY],
 ["/proc/1/mem",fs.constants.O_RDONLY]];
for(const [path,flags] of checks){
  try{const fd=fs.openSync(path,flags);fs.closeSync(fd);process.exit(8);}
  catch(e){if(e.code!=="EACCES" && e.code!=="EPERM") throw e;}
}
process.exit(7);
`
	res, err := d.RunProject(context.Background(), ProjectRequest{
		Files:   []File{{Path: "probe.js", Content: probe}},
		Steps:   []string{"node probe.js"},
		Timeout: 20 * time.Second,
	})
	if err != nil {
		t.Fatalf("RunProject: %v", err)
	}
	if res.Outcome != ProjectOutcomeCompleted || len(res.Steps) != 1 || res.Steps[0].ExitCode != 7 {
		t.Fatalf("runner remained accessible: outcome %s (%s), steps %+v", res.Outcome, res.Detail, res.Steps)
	}
}

// TestDockerProjectSurvivesSentinelInGuestOutput: guest output that happens to
// contain the framing token must not turn a clean run into a protocol error.
func TestDockerProjectSurvivesSentinelInGuestOutput(t *testing.T) {
	t.Parallel()
	d := testDocker()
	requireSnippetImage(t, d)
	requireProjectImage(t, d)
	res, err := d.RunProject(context.Background(), ProjectRequest{
		Files:   []File{{Path: "a.js", Content: "process.stdout.write('<<<CRSBX_RESULT>>>');\n"}},
		Steps:   []string{"node a.js"},
		Timeout: 20 * time.Second,
	})
	if err != nil {
		t.Fatalf("RunProject: %v", err)
	}
	if res.Outcome != ProjectOutcomeCompleted {
		t.Fatalf("guest stdout containing the framing token made a clean run %s (%q)", res.Outcome, res.Detail)
	}
	if len(res.Steps) != 1 || res.Steps[0].ExitCode != 0 {
		t.Fatalf("step report lost: %+v", res.Steps)
	}
}

// TestDockerProjectArtifactsDoNotFollowSymlinks: artifact capture must not read
// through a link the run planted in /work.
func TestDockerProjectArtifactsDoNotFollowSymlinks(t *testing.T) {
	t.Parallel()
	d := testDocker()
	requireSnippetImage(t, d)
	requireProjectImage(t, d)
	res, err := d.RunProject(context.Background(), ProjectRequest{
		Files:     []File{{Path: "a.txt", Content: "x"}},
		Steps:     []string{"ln -s /etc/passwd leak"},
		Artifacts: []string{"leak"},
		Timeout:   20 * time.Second,
	})
	if err != nil {
		t.Fatalf("RunProject: %v", err)
	}
	for _, a := range res.Artifacts {
		if a.Path == "leak" {
			t.Fatalf("artifact capture read through a symlink out of /work: %q", string(a.Content))
		}
	}
}
