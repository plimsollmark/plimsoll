package sandbox

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox/internal/nativehelper"
)

// The helper is non-dumpable from its exec, before its first instruction, because it is
// installed readable by root alone (nativehelper.InstalledMode): the kernel makes a process
// that runs a program its user cannot read non-dumpable at the exec. Before, it was dumpable
// from the exec until its own first call, and in that moment another process of the guest's
// could open /proc/<pid>/mem and change the answer being made (review finding
// session-files-14). Measured 2026-11-27 under runc and gVisor.

// HelperDumpableProbe is a snippet that starts each of paths, with no argument, its stdout and
// stderr on a FIFO already full, so that the program blocks in the write of its usage message
// before it makes any call of its own (the helper's usage path makes none, so a refusal there
// is the exec's alone), then, as its parent, opens /proc/<pid>/mem: Yama's ptrace_scope 1
// admits a parent, so only the program's dumpable state decides. It prints one JSON object:
// for each path, the program's state as /proc/<pid>/stat names it and what the open gave
// ("open", or the error's code). Run in the work folder (the FIFO is made there).
func HelperDumpableProbe(paths ...string) string {
	list, _ := json.Marshal(paths)
	return `const fs = require("fs"), cp = require("child_process");
const out = {};
for (const bin of ` + string(list) + `) {
  const fifo = "plimsoll-probe-fifo-" + process.pid + "-" + Object.keys(out).length;
  cp.execFileSync("mkfifo", [fifo]);
  const rw = fs.openSync(fifo, fs.constants.O_RDWR | fs.constants.O_NONBLOCK);
  const block = Buffer.alloc(4096);
  try { for (;;) fs.writeSync(rw, block); } catch (e) { if (e.code !== "EAGAIN") throw e; }
  const w = fs.openSync(fifo, fs.constants.O_WRONLY);
  const c = cp.spawn(bin, [], { stdio: ["ignore", w, w] });
  const r = { stat: "" };
  for (const t0 = Date.now(); Date.now() - t0 < 10000; ) {
    try { r.stat = fs.readFileSync("/proc/" + c.pid + "/stat", "latin1").split(" ").slice(1, 3).join(" "); } catch (e) { r.stat = e.code; }
    if (/^\((?!node\)).*\) S$/.test(r.stat)) break;
  }
  try { fs.closeSync(fs.openSync("/proc/" + c.pid + "/mem", "r")); r.mem = "open"; } catch (e) { r.mem = e.code; }
  c.kill("SIGKILL"); fs.closeSync(rw); fs.closeSync(w); fs.unlinkSync(fifo);
  out[bin] = r;
}
process.stdout.write(JSON.stringify(out));`
}

// HelperDumpableReading is one path's line of HelperDumpableProbe's output.
type HelperDumpableReading struct {
	Stat, Mem string
}

// CheckHelperDumpable judges HelperDumpableProbe's output for control (a program every user may
// read, which must stay dumpable: its memory "open", so the probe can see a dumpable process
// at all) and helper (which must not: EACCES or EPERM), each blocked in its write.
func CheckHelperDumpable(t *testing.T, stdout, control, helper string) {
	t.Helper()
	var got map[string]HelperDumpableReading
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("the probe printed %q: %v", stdout, err)
	}
	t.Logf("the probe's readings: %+v", got)
	for _, p := range []string{control, helper} {
		if !strings.HasSuffix(got[p].Stat, ") S") || strings.HasPrefix(got[p].Stat, "(node)") {
			t.Fatalf("%s was not blocked in its write when its memory was opened (stat %q), so the reading proves nothing", p, got[p].Stat)
		}
	}
	if got[control].Mem != "open" {
		t.Fatalf("the memory of %s, a program the guest may read, did not open (%q): the probe cannot see a dumpable process here, so it proves nothing", control, got[control].Mem)
	}
	if m := got[helper].Mem; m != "EACCES" && m != "EPERM" {
		t.Fatalf("a process of the guest's opened the memory of the helper at %s before its first call (%q); want it refused from the exec", helper, m)
	}
}

// TestDockerHelperIsNonDumpableFromItsExec: on the project image, in a session, a process of
// the guest's starts the helper and opens its memory before the helper's first call: refused,
// where the same opening of a program the guest may read succeeds.
func TestDockerHelperIsNonDumpableFromItsExec(t *testing.T) {
	t.Parallel()
	d := testDocker()
	requireProjectImage(t, d)
	if dockerNativeHelperFile != "" {
		t.Skip("PLIMSOLL_TEST_NATIVE_HELPER_FILE mounts a file of the host's over the image's helper, with that file's mode")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	s, err := d.OpenSession(ctx, SessionOptions{Lifetime: 2 * time.Minute, DiskBytes: 64 << 20})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	t.Cleanup(func() { _ = s.Close(context.Background()) })
	res, err := s.RunJavaScript(ctx, Request{Code: HelperDumpableProbe("/bin/sleep", nativehelper.InContainer), Timeout: 60 * time.Second})
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("the probe: %+v, %v", res, err)
	}
	CheckHelperDumpable(t, res.Stdout, "/bin/sleep", nativehelper.InContainer)
}
