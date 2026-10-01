package sandbox

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The shipped profile allows mknod and mknodat only for FIFOs, which a session's
// interpreter needs for its output (docs/seccomp.md). A regular file and a device
// node through mknod stay denied: the regular file only by the filter, since
// creating one needs no capability.
func TestDockerSeccompAllowsOnlyFIFOs(t *testing.T) {
	d := testDocker()
	d.ProjectImage = "plimsoll/sandbox-python:latest"
	requireProjectImage(t, d)
	if d.Runtime == "runsc" {
		t.Log("gVisor filters syscalls itself and the profile is not applied; this checks gVisor's answer")
	}
	profile, err := filepath.Abs("../docker/seccomp.json")
	if err != nil {
		t.Fatal(err)
	}
	d.Seccomp = profile
	code := `import os, stat
os.mkfifo("fifo")
print("fifo", stat.S_ISFIFO(os.stat("fifo").st_mode))
for name, mode, dev in [("file", stat.S_IFREG | 0o600, 0), ("char", stat.S_IFCHR | 0o600, os.makedev(1, 3))]:
    try:
        os.mknod(name, mode, dev)
        print(name, "created")
    except PermissionError:
        print(name, "denied")
`
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := d.RunProject(ctx, ProjectRequest{Files: []File{{Path: "probe.py", Content: code}}, Steps: []string{"python3 probe.py"}})
	if err != nil || res.Outcome != ProjectOutcomeCompleted || len(res.Steps) != 1 {
		t.Fatalf("probe: %+v, %v", res, err)
	}
	out := res.Steps[0].Stdout
	if !strings.Contains(out, "fifo True") || !strings.Contains(out, "char denied") {
		t.Fatalf("probe printed %q", out)
	}
	if d.Runtime != "runsc" && !strings.Contains(out, "file denied") {
		t.Fatalf("a regular file through mknod was not denied under the profile: %q", out)
	}
}
