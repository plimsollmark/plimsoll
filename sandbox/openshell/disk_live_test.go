package openshell

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// fillTmp writes up to limit MiB to /tmp in 1 MiB writes and prints how far it got.
func fillTmp(limit int) string {
	return fmt.Sprintf(`const fs=require("fs");const fd=fs.openSync("/tmp/fill","w");const b=Buffer.alloc(1<<20,1);let n=0;
try{for(let i=0;i<%d;i++){fs.writeSync(fd,b);n+=b.length}console.log("done",n)}catch(e){console.log("stopped",n,e.code)}`, limit)
}

// TestDiskCapLive proves the disk cap against the gateway. A gateway with
// allow_driver_config must pass the startup check of /tmp's mount and stop a run's
// writes at the cap; one without it must refuse startup naming both settings. Either
// outcome is asserted, never skipped, and the log says which one this gateway gave.
func TestDiskCapLive(t *testing.T) {
	p := liveProvider(t, func(c *Config) { c.DiskMB = 64 })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	err := sandbox.Provider{Sandbox: p}.EnsureReady(ctx)
	if err != nil && strings.Contains(err.Error(), "allow_driver_config") {
		if !strings.Contains(err.Error(), "SANDBOX_DISK_MB") {
			t.Fatalf("the refusal does not name SANDBOX_DISK_MB: %v", err)
		}
		t.Logf("this gateway lacks allow_driver_config: startup refused as required (%v); the cap itself was not exercised", err)
		return
	}
	if err != nil {
		t.Fatalf("EnsureReady with the disk cap: %v", err)
	}
	res, err := p.RunJavaScript(ctx, sandbox.Request{Code: fillTmp(100), Timeout: time.Minute})
	if err != nil || strings.TrimSpace(res.Stdout) != "stopped 67108864 ENOSPC" {
		t.Fatalf("a 100 MiB write into a 64 MiB /tmp: %q, %v", res.Stdout, err)
	}

	// A session keeps its files across a suspend with the cap on: its sandbox gets no
	// tmpfs, which docker would discard when the suspend stops the container.
	s, err := p.OpenSession(ctx, sandbox.SessionOptions{Lifetime: 2 * time.Minute, DiskBytes: 32 << 20})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	defer func() { _ = s.Close(context.Background()) }()
	if _, err := s.RunJavaScript(ctx, sandbox.Request{Code: `require("fs").writeFileSync("/tmp/keep","kept")`}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Suspend(ctx); err != nil {
		t.Fatalf("Suspend: %v", err)
	}
	res, err = s.RunJavaScript(ctx, sandbox.Request{Code: `console.log(require("fs").readFileSync("/tmp/keep","utf8"))`})
	if err != nil || strings.TrimSpace(res.Stdout) != "kept" {
		t.Fatalf("a session's file after a suspend: %q, %q, %v", res.Stdout, res.Stderr, err)
	}

	// tmpfs pages are charged to the sandbox's memory: with less memory than disk, the
	// run is killed for memory before /tmp is full (docs/openshell.md, Disk).
	small := liveProvider(t, func(c *Config) { c.DiskMB, c.MemoryMB = 512, 64 })
	if err := small.Preflight(ctx); err != nil {
		t.Fatal(err)
	}
	res, err = small.RunJavaScript(ctx, sandbox.Request{Code: fillTmp(400), Timeout: time.Minute})
	if err != nil || res.ExitCode != 137 || strings.Contains(res.Stdout, "ENOSPC") || strings.Contains(res.Stdout, "done") {
		t.Fatalf("400 MiB into a 512 MiB /tmp with 64 MiB of memory: exit %d, %q, %v; want a kill for memory", res.ExitCode, res.Stdout, err)
	}
}
