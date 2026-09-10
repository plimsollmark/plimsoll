package sandbox

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWasmDefaultCannotReachHostResources is the authoritative isolation guard for
// the default wasm provider (no HostAPI grant — the configuration an in-process
// embedder gets by default).
//
// IMPORTANT: the real boundary is NOT that the std/os GLOBALS are absent. Even
// without `--std`, a snippet can still reach the full QuickJS file/process API via
// dynamic import("qjs:std") / import("qjs:os"). Isolation holds because the wazero
// runtime preopens NO filesystem directory and passes NO host env, so those calls
// fail at the WASI syscall (loadFile/open -> null, readdir -> errno, getenv ->
// undefined). This test obtains the capability the way an attacker would and
// proves it cannot reach real host resources — so it fails the moment a dir mount
// or env-passing is wired onto this path (the regression the docstrings promise).
//
// SCOPE: this covers ONLY the in-process wasm backend. The docker and e2b
// providers run real Node (process/fetch/require defined, host FS/network
// reachable) and rely on an OS/VM boundary (gVisor/microVM) plus a minimally
// scoped token, NOT on JS-global removal.
func TestWasmDefaultCannotReachHostResources(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(secret, []byte("TOP-SECRET-CONTENTS"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WI_SANDBOX_SECRET", "leaked-env-value")

	ws := DefaultWasm() // no HostAPI grant -> no FS preopen, no --std, no env
	code := fmt.Sprintf(`
	  (async () => {
	    const out = {};
	    const std = await import("qjs:std");
	    const os  = await import("qjs:os");
	    // positive control: the modules ARE reachable, so a "blocked" read below is
	    // a real boundary, not a module-missing artifact.
	    out.reachable = (typeof std.loadFile === "function" && typeof os.readdir === "function");
	    let lf; try { lf = std.loadFile(%q); } catch (e) { lf = "threw"; }
	    out.loadFile = (lf === null || lf === undefined || lf === "threw") ? "blocked" : "LEAK:" + String(lf);
	    let op; try { const f = std.open(%q, "r"); op = f ? "OPENED" : "null"; if (f && f.close) f.close(); } catch (e) { op = "threw"; }
	    out.open = (op === "OPENED") ? "LEAK" : "blocked";
	    try { const r = os.readdir("/"); out.readdir = (Array.isArray(r) && r[1] === 0) ? ("LEAK:" + r[0].length) : "blocked"; } catch (e) { out.readdir = "blocked"; }
	    let env; try { env = std.getenv("WI_SANDBOX_SECRET"); } catch (e) { env = "threw"; }
	    out.getenv = (env === undefined || env === null || env === "threw") ? "blocked" : "LEAK:" + env;
	    console.log("ISO=" + JSON.stringify(out));
	  })();
	`, secret, secret)

	res, err := ws.RunJavaScript(context.Background(), Request{Code: code})
	if err != nil {
		t.Fatalf("infra error: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("probe exit=%d stderr=%q", res.ExitCode, res.Stderr)
	}
	out := res.Stdout
	if !strings.Contains(out, "ISO=") {
		t.Fatalf("probe produced no result: %q", out)
	}
	if strings.Contains(out, "LEAK") {
		t.Fatalf("a snippet REACHED a host resource — sandbox isolation regressed: %s", out)
	}
	if !strings.Contains(out, `"reachable":true`) {
		t.Errorf("std/os modules were not reachable; the blocked results would be a false negative: %s", out)
	}
	for _, want := range []string{`"loadFile":"blocked"`, `"open":"blocked"`, `"readdir":"blocked"`, `"getenv":"blocked"`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s in probe output %s", want, out)
		}
	}
}

// TestWasmDefaultExposesNoStdGlobals is a SECONDARY (defense-in-depth) check: with
// no grant, `--std` is not passed, so std/os/require/process are not bound as
// globals. This is NOT the isolation boundary (see the authoritative test above) —
// it just confirms the no-grant path does not enable the libc globals.
func TestWasmDefaultExposesNoStdGlobals(t *testing.T) {
	ws := DefaultWasm()
	res, err := ws.RunJavaScript(context.Background(), Request{Code: `
		const names = ["std","os","require","process","fetch","Deno","Bun"];
		console.log(names.map(n => n + "=" + eval("typeof " + n)).join(","));
	`})
	if err != nil {
		t.Fatalf("probe run failed: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("probe exit=%d stderr=%q", res.ExitCode, res.Stderr)
	}
	for _, want := range []string{"std=undefined", "os=undefined", "require=undefined", "process=undefined", "fetch=undefined"} {
		if !strings.Contains(res.Stdout, want) {
			t.Errorf("expected %q (no --std globals), got %q", want, res.Stdout)
		}
	}
}
