package sandbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestWasmRunJavaScript(t *testing.T) {
	w := DefaultWasm()
	res, err := w.RunJavaScript(context.Background(), Request{Code: `console.log("wasm", 6 * 7)`})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit = %d, want 0 (stderr=%q)", res.ExitCode, res.Stderr)
	}
	if !strings.Contains(res.Stdout, "wasm 42") {
		t.Fatalf("stdout = %q, want it to contain %q", res.Stdout, "wasm 42")
	}
	if res.Sandbox != "wasm" {
		t.Fatalf("sandbox = %q, want wasm", res.Sandbox)
	}
}

func TestWasmEnforcesMinimumIsolationBeforeExecution(t *testing.T) {
	w := DefaultWasm()
	res, err := w.RunJavaScript(context.Background(), Request{
		Code:             `console.log("must not run")`,
		MinimumIsolation: IsolationKernel,
	})
	if !errors.Is(err, ErrInsufficientIsolation) {
		t.Fatalf("RunJavaScript error = %v, want ErrInsufficientIsolation", err)
	}
	if res.Isolation != IsolationProcess || res.Stdout != "" {
		t.Fatalf("rejected result = %+v, want process evidence and no execution output", res)
	}

	project, err := w.RunProject(context.Background(), ProjectRequest{
		Steps:            []string{"true"},
		MinimumIsolation: IsolationVM,
	})
	if !errors.Is(err, ErrInsufficientIsolation) || errors.Is(err, ErrUnsupported) {
		t.Fatalf("RunProject error = %v, want isolation rejection before unsupported operation", err)
	}
	if project.Isolation != IsolationProcess {
		t.Fatalf("project isolation = %s, want process", project.Isolation)
	}
}

func TestWasmNonZeroExitIsResult(t *testing.T) {
	w := DefaultWasm()
	res, err := w.RunJavaScript(context.Background(), Request{Code: `throw new Error("boom")`})
	if err != nil {
		t.Fatalf("a JS error should be a result, got error: %v", err)
	}
	if res.ExitCode == 0 {
		t.Fatalf("expected non-zero exit for an uncaught error")
	}
}

func TestWasmHasNoNetworkOrFS(t *testing.T) {
	w := DefaultWasm()
	// No host import is provided for fetch; it should be undefined in QuickJS.
	res, err := w.RunJavaScript(context.Background(), Request{Code: `console.log("hasFetch=" + (typeof fetch))`})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(res.Stdout, "hasFetch=undefined") {
		t.Fatalf("expected no fetch in the wasm runtime, got %q", res.Stdout)
	}
}

func TestWasmTimeout(t *testing.T) {
	w := DefaultWasm()
	w.DefaultTimeout = 1 * time.Second
	res, err := w.RunJavaScript(context.Background(), Request{Code: `while (true) {}`})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.TimedOut {
		t.Fatalf("expected TimedOut=true, got %+v", res)
	}
}

// TestWasmZeroValueTimeoutFallbacks guards the fix for a hand-built WasmSandbox whose
// MaxTimeout/DefaultTimeout were left zero: the zero value must still be bounded, not
// treated as "no cap" (which let a caller pin an in-process slot indefinitely) and
// not produce a zero (already-expired) default deadline.
func TestWasmZeroValueTimeoutFallbacks(t *testing.T) {
	var w WasmSandbox // zero value
	if got := w.maxTimeout(); got != wasmMaxTimeout {
		t.Errorf("zero-value maxTimeout() = %v, want fallback %v (must not mean 'no cap')", got, wasmMaxTimeout)
	}
	if got := w.defaultTimeout(); got != wasmDefaultTimeout {
		t.Errorf("zero-value defaultTimeout() = %v, want fallback %v (must not be 0)", got, wasmDefaultTimeout)
	}
	if got := w.maxOutput(); got != wasmDefaultOutput {
		t.Errorf("zero-value maxOutput() = %d, want fallback %d", got, wasmDefaultOutput)
	}
	// An explicit config still wins over the fallback.
	w.MaxTimeout = 3 * time.Second
	if got := w.maxTimeout(); got != 3*time.Second {
		t.Errorf("configured maxTimeout() = %v, want 3s", got)
	}
}

func TestWasmMemoryPagesClamped(t *testing.T) {
	// An oversized resource envelope (8 GiB → 131072 pages) exceeds wazero's 4 GiB
	// ceiling; it must be pinned to the max, not panic the runtime on first run.
	w := DefaultWasm()
	Resources{MemoryMB: 8192}.applyWasm(w)
	if got := w.memoryLimitPages(); got != wasmMaxPages {
		t.Fatalf("pages = %d, want clamped to %d", got, wasmMaxPages)
	}
	if _, err := w.RunJavaScript(context.Background(), Request{Code: `console.log("ok")`}); err != nil {
		t.Fatalf("run with oversized memory envelope errored: %v", err)
	}
}

func TestWasmRejectsUnsupportedResourceDimensions(t *testing.T) {
	w := DefaultWasm()
	Resources{CPUs: 1}.applyWasm(w)
	if err := w.Preflight(context.Background()); err == nil {
		t.Fatal("WASM silently ignored a configured CPU cap")
	}
	if _, err := w.RunJavaScript(context.Background(), Request{Code: "1"}); err == nil {
		t.Fatal("direct WASM run silently ignored a configured CPU cap")
	}
}

// TestWasmMemoryLimitEnforced proves the HEADLINE claim of the wasm unification: the
// wazero WithMemoryLimitPages cap is a REAL per-run limit (unlike qjs's no-op
// MemoryLimit). The same allocation succeeds under the default cap and is stopped
// under a small one — so if WithMemoryLimitPages were dropped (regressing to
// wazero's ~4 GiB default), the small-cap run would succeed and this test fails. wasm
// runs IN-PROCESS, so an unenforced cap is a direct host-OOM vector.
func TestWasmMemoryLimitEnforced(t *testing.T) {
	// Allocate ~128 MiB of live Uint8Arrays: trivial under the 256 MiB default cap,
	// impossible under a 32 MiB one.
	const code = `
		var blocks = [];
		try {
			for (var i = 0; i < 128; i++) { blocks.push(new Uint8Array(1024 * 1024)); }
			console.log("ALLOCATED_128MB");
		} catch (e) {
			console.log("OOM");
		}`

	// Baseline: 128 MiB fits under the 256 MiB default, so the workload is a valid
	// discriminator and not failing for some unrelated reason.
	big := DefaultWasm()
	if res, err := big.RunJavaScript(context.Background(), Request{Code: code}); err != nil {
		t.Fatalf("baseline run errored: %v", err)
	} else if !strings.Contains(res.Stdout, "ALLOCATED_128MB") {
		t.Fatalf("128 MiB should fit under the 256 MiB default cap; stdout=%q stderr=%q", res.Stdout, res.Stderr)
	}

	// Under a 32 MiB cap the SAME allocation must be stopped (caught OOM or a guest
	// trap), never completed.
	small := DefaultWasm()
	small.MemoryPages = 512 // 32 MiB
	res, err := small.RunJavaScript(context.Background(), Request{Code: code})
	if err != nil {
		t.Fatalf("cap enforcement should surface as a Result, not an infra error: %v", err)
	}
	if strings.Contains(res.Stdout, "ALLOCATED_128MB") {
		t.Fatalf("guest allocated 128 MiB under a 32 MiB cap — memory limit NOT enforced (stdout=%q)", res.Stdout)
	}
}

// TestWasmTrapClassifierPinsWazeroPrefix pins the unversioned wazero trap-error
// prefix ("wasm error:") that the guest-vs-infra classifier keys off (wasm.go). A
// deep-recursion stack overflow traps as an out-of-bounds access (qjs#47); the
// classifier must recognize it as a GUEST fault (a Result, not a returned infra
// error). If wazero changes the prefix, the trap would instead be returned as an
// infra error and this test fails — exactly the regression to catch.
func TestWasmTrapClassifierPinsWazeroPrefix(t *testing.T) {
	w := DefaultWasm()
	res, err := w.RunJavaScript(context.Background(), Request{
		Code: `function f(n){return n<=0?0:1+f(n-1)} f(200000)`,
	})
	if err != nil {
		t.Fatalf("guest trap must be a Result, not a returned error (wazero prefix changed?): %v", err)
	}
	if res.ExitCode != 134 {
		t.Fatalf("exit = %d, want 134 (abnormal abort via the trap path); stderr=%q", res.ExitCode, res.Stderr)
	}
	if !strings.Contains(res.Stderr, "wasm error:") {
		t.Fatalf("stderr = %q, want it to carry the pinned wazero trap prefix %q", res.Stderr, "wasm error:")
	}
}

func TestWasmProjectUnsupported(t *testing.T) {
	w := DefaultWasm()
	// The wasm provider cannot run projects; it signals this with ErrUnsupported (a
	// returned error mapped to Unimplemented by the RPC layer), not a
	// success-with-Err-string, so every provider reports "unsupported" uniformly.
	_, err := w.RunProject(context.Background(), ProjectRequest{Steps: []string{"node main.js"}})
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
}

func TestWasmConsoleErrorDoesNotCrash(t *testing.T) {
	w := DefaultWasm()
	// qjs only defines console.log; the shim must make error/warn/info/debug
	// callable so this whole script runs instead of aborting on console.error.
	res, err := w.RunJavaScript(context.Background(), Request{
		Code: `console.error("E"); console.warn("W"); console.info("I"); console.debug("D"); console.log("OK")`,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit = %d, want 0 (console.* must not throw); stderr=%q", res.ExitCode, res.Stderr)
	}
	if !strings.Contains(res.Stdout, "OK") {
		t.Fatalf("stdout = %q, want it to contain OK (script must run to completion)", res.Stdout)
	}
}

func TestWasmNumberFormatting(t *testing.T) {
	w := DefaultWasm()
	// qjs lacks Intl and groups nothing; the polyfill must make currency/number
	// formatting produce Node-like output instead of the bare number.
	cases := []struct{ code, want string }{
		{`console.log((95000).toLocaleString())`, "95,000"},
		{`console.log((95000).toLocaleString("en-US",{style:"currency",currency:"USD"}))`, "$95,000.00"},
		{`console.log((-1234567.5).toLocaleString("en-US",{style:"currency",currency:"USD"}))`, "-$1,234,567.50"},
		{`console.log(new Intl.NumberFormat("en-US",{style:"currency",currency:"EUR"}).format(1000))`, "€1,000.00"},
	}
	for _, c := range cases {
		r, err := w.RunJavaScript(context.Background(), Request{Code: c.code})
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", c.code, err)
		}
		if !strings.Contains(r.Stdout, c.want) {
			t.Fatalf("%s\n got stdout=%q\nwant it to contain %q (stderr=%q)", c.code, r.Stdout, c.want, r.Stderr)
		}
	}
}

// TestEmbeddedQuickJSProvenance pins the embedded interpreter to the exact
// locally reproducible artifact wasm/README.md documents (quickjs-ng v0.15.1 plus
// plimsoll's minimal host-call shim). The wasm binary IS the process-tier TCB:
// a swapped or tampered artifact must fail the build's tests, not ship.
// When updating the asset, update the README table and this constant together.
func TestEmbeddedQuickJSProvenance(t *testing.T) {
	const pinned = "f9258d318b05404d49f635191d2056c30d24ad75f2cb7f1190fdb98a76cd679e" // quickjs-ng v0.15.1 + plimsoll host-call shim
	sum := sha256.Sum256(qjsWasm)
	if got := hex.EncodeToString(sum[:]); got != pinned {
		t.Fatalf("embedded qjs-wasi.wasm sha256 = %s, want the pinned quickjs-ng v0.15.1 + host-call artifact %s (update wasm/README.md provenance and this pin together)", got, pinned)
	}
}

// TestQuickJSLicenseNoticeProvenance pins the verbatim license notice shipped
// in the QuickJS-ng v0.15.1 source archive. This keeps attribution tied to the
// same upstream input as the embedded interpreter, even though the archive is
// only a regeneration input and is not part of the exported repository.
//
// Read the guarantee narrowly: the archive is not on disk here, so this proves the
// notice has not been altered since it was checked in, NOT that it matches upstream.
// The comparison against the archive's own LICENSE lives in wasm/build.sh, which
// runs at the one moment the upstream copy exists locally.
func TestQuickJSLicenseNoticeProvenance(t *testing.T) {
	const pinned = "bfa580b50618373ca3debde48ea146aa2733e0fe99fd4d05b00d12cb98f9f822"
	license, err := os.ReadFile("wasm/LICENSE.quickjs-ng")
	if err != nil {
		t.Fatalf("read QuickJS-ng license notice: %v", err)
	}
	sum := sha256.Sum256(license)
	if got := hex.EncodeToString(sum[:]); got != pinned {
		t.Fatalf("wasm/LICENSE.quickjs-ng sha256 = %s, want QuickJS-ng v0.15.1 license notice %s", got, pinned)
	}
}

func TestWasmStackOverflowIsResultNotError(t *testing.T) {
	w := DefaultWasm()
	// Deep JS recursion overflows the stack; in this wasm build that traps as an
	// out-of-bounds access (qjs#47). It must be reported as a failed run (non-zero
	// exit), not as an infrastructure error returned to the caller.
	res, err := w.RunJavaScript(context.Background(), Request{
		Code: `function f(n){return n<=0?0:1+f(n-1)} f(200000)`,
	})
	if err != nil {
		t.Fatalf("a guest stack overflow must be a Result, not a returned error: %v", err)
	}
	if res.ExitCode == 0 {
		t.Fatalf("expected non-zero exit for a guest fault, got 0 (stderr=%q)", res.Stderr)
	}
}
