package sandbox

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/tetratelabs/wazero/sys"
)

// REFERENCE SANDBOX (2026-06-19): this package is the canonical sandbox, and
// embedders are expected to unify onto it rather than roll their own: wazero
// driven directly with WithMemoryLimitPages (a real per-run memory cap) plus the
// docker/e2b microVM providers, never the github.com/fastschema/qjs wrapper (its
// MemoryLimit is a no-op).

// qjsWasm is a WASI build of QuickJS-ng (MIT). See wasm/README.md.
//
//go:embed wasm/qjs-wasi.wasm
var qjsWasm []byte

// compilationCache lets every per-call runtime reuse the compiled QuickJS module,
// so compilation happens once per process instead of once per run.
var compilationCache = wazero.NewCompilationCache()

// WasmSandbox runs a JavaScript snippet inside QuickJS compiled to WASM, executed
// by wazero IN-PROCESS: no container, no network, no syscalls beyond what WASI
// exposes. It is low latency but only a process-tier boundary: a wazero/QuickJS
// escape lands in the host process. It is JS-only; granted snippets reach the
// provider-neutral broker through a quota-bounded wazero host function while the
// credential remains in Go.
type WasmSandbox struct {
	DefaultTimeout time.Duration
	MaxTimeout     time.Duration
	MaxOutputBytes int
	MemoryPages    uint32 // hard cap on guest linear memory (1 page = 64 KiB)
	configErr      error  // unsupported resource dimensions from Resources.applyWasm
}

// Fallbacks for a hand-built WasmSandbox that left these zero. wasm runs
// IN-PROCESS, so a run with no upper timeout would pin its full memory limit for
// however long the caller asked — a zero-value sandbox must not become an unbounded
// in-process slot. These mirror DefaultWasm so the zero value is still bounded.
const (
	wasmDefaultTimeout = 5 * time.Second
	wasmMaxTimeout     = 30 * time.Second
	wasmDefaultOutput  = 64 << 10
)

func DefaultWasm() *WasmSandbox {
	return &WasmSandbox{
		DefaultTimeout: wasmDefaultTimeout,
		MaxTimeout:     wasmMaxTimeout,
		MaxOutputBytes: wasmDefaultOutput,
		MemoryPages:    4096, // 256 MiB, matching the Docker provider's memory cap
	}
}

func (w *WasmSandbox) maxOutput() int {
	if w.MaxOutputBytes > 0 {
		return w.MaxOutputBytes
	}
	return wasmDefaultOutput
}

// defaultTimeout is used when the caller requests no timeout; it never returns 0,
// so a zero-value DefaultTimeout cannot produce an already-expired context.
func (w *WasmSandbox) defaultTimeout() time.Duration {
	if w.DefaultTimeout > 0 {
		return w.DefaultTimeout
	}
	return wasmDefaultTimeout
}

// maxTimeout is the hard wall-clock ceiling. Unlike the old `if MaxTimeout > 0`
// guard, a zero MaxTimeout no longer means "no cap" — it falls back to wasmMaxTimeout
// so an unconfigured sandbox still bounds hostile in-process runs.
func (w *WasmSandbox) maxTimeout() time.Duration {
	if w.MaxTimeout > 0 {
		return w.MaxTimeout
	}
	return wasmMaxTimeout
}

// wasmMaxPages is wazero's hard ceiling on the memory limit (the WASM max, 4 GiB at
// 64 KiB/page). WithMemoryLimitPages PANICS above it, so we pin rather than crash.
const wasmMaxPages = 65536

func (w *WasmSandbox) memoryLimitPages() uint32 {
	pages := w.MemoryPages
	if pages == 0 {
		pages = 4096
	}
	// An oversized configured value (e.g. SANDBOX_MEMORY_MB > 4096) would otherwise
	// panic wazero on the first run; pin it to the ceiling instead.
	if pages > wasmMaxPages {
		pages = wasmMaxPages
	}
	return pages
}

func (*WasmSandbox) Name() string { return "wasm" }

// SupportsProjects is false: there is no toolchain inside the QuickJS/WASI guest,
// so RunProject always returns ErrUnsupported.
func (*WasmSandbox) SupportsProjects() bool { return false }

func (*WasmSandbox) SupportsJavaScriptGrants() bool { return true }
func (*WasmSandbox) SupportsProjectGrants() bool    { return false }

// IsolationClass is Process: QuickJS runs in the host's own OS process via wazero.
// Memory is hard-capped and there is no network or syscall surface beyond WASI, but
// it is not a boundary that survives a hostile native escape — use docker (gVisor)
// or e2b for a real host/VM boundary.
func (*WasmSandbox) IsolationClass() IsolationClass { return IsolationProcess }

func (w *WasmSandbox) Preflight(context.Context) error { return w.configErr }

// wasmConsoleShim makes QuickJS's minimal console match Node's surface. qjs only
// defines console.log, so console.error/warn/info/debug/trace would throw
// "not a function" and abort the whole script (silently losing prior stdout). We
// alias the missing methods to log. There is no std module here (no stderr
// handle), so on this provider they route to stdout; use docker/e2b for real
// stderr separation. Kept to one line so it shifts user error line numbers by one.
const wasmConsoleShim = `(function(){var c=globalThis.console||(globalThis.console={});if(typeof c.log!=="function"){c.log=function(){}}["error","warn","info","debug","trace"].forEach(function(m){if(typeof c[m]!=="function"){c[m]=c.log}})})();`

// wasmNumberFormatShim polyfills Number.prototype.toLocaleString and
// Intl.NumberFormat for the common cases (en-US grouping + currency). qjs ships
// no Intl and a degenerate toLocaleString that returns the bare number, so
// payroll/HR code formatting money would silently emit "95000" instead of
// "$95,000.00". This covers grouping, currency symbols for common codes, and
// min/max fraction digits; it is NOT full ICU (en-US grouping only, JPY-style
// 0-fraction currencies still get 2). Guarded so it only activates when the
// engine lacks real Intl. One line, to keep the error-line shift at one.
const wasmNumberFormatShim = `(function(g){function f(v,o){o=o||{};var st=o.style||"decimal",cu=o.currency,ic=st==="currency",mx=o.maximumFractionDigits,mn=o.minimumFractionDigits;if(ic){if(mn==null)mn=2;if(mx==null)mx=mn>2?mn:2}if(mn==null)mn=0;if(mx==null)mx=3;var n=Number(v);if(!isFinite(n))return String(v);var ng=n<0;n=Math.abs(n);var s=n.toFixed(mx);if(mx>mn){s=s.replace(/0+$/,"");var d=s.indexOf(".");if(d<0){s+=".";d=s.length-1}var fl=s.length-d-1;while(fl<mn){s+="0";fl++}if(s.charAt(s.length-1)===".")s=s.slice(0,-1)}var p=s.split(".");p[0]=p[0].replace(/\B(?=(\d{3})+(?!\d))/g,",");var b=p.join("."),sy="";if(ic){var sm={USD:"$",CAD:"$",AUD:"$",EUR:"€",GBP:"£",JPY:"¥",CNY:"¥",INR:"₹"};sy=sm[cu]||(cu?cu+" ":"")}return(ng?"-":"")+sy+b}if(!g.Intl)g.Intl={};if(typeof g.Intl.NumberFormat!=="function"){g.Intl.NumberFormat=function(l,o){this.format=function(v){return f(v,o)};this.resolvedOptions=function(){return Object.assign({locale:"en-US"},o||{})}}}if((1234).toLocaleString()==="1234"){Number.prototype.toLocaleString=function(l,o){return f(this,o)}}})(globalThis);`

func (w *WasmSandbox) RunJavaScript(ctx context.Context, req Request) (Result, error) {
	if err := ValidateRequest(req); err != nil {
		return Result{Sandbox: w.Name(), Isolation: w.IsolationClass()}, err
	}
	if err := CheckMinimumIsolation(w.IsolationClass(), req.MinimumIsolation); err != nil {
		return Result{Sandbox: w.Name(), Isolation: w.IsolationClass()}, err
	}
	if w.configErr != nil {
		return Result{Sandbox: w.Name(), Isolation: w.IsolationClass()}, w.configErr
	}
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = w.defaultTimeout()
	}
	if m := w.maxTimeout(); timeout > m {
		timeout = m
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	broker, err := brokerSessionForGrant(runCtx, req.Grant, timeout)
	if err != nil {
		return Result{Sandbox: w.Name(), Isolation: w.IsolationClass()}, fmt.Errorf("start host api broker: %w", err)
	}
	defer broker.Close()

	code := withWasmHostSDK(req.Code, req.Grant)
	args := []string{"qjs"}
	// Alias the console methods qjs lacks (console.error/warn/info/...) so agent
	// code using them does not throw and abort. Prepended last so it runs first,
	// ahead of any control preamble.
	code = wasmConsoleShim + wasmNumberFormatShim + "\n" + code
	args = append(args, "-e", code)

	// A fresh runtime per call gives clean isolation between runs; the compilation
	// cache keeps it cheap. WithCloseOnContextDone honors the deadline;
	// WithMemoryLimitPages caps guest RAM (QuickJS declares no max, so without this
	// a hostile snippet could grow to the WASM max ~4 GiB and OOM the host process).
	rt := wazero.NewRuntimeWithConfig(runCtx, wazero.NewRuntimeConfig().
		WithCloseOnContextDone(true).
		WithMemoryLimitPages(w.memoryLimitPages()).
		WithCompilationCache(compilationCache))
	defer rt.Close(context.Background())
	// The module name "coderunner" is the project's former name and is deliberately
	// NOT renamed: it is one half of an ABI. The embedded qjs-wasi.wasm imports
	// "coderunner"/"host_call", matching import_module("coderunner") in
	// wasm/coderunner-hostcall.c. That .wasm is pinned by SHA-256 and guarded by
	// TestEmbeddedQuickJSProvenance, so renaming this string alone breaks
	// instantiation, and renaming both would require rebuilding and re-pinning the
	// artifact while invalidating the provenance record of the inputs that built it.
	if _, err := rt.NewHostModuleBuilder("coderunner").
		NewFunctionBuilder().WithFunc(func(ctx context.Context, mod api.Module, requestPtr, requestLen, responsePtr, responseCap uint32) uint64 {
		return wasmBrokerHostCall(ctx, mod, broker, requestPtr, requestLen, responsePtr, responseCap)
	}).Export("host_call").
		Instantiate(runCtx); err != nil {
		return Result{Sandbox: w.Name(), Isolation: w.IsolationClass()}, fmt.Errorf("instantiate host api bridge: %w", err)
	}
	if _, err := wasi_snapshot_preview1.Instantiate(runCtx, rt); err != nil {
		return Result{Sandbox: w.Name(), Isolation: w.IsolationClass()}, fmt.Errorf("instantiate WASI: %w", err)
	}

	var stdout, stderr cappedBuffer
	stdout.limit = w.maxOutput()
	stderr.limit = w.maxOutput()
	cfg := wazero.NewModuleConfig().
		WithStdout(&stdout).WithStderr(&stderr).
		WithArgs(args...)

	start := time.Now()
	_, err = rt.InstantiateWithConfig(runCtx, qjsWasm, cfg)
	res := Result{
		Stdout:          stdout.String(),
		Stderr:          stderr.String(),
		StdoutTruncated: stdout.Truncated(),
		StderrTruncated: stderr.Truncated(),
		Duration:        time.Since(start),
		Sandbox:         w.Name(),
		Isolation:       w.IsolationClass(),
		CallTrace:       broker.traceSnapshot(),
	}

	if runCtx.Err() == context.DeadlineExceeded {
		res.TimedOut = true
		res.ExitCode = 124
		return res, nil
	}
	if err != nil {
		var exitErr *sys.ExitError
		if errors.As(err, &exitErr) {
			res.ExitCode = int(exitErr.ExitCode())
			return res, nil
		}
		// A wasm trap (wazero prefixes these "wasm error: …") is the GUEST faulting,
		// not an infrastructure failure: e.g. a JS stack overflow surfaces as an
		// out-of-bounds access rather than a catchable RangeError (upstream qjs#47).
		// Per the Sandbox contract that is a failed run (non-zero exit + a message),
		// not a returned error, matching the docker/e2b providers. Keep res so any
		// partial stdout/stderr captured before the trap survives.
		if strings.Contains(err.Error(), "wasm error:") {
			res.ExitCode = 134 // abnormal abort
			if res.Stderr == "" {
				res.Stderr = "guest aborted: " + err.Error()
			}
			return res, nil
		}
		return Result{Sandbox: w.Name()}, err
	}
	return res, nil
}

// wasmBrokerEnvelope is the entire guest-controlled wire protocol. It contains
// no origin, headers, token, or quotas; those are exclusively brokerSession state.
// Body remains JSON bytes so the core forwards exactly the serialized value.
type wasmBrokerEnvelope struct {
	Method string          `json:"method"`
	Path   string          `json:"path"`
	Body   json.RawMessage `json:"body,omitempty"`
}

// The request envelope adds only trusted framing around the core's 1 MiB body
// limit. The response buffer in the QuickJS shim is exactly the core's 4 MiB
// response limit. Both live inside the run's already-capped WASM linear memory.
const maxWasmBrokerEnvelopeBytes = maxHostRequestBytes + 64<<10

func wasmBrokerHostCall(ctx context.Context, mod api.Module, broker *brokerSession, requestPtr, requestLen, responsePtr, responseCap uint32) uint64 {
	if requestLen == 0 || requestLen > maxWasmBrokerEnvelopeBytes {
		return writeWasmBrokerReply(mod, responsePtr, responseCap, brokerError(http.StatusRequestEntityTooLarge, "host api request envelope too large"))
	}
	requestBytes, ok := mod.Memory().Read(requestPtr, requestLen)
	if !ok {
		return writeWasmBrokerReply(mod, responsePtr, responseCap, brokerError(http.StatusBadRequest, "invalid host api request envelope"))
	}
	var envelope wasmBrokerEnvelope
	decoder := json.NewDecoder(bytes.NewReader(requestBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return writeWasmBrokerReply(mod, responsePtr, responseCap, brokerError(http.StatusBadRequest, "invalid host api request envelope"))
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return writeWasmBrokerReply(mod, responsePtr, responseCap, brokerError(http.StatusBadRequest, "invalid host api request envelope"))
	}
	var body io.Reader
	if envelope.Body != nil {
		body = bytes.NewReader(envelope.Body)
	}
	response := broker.Call(ctx, brokerCall{Method: envelope.Method, RawTarget: envelope.Path, Body: body})
	return writeWasmBrokerReply(mod, responsePtr, responseCap, response)
}

// The i64 result packs status in the high word and body length in the low word.
// The response bytes are written to guest-owned memory; the credential never is.
func writeWasmBrokerReply(mod api.Module, responsePtr, responseCap uint32, response brokerResponse) uint64 {
	status := response.Status
	if status < 100 || status > 599 {
		status = http.StatusInternalServerError
		response.Body = nil
	}
	if uint64(len(response.Body)) > uint64(responseCap) || !mod.Memory().Write(responsePtr, response.Body) {
		return uint64(http.StatusInternalServerError) << 32
	}
	return uint64(uint32(status))<<32 | uint64(uint32(len(response.Body)))
}

// RunProject is unsupported: the WASM runtime is a single JS engine with no
// toolchain. Use the docker or e2b provider for multi-file/TS project runs. It
// returns ErrUnsupported (a returned error, mapped to Unimplemented by the RPC
// layer) rather than a success-with-Err-string, so every provider signals an
// unsupported operation the same way.

func (w *WasmSandbox) RunProject(_ context.Context, req ProjectRequest) (ProjectResult, error) {
	if err := ValidateProjectRequest(req); err != nil {
		return ProjectResult{Sandbox: w.Name(), Isolation: w.IsolationClass()}, err
	}
	if err := CheckMinimumIsolation(w.IsolationClass(), req.MinimumIsolation); err != nil {
		return ProjectResult{Sandbox: w.Name(), Isolation: w.IsolationClass()}, err
	}
	return ProjectResult{Sandbox: w.Name(), Isolation: w.IsolationClass()}, ErrUnsupported
}
