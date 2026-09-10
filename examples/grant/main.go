// Command grant demonstrates the capability model: agent-authored code reaching a
// real HTTP API through an injected client, over a route allowlist the code cannot
// widen, with a credential it never sees.
//
// It needs no daemon, no docker and no credentials of its own. It starts a throwaway
// HTTP server on loopback to stand in for a customer's host API, then runs three
// snippets against it in the in-process WASM provider:
//
//	go run ./examples/grant
//
//	1. a permitted call, which succeeds and is recorded in the call trace;
//	2. a call to a route the grant does not list, refused before any request is sent;
//	3. the same permitted code with no grant at all, which reaches nothing.
//
// WASM is process tier, chosen here so the example runs anywhere. The capability
// model is provider-neutral: docker runs enforce the identical allowlist through a
// per-run Unix socket, with the same shared broker doing the deciding.
package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// theCredential stands in for a real bearer token. The whole point of the exercise
// below is that this string never enters the JavaScript runtime: it lives in Go, and
// the broker attaches it to the upstream request after the guest has been told yes.
const theCredential = "bearer-that-must-never-reach-the-guest"

// permitted calls a route the grant lists. host.get returns a promise resolving to
// the parsed JSON body.
const permitted = `
host.get("/v1/employees/e-1024/comp").then(
  function (v) { console.log("ok: " + v.dept + " " + v.cents); },
  function (e) { console.log("failed: " + e.message); }
);
`

// forbidden calls a route the grant does not list. Nothing about this snippet is
// unusual: it is the same client, the same syntax, a different path.
const forbidden = `
host.get("/v1/employees/e-1024/ssn").then(
  function (v) { console.log("ok: " + JSON.stringify(v)); },
  function (e) { console.log("refused: " + e.message); }
);
`

// bypass skips the injected client entirely and calls the raw host function it is
// built on. Hostile code would obviously do this: the client is JavaScript running
// inside the sandbox, so its allowlist check is the guest's own code and the guest
// can decline to run it. The check that matters is the one on the other side.
const bypass = `
var r = __coderunner_host_call(JSON.stringify({method: "GET", path: "/v1/employees/e-1024/ssn"}));
console.log("broker answered: " + r.status + " " + r.body);
`

// noGrantBypass calls the same raw host function in a run that carries no grant.
const noGrantBypass = `
var r = __coderunner_host_call(JSON.stringify({method: "GET", path: "/v1/departments"}));
console.log("broker answered: " + r.status + " " + r.body);
`

// exfiltrate goes looking for the credential. There is nothing to find: the injected
// client holds an allowlist, not a token.
//
// The needle is assembled at runtime rather than written as a literal, and that is
// not decoration. globalThis.execArgv in this runtime is ["qjs", "-e", <this very
// source>], so a scan for a literal string finds the scan's own source code and
// reports a leak that is not there. Written the naive way, this snippet accuses
// execArgv every time.
const exfiltrate = `
console.log("host keys: " + Object.keys(host).join(","));
var needle = ["bearer", "that", "must", "never", "reach", "the", "guest"].join("-");
var found = Object.getOwnPropertyNames(globalThis).filter(function (n) {
  try { return String(globalThis[n]).indexOf(needle) >= 0; } catch (e) { return false; }
});
console.log("globals holding the credential: " + (found.length ? found.join(",") : "none"));
console.log("what execArgv actually holds: " + execArgv.slice(0, 2).join(" ") + " <the snippet's own source>");
`

func main() {
	if err := run(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "example failed:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	upstream := httptest.NewServer(http.HandlerFunc(serveHostAPI))
	defer upstream.Close()

	// The grant is per run, not provider state: it rides on the Request, so authority
	// is chosen independently for every dispatch rather than configured once and
	// inherited. Two routes are listed. Everything else in the API, including routes
	// that exist and work when called with this same credential from outside, is
	// unreachable from inside the sandbox.
	grant := &sandbox.HostAPIGrant{
		BaseURL: upstream.URL, // loopback, so plain HTTP is allowed here; HTTPS is required off loopback
		Allow: []sandbox.HostRoute{
			{Method: "GET", Path: "/v1/employees/*/comp"},
			{Method: "GET", Path: "/v1/departments"},
		},
		// StaticToken is the degenerate minter, for host APIs with no real minting.
		// Prefer a TokenMinter issuing a short-lived, route-scoped token per run, so
		// an exfiltrated credential dies almost immediately.
		Minter: sandbox.StaticToken(theCredential),
		Scopes: []string{"comp:read"},
	}

	provider, err := sandbox.Build(wasmEnv)
	if err != nil {
		return fmt.Errorf("select provider: %w", err)
	}
	if err := provider.EnsureReady(ctx); err != nil {
		return fmt.Errorf("provider not ready: %w", err)
	}

	steps := []struct {
		title string
		code  string
		grant *sandbox.HostAPIGrant
	}{
		{"a route the grant lists", permitted, grant},
		{"a route it does not list, through the client", forbidden, grant},
		{"the same forbidden route, bypassing the client", bypass, grant},
		{"the granted client, in a run carrying no grant", permitted, nil},
		{"the raw host call, in a run carrying no grant", noGrantBypass, nil},
		{"the guest hunting for the credential", exfiltrate, grant},
	}
	for i, step := range steps {
		fmt.Printf("%d. %s\n", i+1, step.title)
		if err := show(ctx, provider, step.code, step.grant); err != nil {
			return err
		}
		fmt.Println()
	}
	return nil
}

// show runs one snippet and prints its output plus the metadata-only evidence the
// broker recorded for it.
func show(ctx context.Context, provider sandbox.Provider, code string, grant *sandbox.HostAPIGrant) error {
	result, err := provider.Sandbox.RunJavaScript(ctx, sandbox.Request{
		Code:    code,
		Grant:   grant,
		Timeout: 10 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("dispatch: %w", err)
	}

	if out := strings.TrimRight(result.Stdout, "\n"); out != "" {
		for _, line := range strings.Split(out, "\n") {
			fmt.Println("   guest |", line)
		}
	}
	if errOut := strings.TrimRight(result.Stderr, "\n"); errOut != "" {
		for _, line := range strings.Split(errOut, "\n") {
			fmt.Println("   guest ! |", line)
		}
	}

	// A run that leaks the credential into its own output would be the failure this
	// design exists to prevent, so the example checks rather than assuming.
	if strings.Contains(result.Stdout, theCredential) || strings.Contains(result.Stderr, theCredential) {
		return fmt.Errorf("the credential reached guest-visible output")
	}

	describeTrace(result.CallTrace)
	return nil
}

// describeTrace prints the run's CallTrace. Note what is in it and what cannot be:
// CallRow has fields for the matched route TEMPLATE, method, status, byte counts and
// latency, and has no field for a raw path, a query, a body or a credential. That is
// a property of the type, not a redaction step that could be forgotten.
func describeTrace(trace *sandbox.CallTrace) {
	if trace == nil {
		// Nil means the broker recorded nothing, which is not the same as "the call
		// was allowed" or even "a call was attempted". A run with no grant has no
		// broker at all; a run whose only call was refused by the injected client
		// never reached the broker either, so there is nothing for it to have seen.
		fmt.Println("   trace | nothing recorded: the broker was never reached")
		return
	}
	fmt.Printf("   trace | %d call(s), %d denied by policy, %d shed for backpressure, %d dropped\n",
		trace.Len(), trace.Denied, trace.Shed, trace.Dropped)
	for _, row := range trace.Calls {
		fmt.Printf("   trace | #%d %s %s -> %d, %dB in %dB out, %s\n",
			row.Seq, row.Method, row.Route, row.Status,
			row.ReqBytes, row.RespBytes, row.Latency.Round(time.Millisecond))
	}
}

// serveHostAPI stands in for a customer's HTTP API. It serves the granted route and
// also a route holding something the agent has no business reading, to make the
// point that the allowlist is what keeps the second one away rather than the API
// lacking it.
func serveHostAPI(w http.ResponseWriter, r *http.Request) {
	// A real host API authenticates. This one only demonstrates that the broker
	// presented the credential, which the guest never had access to.
	if r.Header.Get("Authorization") != "Bearer "+theCredential {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"missing credential"}`)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch {
	case strings.HasSuffix(r.URL.Path, "/comp"):
		_, _ = io.WriteString(w, `{"dept":"Engineering","cents":46600000}`)
	case strings.HasSuffix(r.URL.Path, "/ssn"):
		_, _ = io.WriteString(w, `{"ssn":"000-00-0000"}`)
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"error":"no such route"}`)
	}
}

// wasmEnv pins this example to the in-process provider so it runs with no setup.
// See examples/minimal for why the choice is explicit rather than inherited.
func wasmEnv(key string) string {
	if key == "SANDBOX_PROVIDER" {
		return "wasm"
	}
	return os.Getenv(key)
}
