// Command minimal runs one JavaScript snippet in a sandbox and prints what ran,
// where, and behind which isolation boundary.
//
// It needs no daemon, no docker, no credentials and no network. With
// SANDBOX_PROVIDER unset it selects the in-process WASM provider so the example
// works on a stock machine:
//
//	go run ./examples/minimal
//
// WASM is process tier. That is not an OS boundary, and it is not a production
// posture for hostile code: a runtime escape lands in this process. To run the
// same snippet behind a real kernel boundary, install gVisor and set the
// provider explicitly:
//
//	SANDBOX_PROVIDER=docker SANDBOX_DOCKER_RUNTIME=runsc go run ./examples/minimal
//
// The printed isolation line is the run's own evidence, not a claim from this
// file, so it changes when the boundary changes.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// snippet is stand-in agent-authored code: it aggregates rows it was handed and
// prints JSON. Nothing here reaches the network or the filesystem, because
// without a host-API grant the run has neither.
const snippet = `
const rows = [
  { dept: "Engineering", cents: 46600000 },
  { dept: "Sales",       cents: 20300000 },
  { dept: "Operations",  cents: 9800000  },
  { dept: "Engineering", cents: 12400000 },
];

const totals = {};
for (const row of rows) {
  totals[row.dept] = (totals[row.dept] ?? 0) + row.cents;
}
console.log(JSON.stringify(totals));
`

// exampleEnv opts this example into a provider.
//
// sandbox.Build runs nothing when SANDBOX_PROVIDER is unset: the default is the
// Disabled provider, so execution is always an explicit choice rather than
// something a caller switches on by accident. A real embedder makes that choice
// deliberately in its own configuration. This example makes it in one visible
// place instead of inheriting whatever the shell happens to hold.
func exampleEnv(key string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	if key == "SANDBOX_PROVIDER" {
		return "wasm"
	}
	return ""
}

func main() {
	if err := run(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "example failed:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	// Build is checked: it returns an error rather than guessing when the safety
	// configuration is malformed or the provider name is unrecognized.
	provider, err := sandbox.Build(exampleEnv)
	if err != nil {
		return fmt.Errorf("select provider: %w", err)
	}

	// EnsureReady bundles Preflight (configuration and dependency evidence) with
	// SmokeTest (behavioral proof through a throwaway sandbox). Call it before
	// running hostile code; plimsolld does the same thing at startup and refuses
	// to serve if it fails.
	if err := provider.EnsureReady(ctx); err != nil {
		return fmt.Errorf("provider not ready: %w", err)
	}

	result, err := provider.Sandbox.RunJavaScript(ctx, sandbox.Request{
		Code:    snippet,
		Timeout: 10 * time.Second,
	})
	if err != nil {
		// A returned error means the run never happened, or infrastructure broke.
		// Code that merely failed does not come back this way.
		return fmt.Errorf("dispatch: %w", err)
	}

	fmt.Printf("provider   %s\n", result.Sandbox)
	fmt.Printf("isolation  %s\n", result.Isolation)
	fmt.Printf("exit code  %d\n", result.ExitCode)
	fmt.Printf("timed out  %t\n", result.TimedOut)
	fmt.Printf("truncated  stdout=%t stderr=%t\n", result.StdoutTruncated, result.StderrTruncated)
	fmt.Printf("duration   %s\n", result.Duration.Round(time.Millisecond))
	fmt.Printf("stdout     %s", result.Stdout)
	if result.Stderr != "" {
		fmt.Printf("stderr     %s", result.Stderr)
	}

	// A non-zero exit code is a normal result: it means the submitted code failed,
	// which is a thing agent-authored code does routinely. It is deliberately not
	// a Go error, so callers do not have to tell "the sandbox broke" apart from
	// "the snippet threw" by inspecting error strings.
	if result.ExitCode != 0 {
		fmt.Println("\nthe snippet failed; that is a result, not an error")
	}
	return nil
}
